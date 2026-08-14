"""Tests for hexact-cli.

**Hermetic by construction.** Every variable this package reads is scrubbed at
import, before any test runs. Without that, a developer who has exported
``HEXOWATCH_API_KEY`` would see the credential tests pass for the wrong
reason -- the resolver would find a real key and never exercise the branch
under test. Individual tests opt back in with ``mock.patch.dict``.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import http.client
import io
import json
import os
import re
import stat
import subprocess
import sys
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

_MANAGED_VARS = (
    "HEXOWATCH_API_KEY", "HEXOMATIC_API_KEY",
    "HEXOWATCH_OP_REF", "HEXOMATIC_OP_REF",
    "HEXOWATCH_REFRESH_TOKEN", "HEXOWATCH_REFRESH_OP_REF",
    "HEXOWATCH_ACCESS_TOKEN", "HEXOWATCH_ACCESS_OP_REF",
    "HEXOMETER_API_KEY", "HEXOMETER_OP_REF",
    "HEXACT_OP_CMD", "HEXACT_HOME",
)
for _name in _MANAGED_VARS:
    os.environ.pop(_name, None)

from hexact import (  # noqa: E402
    auth, cli, cli_auth, cli_hexomatic, cli_hexowatch, cli_watch_rest, config,
    graphql, hexomatic, hexometer, hexospark, hexowatch,
)
# Imported from the module that owns each one rather than through `cli`, which
# only re-exports them for the parser. A test that reaches an implementation
# through a re-export keeps passing after the implementation moves away from it.
from hexact.cli import main  # noqa: E402
from hexact.cli_common import (  # noqa: E402
    _is_paused, _parse_timestamp, _rows, _state_label, parse_since,
    reject_duration_for_a_date_flag,
)
from hexact.cli_watch_rest import _normalise_address, resolve_tool_from_payload  # noqa: E402
from hexact.http import HexactAPIError, redact, request  # noqa: E402


class TestRedaction(unittest.TestCase):
    """The key rides in the query string, so redaction is a security control."""

    def test_redacts_key_anywhere_in_url(self):
        for url in (
            "https://api.hexowatch.com/v1/x?key=SECRET123",
            "https://api.hexowatch.com/v1/x?limit=10&key=SECRET123",
            "https://api.hexowatch.com/v1/x?key=SECRET123&limit=10",
        ):
            with self.subTest(url=url):
                self.assertNotIn("SECRET123", redact(url))
                self.assertIn("***REDACTED***", redact(url))

    def test_leaves_other_content_intact(self):
        self.assertEqual(redact("no credential here"), "no credential here")

    def test_http_error_message_never_leaks_the_key(self):
        failure = urllib.error.HTTPError(
            url="https://api.hexowatch.com/v1/x?key=SECRET123",
            code=500, msg="Server Error", hdrs=None, fp=io.BytesIO(b"boom"),
        )
        with mock.patch("urllib.request.urlopen", side_effect=failure):
            with self.assertRaises(HexactAPIError) as caught:
                request("https://api.hexowatch.com", "v1/x", "SECRET123")
        self.assertNotIn("SECRET123", str(caught.exception))


class TestKeyLeakViaUnexpectedExceptionType(unittest.TestCase):
    """Regression: a control character in a path id leaked the live key.

    Found by security audit and reproduced end-to-end on 2026-08-13:
    ``hexact watch scan $'\\n' --tool keywordTool`` raised
    ``http.client.InvalidURL``, whose message embeds the whole URL including
    ``key=``. It inherits from ``HTTPException`` -- not ``URLError``, not
    ``OSError``, not ``ValueError`` -- so every handler missed it and the raw
    key was printed to stderr by the default traceback hook.

    These tests deliberately do NOT mock ``urlopen``. The pre-existing
    redaction test did mock it, which is precisely why it never caught this:
    the failure originates below urllib, inside ``http.client``.
    """

    CANARY = "CANARY_KEY_DO_NOT_LEAK_12345"

    def test_invalid_url_is_not_a_urlerror(self):
        # The premise of the bug. If this ever changes, the handler design
        # above can be simplified -- but until then, it justifies the catch-all.
        self.assertFalse(issubclass(http.client.InvalidURL, urllib.error.URLError))
        self.assertFalse(issubclass(http.client.InvalidURL, OSError))

    def test_control_character_in_path_never_reaches_the_wire_unescaped(self):
        from hexact.http import path_segment
        self.assertEqual(path_segment("\n"), "%0A")
        self.assertEqual(path_segment("a/b"), "a%2Fb")
        self.assertEqual(path_segment("../../etc/passwd"), "..%2F..%2Fetc%2Fpasswd")

    def test_scan_result_with_control_character_does_not_leak_the_key(self):
        with mock.patch.dict(os.environ, {"HEXOWATCH_API_KEY": self.CANARY}, clear=False):
            buffer = io.StringIO()
            with contextlib.redirect_stderr(buffer):
                # Must not raise: main() returns an exit code instead.
                code = main(["watch", "scan", "\n", "--tool", "keywordTool"])
        self.assertNotEqual(code, 0)
        self.assertNotIn(self.CANARY, buffer.getvalue())

    def test_unexpected_exception_type_is_redacted_not_propagated(self):
        leaky = http.client.InvalidURL(
            f"URL can't contain control characters. "
            f"'/v1/x?key={self.CANARY}&tool=keywordTool'"
        )
        with mock.patch("urllib.request.urlopen", side_effect=leaky):
            with self.assertRaises(HexactAPIError) as caught:
                request("https://api.hexowatch.com", "v1/x", self.CANARY)
        self.assertNotIn(self.CANARY, str(caught.exception))
        self.assertIn("***REDACTED***", str(caught.exception))


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False


def _respond_with(payload) -> mock._patch:
    body = json.dumps(payload).encode("utf-8")
    return mock.patch("urllib.request.urlopen", return_value=_FakeResponse(body))


class TestErrorEnvelope(unittest.TestCase):
    """HTTP 200 with ``error: true`` is a failure and must not reach the caller."""

    def test_error_envelope_raises_despite_http_200(self):
        with _respond_with({"error": True, "message": "Invalid API key"}):
            with self.assertRaises(HexactAPIError) as caught:
                request("https://api.hexowatch.com", "v1/x", "k")
        self.assertIn("Invalid API key", str(caught.exception))

    def test_success_envelope_returns_payload(self):
        with _respond_with({"error": False, "monitored_urls": [{"id": 1}]}):
            result = request("https://api.hexowatch.com", "v1/x", "k")
        self.assertEqual(result["monitored_urls"], [{"id": 1}])

    def test_non_json_body_raises_rather_than_returning_none(self):
        with mock.patch("urllib.request.urlopen", return_value=_FakeResponse(b"<html>")):
            with self.assertRaises(HexactAPIError):
                request("https://api.hexowatch.com", "v1/x", "k")


class TestCredentialResolution(unittest.TestCase):
    """Assert both directions: absent is refused, present is honoured."""

    def test_absent_everywhere_is_refused(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"HEXACT_HOME": tmp}, clear=False):
                with self.assertRaises(config.CredentialError):
                    config.resolve_key(config.HEXOWATCH)

    def test_environment_variable_is_honoured(self):
        with mock.patch.dict(os.environ, {"HEXOWATCH_API_KEY": "from-env"}, clear=False):
            self.assertEqual(config.resolve_key(config.HEXOWATCH), "from-env")

    def test_environment_wins_over_file(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.env"
            path.write_text("HEXOWATCH_API_KEY=from-file\n", encoding="utf-8")
            path.chmod(0o600)
            env = {"HEXACT_HOME": tmp, "HEXOWATCH_API_KEY": "from-env"}
            with mock.patch.dict(os.environ, env, clear=False):
                self.assertEqual(config.resolve_key(config.HEXOWATCH), "from-env")

    def test_file_is_used_when_environment_is_empty(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.env"
            path.write_text("# comment\nHEXOWATCH_API_KEY='from-file'\n", encoding="utf-8")
            path.chmod(0o600)
            with mock.patch.dict(os.environ, {"HEXACT_HOME": tmp}, clear=False):
                self.assertEqual(config.resolve_key(config.HEXOWATCH), "from-file")

    def test_world_readable_file_is_refused_not_loaded(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.env"
            path.write_text("HEXOWATCH_API_KEY=leaked\n", encoding="utf-8")
            path.chmod(0o644)
            with mock.patch.dict(os.environ, {"HEXACT_HOME": tmp}, clear=False):
                with self.assertRaises(config.CredentialError) as caught:
                    config.resolve_key(config.HEXOWATCH)
        self.assertIn("chmod 600", str(caught.exception))

    def test_malformed_op_reference_is_rejected(self):
        env = {"HEXOWATCH_OP_REF": "Agent Automation/Hexact/key"}  # missing op://
        with mock.patch.dict(os.environ, env, clear=False):
            with self.assertRaises(config.CredentialError) as caught:
                config.resolve_key(config.HEXOWATCH)
        self.assertIn("op://", str(caught.exception))

    def test_op_reference_reads_through_the_cli(self):
        env = {"HEXOWATCH_OP_REF": "op://Agent Automation/Hexact API/hexowatch_key"}
        completed = mock.Mock(returncode=0, stdout="from-1password\n", stderr="")
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("subprocess.run", return_value=completed) as run:
                self.assertEqual(config.resolve_key(config.HEXOWATCH), "from-1password")
        self.assertEqual(run.call_args.args[0][:2], ["op", "read"])

    def test_op_cmd_override_routes_through_a_wrapper(self):
        env = {
            "HEXOWATCH_OP_REF": "op://Agent Automation/Hexact API/hexowatch_key",
            "HEXACT_OP_CMD": "python3 /path/to/op_unattended.py --",
        }
        completed = mock.Mock(returncode=0, stdout="via-wrapper\n", stderr="")
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("subprocess.run", return_value=completed) as run:
                self.assertEqual(config.resolve_key(config.HEXOWATCH), "via-wrapper")
        self.assertEqual(run.call_args.args[0][0], "python3")


class TestArgumentValidation(unittest.TestCase):
    def test_unknown_tool_is_rejected_before_any_request(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            with self.assertRaises(ValueError):
                hexowatch.create_monitor("k", tool="notATool", addresses=["https://x.com"])
        urlopen.assert_not_called()

    def test_empty_address_list_is_rejected(self):
        with self.assertRaises(ValueError):
            hexowatch.create_monitor("k", tool="visualMonitoringTool", addresses=[])

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(ValueError):
            hexowatch.act("k", "destroy", [1])

    def test_unknown_interval_is_rejected(self):
        with self.assertRaises(ValueError):
            hexowatch.create_monitor(
                "k", tool="keywordTool", addresses=["https://x.com"],
                monitoring_interval="1_FORTNIGHT",
            )

    def test_empty_workflow_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            hexomatic.set_active("k", [], True)
        with self.assertRaises(ValueError):
            hexomatic.delete_workflows("k", [])


class TestObservedFieldNames(unittest.TestCase):
    """Regression tests for two field names that were guessed wrong.

    Both produced confident, non-erroring, WRONG output against the live API on
    2026-08-13, which is why they are locked here rather than left to review:
    every monitor rendered as "paused" when all 48 were running, and a populated
    change history rendered as "no changes detected". The payloads below are
    verbatim shapes from that run.
    """

    def test_monitor_state_reads_paused_not_active(self):
        running = {"id": 1, "address": "https://x.com", "name": "x", "paused": False}
        stopped = {"id": 2, "address": "https://y.com", "name": "y", "paused": True}
        self.assertFalse(_is_paused(running))
        self.assertTrue(_is_paused(stopped))
        self.assertEqual(_state_label(running), "active")
        self.assertEqual(_state_label(stopped), "paused")

    def test_absent_paused_key_is_unknown_not_active(self):
        # A shape change must not silently report every monitor as running.
        self.assertEqual(_state_label({"id": 3}), "unknown")

    def test_scan_history_lives_under_monitoring_results(self):
        payload = {
            "error": False,
            "monitoring_id": "337094",
            "tool": "visualMonitoringTool",
            "monitoring_results": [
                {"scan_result_id": "6a7cc8ff", "date": "2026-08-12T19:26:55.309Z",
                 "event_detected": True, "percentage": 0.06162175464501046},
            ],
        }
        rows = _rows(payload, "monitoring_results", "monitoring_logs", "logs", "data")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["event_detected"])
        # The older guessed names must not resolve against this payload.
        self.assertEqual(_rows(payload, "monitoring_logs", "logs", "data"), [])

    def test_iso_z_timestamp_parses_as_utc(self):
        stamp = _parse_timestamp("2026-08-12T19:26:55.309Z")
        self.assertIsNotNone(stamp)
        self.assertEqual(stamp.tzinfo, timezone.utc)
        self.assertEqual(stamp.year, 2026)


class TestDocumentedSchema(unittest.TestCase):
    """Locks facts taken from the published API docs, each of which was
    initially assumed wrong."""

    def test_only_eight_tools_are_creatable(self):
        self.assertEqual(len(hexowatch.TOOLS), 8)
        for tool in ("sitemapTool", "apiMonitoringTool", "htmlElementMonitoringTool",
                     "automaticAITool", "rssTool"):
            self.assertNotIn(tool, hexowatch.TOOLS)
            self.assertIn(tool, hexowatch.SCAN_RESULT_TOOLS)
        self.assertEqual(len(hexowatch.SCAN_RESULT_TOOLS), 13)

    def test_read_only_tool_rejection_explains_why(self):
        with self.assertRaises(ValueError) as caught:
            hexowatch.create_monitor("k", tool="sitemapTool", addresses=["https://x.com"])
        self.assertIn("no documented creation schema", str(caught.exception))

    def test_nineteen_intervals(self):
        self.assertEqual(len(hexowatch.INTERVALS), 19)
        for missed in ("4_HOUR", "5_HOUR", "3_DAY", "2_MONTH"):
            self.assertIn(missed, hexowatch.INTERVALS)

    def test_notification_level_is_validated_per_tool(self):
        # GE_5 is valid for visual, and invalid for keyword.
        self.assertIn("GE_5", hexowatch.NOTIFICATION_LEVELS["visualMonitoringTool"])
        self.assertNotIn("GE_5", hexowatch.NOTIFICATION_LEVELS["keywordTool"])
        with self.assertRaises(ValueError) as caught:
            hexowatch.create_monitor("k", tool="keywordTool", addresses=["https://x.com"],
                                     change_notification_level="GE_5")
        message = str(caught.exception)
        self.assertIn("keywordTool", message)
        # The error must point at the real mute mechanism, not just refuse.
        self.assertIn("notification_integrations=[]", message)

    def test_no_notification_level_can_mute(self):
        # The mute path must be notification_integrations, not a level value.
        for values in hexowatch.NOTIFICATION_LEVELS.values():
            for forbidden in ("OFF", "NONE", "SILENT", "MUTE", "NEVER"):
                self.assertNotIn(forbidden, values)

    def test_silent_kwargs_send_empty_list_rather_than_dropping_it(self):
        captured: dict[str, Any] = {}

        def fake_request(base, path, key, **kwargs):
            captured.update(kwargs.get("body") or {})
            return {"error": False, "monitoring_ids": [1]}

        with mock.patch("hexact.hexowatch.request", side_effect=fake_request):
            hexowatch.create_monitor(
                "k", tool="visualMonitoringTool", addresses=["https://x.com"],
                **hexowatch.silent_monitor_kwargs(),
            )
        # The empty list is the whole point; a falsiness check would drop it.
        self.assertIn("notification_integrations", captured)
        self.assertEqual(captured["notification_integrations"], [])
        self.assertIs(captured["pause_after_first_change_event"], False)
        self.assertNotIn("webhook", captured)  # None is omitted, not sent


class TestStateKeyInconsistency(unittest.TestCase):
    """The docs say `active`; the live API sent `paused`. Both must work."""

    def test_documented_active_key(self):
        self.assertFalse(_is_paused({"id": 1, "active": True}))
        self.assertTrue(_is_paused({"id": 2, "active": False}))
        self.assertEqual(_state_label({"id": 1, "active": True}), "active")

    def test_observed_paused_key_wins_when_both_present(self):
        self.assertTrue(_is_paused({"id": 1, "paused": True, "active": True}))

    def test_neither_key_is_unknown_not_running(self):
        self.assertIsNone(_is_paused({"id": 1}))
        self.assertEqual(_state_label({"id": 1}), "unknown")


class TestDuplicateDetection(unittest.TestCase):
    def test_cosmetic_differences_collapse(self):
        variants = [
            "https://rotorbike.com/", "http://rotorbike.com",
            "https://www.rotorbike.com/", "ROTORBIKE.com/",
        ]
        self.assertEqual(len({_normalise_address(v) for v in variants}), 1)

    def test_different_paths_stay_distinct(self):
        self.assertNotEqual(
            _normalise_address("https://loopearplugs.jp/"),
            _normalise_address("https://loopearplugs.jp/products/quiet"),
        )

    def test_query_strings_are_significant(self):
        self.assertNotEqual(
            _normalise_address("https://meetup.com/g/?eventOrigin=event_home_page"),
            _normalise_address("https://meetup.com/g/"),
        )


class TestSameAddressDifferentToolIsNotADuplicate(unittest.TestCase):
    """The address is not the identity of a monitor; (address, tool) is.

    These four records are verbatim from the live account on 2026-08-13.
    Grouping them by address alone reported 18 redundant monitors out of 48
    when only 1 was real -- a 94% false-positive rate on a command whose output
    is a list of monitors to switch off. Acting on it would have paused real
    coverage, and nothing would have errored.
    """

    LIVE = [
        {"id": 285431, "address": "https://info.littleboattan.com/", "tool": "sitemapTool"},
        {"id": 285438, "address": "https://info.littleboattan.com/", "tool": "visualMonitoringTool"},
        {"id": 302407, "address": "https://info.littleboattan.com/", "tool": "techStackTool"},
        # The one true duplicate on the account: same page, same tool, twice.
        {"id": 337079, "address": "https://www.meetup.com/g/?eventOrigin=event_home_page",
         "tool": "visualMonitoringTool"},
        {"id": 337094, "address": "https://www.meetup.com/g/?eventOrigin=event_home_page",
         "tool": "visualMonitoringTool"},
    ]

    def _run_duplicates(self):
        """Drive the real ``cmd_duplicates`` over the live payloads.

        Deliberately not a re-implementation of the grouping: an earlier version
        of this test computed the answer itself and passed even when the
        production key was mutated back to address-only, which is the exact
        defect it claims to guard.
        """
        tools = {row["id"]: row["tool"] for row in self.LIVE}
        monitors = {"error": False, "monitored_urls": [
            {"id": r["id"], "address": r["address"], "name": r["address"], "paused": False}
            for r in self.LIVE
        ]}
        with mock.patch.object(hexowatch, "list_monitored_urls", return_value=monitors), \
             mock.patch.object(hexowatch, "monitoring_logs",
                               side_effect=lambda key, mid, **kw: {
                                   "error": False, "tool": tools[int(mid)],
                                   "monitoring_results": []}), \
             mock.patch.object(cli_watch_rest, "resolve_key", return_value="k"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli_watch_rest.cmd_duplicates(argparse.Namespace(json=True))
        return json.loads(buf.getvalue())

    def test_only_the_real_duplicate_is_reported(self):
        data = self._run_duplicates()
        self.assertEqual(data["redundant_monitors"], 1)
        # The lower id is kept: it is the older monitor and holds the longer
        # change history, so the newer twin is the one to switch off.
        self.assertEqual(data["redundant_ids"], [337094])
        self.assertEqual(data["compared"], 5)

    def test_same_page_under_different_tools_is_not_redundant(self):
        data = self._run_duplicates()
        flagged = set(data["redundant_ids"])
        for monitor_id in (285431, 285438, 302407):
            self.assertNotIn(monitor_id, flagged)

    def test_a_monitor_whose_tool_is_unknown_is_excluded_not_grouped(self):
        monitors = {"error": False, "monitored_urls": [
            {"id": 1, "address": "https://a.com", "name": "a", "paused": False},
            {"id": 2, "address": "https://a.com", "name": "a", "paused": False},
        ]}
        with mock.patch.object(hexowatch, "list_monitored_urls", return_value=monitors), \
             mock.patch.object(hexowatch, "monitoring_logs",
                               return_value={"error": False, "monitoring_results": []}), \
             mock.patch.object(cli_watch_rest, "resolve_key", return_value="k"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli_watch_rest.cmd_duplicates(argparse.Namespace(json=True))
        data = json.loads(buf.getvalue())
        self.assertEqual(data["redundant_monitors"], 0)
        self.assertEqual(data["compared"], 0)
        self.assertEqual(len(data["unresolved"]), 2)

    def test_unknown_tool_never_groups(self):
        """A monitor with no scan history has no tool, and must not be paired.

        Returning a placeholder here would make every unscanned monitor a
        duplicate of every other unscanned monitor.
        """
        self.assertIsNone(
            resolve_tool_from_payload({"error": False, "monitoring_results": []})
        )
        self.assertEqual(
            resolve_tool_from_payload({"error": False, "tool": "sitemapTool"}),
            "sitemapTool",
        )


class TestParseSince(unittest.TestCase):
    def test_supported_units(self):
        now = datetime.now(timezone.utc)
        for value, expected in (("24h", timedelta(hours=24)),
                                ("7d", timedelta(days=7)),
                                ("2w", timedelta(weeks=2))):
            with self.subTest(value=value):
                self.assertAlmostEqual(
                    (now - parse_since(value)).total_seconds(),
                    expected.total_seconds(), delta=5,
                )

    def test_invalid_duration_is_rejected(self):
        for value in ("yesterday", "24", "h24", "-1d", ""):
            with self.subTest(value=value):
                with self.assertRaises(Exception):
                    parse_since(value)


if __name__ == "__main__":
    unittest.main()


class TestGraphQLNullIsAuthFailureNotEmptyData(unittest.TestCase):
    """The most dangerous response this API can send is a successful-looking null.

    Verified against the live gateway on 2026-08-13: no token, a deliberately
    bogus token, and a valid REST API key all produce
    ``{"data":{"Watch":{"getUserWatchPropertiesStatistics":null}}}`` with HTTP
    200. Nothing in the response distinguishes those from an account that
    genuinely has no monitors. Reading null as "empty" would report a healthy,
    empty account to someone whose token had merely expired.
    """

    def test_null_namespace_raises_auth_error(self):
        with self.assertRaises(graphql.AuthError):
            graphql.unwrap({"Watch": None}, "Watch", "getWatchProperty")

    def test_null_field_raises_auth_error(self):
        with self.assertRaises(graphql.AuthError):
            graphql.unwrap({"Watch": {"getWatchProperty": None}},
                           "Watch", "getWatchProperty")

    def test_empty_list_is_data_not_an_auth_failure(self):
        # The gateway returns [] for a genuinely empty collection, so failing
        # closed on null costs nothing legitimate.
        self.assertEqual(
            graphql.unwrap({"Watch": {"getWatchProperties": []}},
                           "Watch", "getWatchProperties"),
            [],
        )

    def test_auth_error_is_catchable_as_an_api_error(self):
        self.assertTrue(issubclass(graphql.AuthError, HexactAPIError))


class TestMutationAllowlistIsEnforcedBeforeTheNetwork(unittest.TestCase):
    """The containment boundary for a credential far broader than the API key.

    A refresh token reaches the whole account, including billing. The allowlist
    is only worth anything if it is checked before a request is built, so these
    assert that no transport is reached at all.
    """

    def _no_network(self):
        return mock.patch.object(
            graphql, "execute",
            side_effect=AssertionError("a forbidden mutation reached the transport"))

    def test_billing_namespace_is_refused(self):
        with self._no_network():
            with self.assertRaises(HexactAPIError) as caught:
                graphql.mutate("HexometerUserSettingsOpts.updateHexometerPackage",
                               {}, token="t")
        self.assertIn("forbidden namespace", str(caught.exception))

    def test_unlisted_watch_mutation_is_refused(self):
        # Real, and destructive in a different way: it would create monitors.
        with self._no_network():
            with self.assertRaises(HexactAPIError):
                graphql.mutate("WatchOps.createWatchPropertyBulk", {}, token="t")

    def test_the_operations_we_rely_on_are_listed(self):
        # Pins the vendor's undocumented, unversioned names. A silent rename
        # should fail here rather than quietly return nothing at runtime.
        #
        # Deliberately an EXACT set, not a subset check: the allowlist is a
        # containment boundary around a session token that reaches the whole
        # account, so widening it must be a decision someone made on purpose
        # and not a line that arrived with a feature.
        self.assertEqual(graphql.MUTATION_ALLOWLIST, frozenset({
            "WatchOps.deleteWatchProperty",
            "WatchOps.deleteWatchProperties",
            "WatchOps.updateWatchProperty",
            "WatchOps.updateWatchProperties",
            "WatchIntegrationOps.updateWatchPropertyIntegrations",
            "WatchIntegrationOps.deleteWatchPropertyIntegration",
            "WatchIntegrationOps.deleteWatchIntegration",
            "UserWatchSettingsOps.update",
            "UserWatchSettingsOps.subscribeWebhook",
            "UserWatchSettingsOps.unsubscribeWebhook",
            # Widened deliberately for tags and the alert inbox. Both stay
            # inside Hexowatch: tags label monitors, alert operations touch the
            # notification inbox. Neither can reach a monitor's data, an
            # account setting, or a billing surface.
            "WatchTagOps.createUserWatchTag",
            "WatchTagOps.updateUserWatchTag",
            "WatchTagOps.deleteUserWatchTag",
            "WatchTagOps.updateWatchPropertyTags",
            "WatchTagOps.addWatchPropertyTag",
            "WatchTagOps.deleteWatchPropertyTag",
            "WatchAlertOps.setAllWatchAlertsReadState",
            "WatchAlertOps.setWatchAlertReadState",
            "WatchAlertOps.deleteWatchAlerts",
        }))

    def test_every_allowlisted_operation_stays_inside_hexowatch(self):
        """A second, independent statement of the boundary.

        The exact-set test above pins *which* operations are allowed; this pins
        *what kind*. Regenerating the set from the code would satisfy the first
        and still fail this one if a Hexomatic, Hexospark or Hexometer mutation
        were added -- those products' writes have not been reviewed and the same
        session token reaches all of them.
        """
        allowed_namespaces = {"WatchOps", "WatchIntegrationOps", "WatchTagOps",
                              "WatchAlertOps", "UserWatchSettingsOps"}
        for operation in graphql.MUTATION_ALLOWLIST:
            self.assertIn(operation.split(".", 1)[0], allowed_namespaces,
                          f"{operation} is outside the reviewed Hexowatch surface")

    def test_no_billing_admin_or_user_mutation_ever_enters_the_allowlist(self):
        """The rule the exact-set test above protects, stated independently.

        If someone regenerates that set from whatever the code currently does,
        this still fails. Billing and account mutations live on the same
        gateway and the same token reaches them.
        """
        for operation in graphql.MUTATION_ALLOWLIST:
            namespace = operation.split(".", 1)[0]
            self.assertNotIn(namespace, graphql.FORBIDDEN_NAMESPACES)
            for banned in ("Billing", "Admin", "Package", "Payment", "Subscription"):
                self.assertNotIn(banned, operation, f"{operation} looks account-level")

    def test_allowlisted_mutation_sends_values_as_variables(self):
        """Arguments must not be interpolated into the query document."""
        seen = {}

        def capture(query, variables=None, **kwargs):
            seen["query"], seen["variables"] = query, variables
            return {"WatchOps": {"deleteWatchProperties": {"error": False}}}

        with mock.patch.object(graphql, "execute", side_effect=capture):
            graphql.delete_monitors("tok", [337094])
        self.assertEqual(seen["variables"], {"watch_properties_ids": [337094]})
        self.assertNotIn("337094", seen["query"])


class TestDeleteRefusesWithoutConfirmation(unittest.TestCase):
    def test_no_yes_means_no_request_and_no_token_lookup(self):
        """Refusal must precede the network, not follow a wasted round trip.

        An earlier version minted an access token first, so `delete` without
        --yes failed with a credential error instead of the guard message --
        the guard was real but unreachable without a working login.
        """
        with mock.patch.object(cli.auth, "access_token",
                               side_effect=AssertionError("token was resolved")), \
             mock.patch.object(cli.graphql, "execute",
                               side_effect=AssertionError("network was touched")):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                code = main(["watch", "delete", "337094"])
        self.assertEqual(code, 2)
        self.assertIn("--yes", buf.getvalue())


class TestAuthStatusDistinguishesFailureModes(unittest.TestCase):
    """`unknown` is a real verdict and must not collapse into `rejected`.

    A network failure is not evidence about a credential. Reporting it as one
    is how a perfectly good token gets rotated -- the shape already recorded in
    memory as "auth failure is not a licence verdict".
    """

    def test_unreachable_gateway_is_unknown_not_rejected(self):
        with mock.patch.object(auth, "resolve_key", return_value="refresh"), \
             mock.patch.object(auth, "access_token",
                               side_effect=HexactAPIError("Could not reach the gateway")):
            verdict, _ = auth.status()
        self.assertEqual(verdict, "unknown")

    def test_refused_token_is_rejected(self):
        with mock.patch.object(auth, "resolve_key", return_value="refresh"), \
             mock.patch.object(auth, "access_token",
                               side_effect=graphql.AuthError("bad token")):
            verdict, _ = auth.status()
        self.assertEqual(verdict, "rejected")

    def test_missing_credential_is_missing_not_rejected(self):
        with mock.patch.object(auth, "resolve_key",
                               side_effect=config.CredentialError("none stored")):
            verdict, _ = auth.status()
        self.assertEqual(verdict, "missing")

    def test_probe_answering_unauthenticated_is_rejected(self):
        # The live shape: HTTP 200, no GraphQL error, refusal inside the envelope.
        payload = {"WatchOps": {"updateWatchProperty": {
            "error": True, "message": "You should be authenticated to perform this action!"}}}
        with mock.patch.object(auth, "resolve_key", return_value="refresh"), \
             mock.patch.object(auth, "access_token", return_value="access"), \
             mock.patch.object(auth.graphql, "execute", return_value=payload):
            verdict, _ = auth.status()
        self.assertEqual(verdict, "rejected")


class TestLoginNeverContinuesOnAnEmptyToken(unittest.TestCase):
    def test_success_envelope_without_a_token_is_a_failure(self):
        payload = {"UserOps": {"authRefreshToken": {"error": False, "token": None}}}
        with mock.patch.object(graphql, "execute", return_value=payload):
            with self.assertRaises(auth.LoginError):
                auth.login("a@b.com", "pw")

    def test_stored_token_file_is_owner_only(self):
        with TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"HEXACT_HOME": tmp}):
                path = auth.store_refresh_token("s3cret-refresh-token")
            mode = path.stat().st_mode
            self.assertFalse(mode & (stat.S_IRWXG | stat.S_IRWXO),
                             "credentials file must not be group- or world-readable")
            self.assertIn("HEXOWATCH_REFRESH_TOKEN=s3cret-refresh-token",
                          path.read_text(encoding="utf-8"))


class TestOnePasswordWriteNeverExposesTheToken(unittest.TestCase):
    """A secret in argv is readable by every process on the machine.

    1Password's own CLI documents that sensitive values belong in a JSON
    template rather than an assignment statement, so these assert the token
    never becomes a command-line argument and never survives on disk.
    """

    TOKEN = "refresh-token-SHOULD-NOT-APPEAR-IN-ARGV"

    def _capture(self):
        seen = {}

        def fake_run(command, **kwargs):
            seen["command"] = command
            template = [a for a in command if a.endswith(".json")]
            seen["template_path"] = template[0] if template else None
            if seen["template_path"]:
                path = Path(seen["template_path"])
                seen["template_mode"] = path.stat().st_mode
                seen["template_body"] = path.read_text(encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

        return seen, fake_run

    def test_token_is_not_passed_as_an_argument(self):
        seen, fake_run = self._capture()
        with mock.patch.object(auth.subprocess, "run", side_effect=fake_run):
            auth.store_refresh_token_1password(
                self.TOKEN, item_title="T", vault="V", op_cmd=["op"])
        self.assertNotIn(self.TOKEN, " ".join(seen["command"]))
        self.assertIn(self.TOKEN, seen["template_body"])

    def test_template_file_is_owner_only_while_it_exists(self):
        seen, fake_run = self._capture()
        with mock.patch.object(auth.subprocess, "run", side_effect=fake_run):
            auth.store_refresh_token_1password(
                self.TOKEN, item_title="T", vault="V", op_cmd=["op"])
        self.assertFalse(seen["template_mode"] & (stat.S_IRWXG | stat.S_IRWXO))

    def test_template_file_is_removed_afterwards(self):
        seen, fake_run = self._capture()
        with mock.patch.object(auth.subprocess, "run", side_effect=fake_run):
            auth.store_refresh_token_1password(
                self.TOKEN, item_title="T", vault="V", op_cmd=["op"])
        self.assertFalse(Path(seen["template_path"]).exists())

    def test_template_is_removed_even_when_op_fails(self):
        seen = {}

        def failing(command, **kwargs):
            seen["template_path"] = [a for a in command if a.endswith(".json")][0]
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="denied")

        with mock.patch.object(auth.subprocess, "run", side_effect=failing):
            with self.assertRaises(auth.LoginError):
                auth.store_refresh_token_1password(
                    self.TOKEN, item_title="T", vault="V", op_cmd=["op"])
        self.assertFalse(Path(seen["template_path"]).exists(),
                         "a failed write must not leave the token on disk")

    def test_returns_an_op_reference_not_the_token(self):
        _, fake_run = self._capture()
        with mock.patch.object(auth.subprocess, "run", side_effect=fake_run):
            reference = auth.store_refresh_token_1password(
                self.TOKEN, item_title="Hexowatch Session", vault="Agent Automation",
                op_cmd=["op"])
        self.assertEqual(reference,
                         "op://Agent Automation/Hexowatch Session/credential")
        self.assertNotIn(self.TOKEN, reference)


class TestVersionIsNotWrittenTwice(unittest.TestCase):
    def test_user_agent_carries_the_package_version(self):
        """Two independent copies of one fact drift silently.

        `__version__` and the version embedded in `USER_AGENT` are separate
        string literals, so bumping one and forgetting the other produces a
        client that misreports itself to the vendor -- with nothing failing.
        Decidable, so it belongs in a check rather than a comment.
        """
        from hexact import __version__
        from hexact.http import USER_AGENT
        self.assertTrue(
            USER_AGENT.startswith(f"hexact-cli/{__version__} "),
            f"USER_AGENT {USER_AGENT!r} does not carry version {__version__!r}",
        )


class TestLiveRunRegressions(unittest.TestCase):
    """Four bugs that only a real account exposed, each of which reported the
    OPPOSITE of the truth. Unit tests passed throughout; the account did not.
    """

    def _args(self, **kwargs):
        return argparse.Namespace(json=True, **kwargs)

    def test_login_stores_the_refresh_token_not_the_access_token(self):
        """`UserLoginResponse` carries both, and only one can be exchanged.

        Storing `token` produced a credential that authenticated for about an
        hour, so every check passed, and then could never be renewed.
        """
        response = {"UserOps": {"authRefreshToken": {
            "error": False, "message": "",
            "token": "SHORT_LIVED_ACCESS", "refresh_token": "LONG_LIVED_REFRESH"}}}
        with mock.patch.object(auth.graphql, "execute", return_value=response):
            self.assertEqual(auth.login("a@b.c", "pw"), "LONG_LIVED_REFRESH")

    def test_login_selects_refresh_token_in_the_query_document(self):
        """A field absent from the selection comes back as None, not an error."""
        self.assertIn("refresh_token", auth._REFRESH_MUTATION)

    def test_deleted_monitor_returns_nulls_rather_than_erroring(self):
        """The live gateway answers a deleted id with a full object of nulls.

        Treating "the call returned" as "still present" made a successful
        delete print STILL PRESENT and exit non-zero.
        """
        with mock.patch.object(cli.auth, "access_token", return_value="tok"), \
             mock.patch.object(cli.graphql, "get_watch_property",
                               return_value={"id": None, "name": None, "url": None}), \
             mock.patch.object(cli.graphql, "delete_monitors", return_value={}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.cmd_watch_delete(self._args(ids=[402138], yes=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["deleted"], [402138])
        self.assertEqual(payload["still_present"], [])

    def test_auth_failure_during_readback_is_never_reported_as_deleted(self):
        """A token expiring mid-loop would otherwise confirm every deletion."""
        with mock.patch.object(cli.auth, "access_token", return_value="tok"), \
             mock.patch.object(cli.graphql, "get_watch_property",
                               side_effect=graphql.AuthError("should be authenticated")), \
             mock.patch.object(cli.graphql, "delete_monitors", return_value={}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.cmd_watch_delete(self._args(ids=[1], yes=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["deleted"], [])
        self.assertEqual([u["id"] for u in payload["unverified"]], [1])
        self.assertNotEqual(code, 0, "an unverified delete must not exit 0")

    def test_a_malformed_readback_query_is_not_proof_of_deletion(self):
        """Measured: a bad selection returned HTTP 400 and every delete
        reported 'gone' on the strength of a syntax error."""
        with mock.patch.object(cli.auth, "access_token", return_value="tok"), \
             mock.patch.object(cli.graphql, "get_watch_property",
                               side_effect=HexactAPIError("HTTP 400 ... must have a selection")), \
             mock.patch.object(cli.graphql, "delete_monitors", return_value={}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.cmd_watch_delete(self._args(ids=[7], yes=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["deleted"], [], "an API error is not evidence of absence")
        self.assertEqual([u["id"] for u in payload["unverified"]], [7])
        self.assertNotEqual(code, 0)

    def test_retune_interval_verifies_the_interval_not_the_level(self):
        """`--interval` used to be 'confirmed' by comparing the level to itself."""
        states = iter([
            {"tool": "pingTool", "change_notification_level": "ANY",
             "monitoring_interval": "3_MONTH"},
            {"tool": "pingTool", "change_notification_level": "ANY",
             "monitoring_interval": "3_MONTH"},   # the write silently did nothing
        ])
        with mock.patch.object(cli.auth, "access_token", return_value="tok"), \
             mock.patch.object(cli.graphql, "get_watch_property",
                               side_effect=lambda *a, **k: next(states)), \
             mock.patch.object(cli.graphql, "update_monitors", return_value={}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = cli.cmd_watch_retune(
                    self._args(ids=[1], level=None, interval="1_MONTH"))
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["applied"], 0,
                         "an unchanged interval must not count as applied")
        self.assertNotEqual(code, 0)

    def test_mute_sends_an_empty_list_rather_than_dropping_the_argument(self):
        """`[]` is falsy. If `mutate` filtered on truthiness, mute would send
        nothing, change nothing, and report success."""
        seen = {}

        def capture(query, variables=None, **kwargs):
            seen["query"], seen["variables"] = query, variables
            return {"WatchIntegrationOps": {
                "updateWatchPropertyIntegrations": {"error": False}}}

        with mock.patch.object(graphql, "execute", side_effect=capture):
            graphql.set_monitor_integrations("tok", 402138, [])
        self.assertEqual(seen["variables"]["watch_integration_ids"], [])
        self.assertIn("watch_integration_ids", seen["query"])

    def test_auth_status_recognises_a_directly_supplied_access_token(self):
        """`status` checked only the refresh token, so it reported 'missing'
        on a session where every other command worked."""
        with mock.patch.dict(os.environ, {"HEXOWATCH_ACCESS_TOKEN": "direct-token"}), \
             mock.patch.object(auth.graphql, "execute",
                               return_value={"WatchOps": {"updateWatchProperty": {
                                   "error": True, "message": "Permission denied"}}}):
            verdict, _ = auth.status()
        self.assertEqual(verdict, "authenticated")


class TestGatewayDocCoversWhatTheCodeUses(unittest.TestCase):
    """Rung-4: the generated reference must describe every operation we call.

    `docs/GATEWAY.md` is regenerated from a live walk whose recall is a lower
    bound, so a future run can silently come back with fewer names. That would
    leave the doc quietly not describing operations the CLI depends on. This
    does not test that the vendor still has them -- only that the reference and
    the allowlist have not drifted apart.
    """

    def setUp(self):
        self.doc = Path(__file__).resolve().parent.parent / "docs" / "GATEWAY.md"
        if not self.doc.is_file():
            self.skipTest("docs/GATEWAY.md not generated in this checkout")
        self.text = self.doc.read_text(encoding="utf-8")

    def test_every_allowlisted_mutation_appears_in_the_reference(self):
        for operation in sorted(graphql.MUTATION_ALLOWLIST):
            namespace, _, field = operation.partition(".")
            self.assertIn(namespace, self.text,
                          f"{namespace} missing from GATEWAY.md")
            self.assertIn(f"`{field}`", self.text,
                          f"{operation} missing from GATEWAY.md")

    def test_the_reference_states_it_is_a_lower_bound(self):
        """The caveat is the most load-bearing sentence in the document.

        Without it a namespace rendered with zero fields reads as 'this is
        empty' rather than 'the probe did not reach it'. Pinned as prose
        because the claim is a judgement; only its presence is decidable.
        """
        lowered = self.text.lower()
        self.assertTrue(
            "lower bound" in lowered or "not discovered" in lowered
            or "undiscovered" in lowered,
            "GATEWAY.md must say its coverage is a lower bound",
        )

    def test_the_reference_records_the_no_execute_guarantee(self):
        self.assertIn("resolvers entered", self.text.lower())


class _TrapGateway:
    """A gateway that 'enters a resolver' for any probe missing the guard.

    Faithful to the one property that matters: a probe carrying the bogus
    argument fails GraphQL validation, so the server returns ``errors`` with no
    ``data`` (inert). A probe *without* it, naming only a valid optional
    argument, is a valid document and the resolver runs -- modelled here by
    returning a non-null ``data``. So ``resolver_was_entered`` flips iff a probe
    dropped the guard, which is exactly the regression to catch.
    """

    BOGUS = "zzzNotAnArg"

    def __init__(self):
        self.documents: list[str] = []

    def messages(self, payload):  # mirrors schema_map.Gateway.messages
        return [e.get("message", "") for e in (payload.get("errors") or [])]

    def post(self, document: str) -> dict:
        self.documents.append(document)
        if self.BOGUS not in document:
            # An unguarded, otherwise-valid document reaches the resolver.
            return {"data": {"TestOps": {"doThing": None}}}
        msgs = ['Unknown argument "zzzNotAnArg" on field "doThing" of type "TestOps".']
        if "__typename" not in document:  # the base probe carries the return type
            msgs.append('Field "doThing" of type "BaseMutationResponse" '
                        'must have a selection of subfields.')
        else:  # discovery/type probes surface an optional arg and its type
            msgs.append('Unknown argument "x" on field "doThing" of type '
                        '"TestOps". Did you mean "note"?')
        if "123" in document:
            msgs.append("Expected type String, found 123.")
        return {"errors": [{"message": m} for m in msgs]}


class TestSchemaMapNeverEntersAResolver(unittest.TestCase):
    """Rung-4 lock on the safety invariant that broke.

    An earlier `describe_field` guarded only its base probe; the argument-type
    probe `field(realOptionalArg: "zZq")` was a valid document and entered 34
    resolvers on the live gateway. The guard now applies to every probe shape;
    this test fails the moment any shape drops it again -- decidable, offline,
    and independent of the live API.
    """

    def setUp(self):
        import importlib.util
        path = Path(__file__).resolve().parent.parent / "tools" / "schema_map.py"
        if not path.is_file():
            self.skipTest("tools/schema_map.py not present in this checkout")
        spec = importlib.util.spec_from_file_location("schema_map", path)
        self.schema_map = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.schema_map)

    def test_every_probe_carries_the_bogus_argument_and_nothing_executes(self):
        from concurrent.futures import ThreadPoolExecutor
        trap = _TrapGateway()
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = self.schema_map.describe_field(
                trap, "TestOps", "doThing", "mutation", pool)

        self.assertTrue(trap.documents, "no probes were sent")
        missing = [d for d in trap.documents if _TrapGateway.BOGUS not in d]
        self.assertEqual(
            missing, [],
            f"{len(missing)} probe(s) dropped the bogus-argument guard, e.g. "
            f"{missing[:1]} -- an unguarded probe can enter a live resolver",
        )
        self.assertFalse(
            result["resolver_was_entered"],
            "describe_field entered a resolver against the trap gateway",
        )
        # The guard must not cost recovery: return type and the optional arg
        # (with its type, read from the guarded 123 probe) still come back.
        self.assertEqual(result["returns"], "BaseMutationResponse")
        self.assertIn("note", [a["name"] for a in result["optional_arguments"]])
        self.assertEqual(
            "String",
            next(a["type"] for a in result["optional_arguments"]
                 if a["name"] == "note"),
        )

    def test_the_trap_would_catch_a_dropped_guard(self):
        """Prove the trap is not vacuous: an unguarded doc DOES flip to data."""
        trap = _TrapGateway()
        guarded = trap.post("mutation { TestOps { doThing(note: 123, zzzNotAnArg: 1) } }")
        unguarded = trap.post("mutation { TestOps { doThing(note: 123) } }")
        self.assertIsNone(guarded.get("data"))
        self.assertIsNotNone(unguarded.get("data"))


def _load_schema_map():
    """Load tools/schema_map.py as a module, or None when absent."""
    import importlib.util
    path = Path(__file__).resolve().parent.parent / "tools" / "schema_map.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("schema_map", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _SuggestionParsingFake:
    """Base for gateway fakes: reuse the REAL suggestion parser, not a copy.

    `walk_fields` calls `gateway.suggestions(payload)`. Re-implementing that
    parse in the test would let the test pass while the real regex rotted.
    """

    def suggestions(self, payload):
        return _load_schema_map().Gateway.suggestions(payload)


class _SilentNamespaceGateway(_SuggestionParsingFake):
    """Answers only when probed with a near-miss of a *sibling's* field name.

    Models the real thing that made 6 namespaces look empty: the suggester only
    offers names within `floor(len(probe)*0.4)+1` edits, so a field reachable
    from a sibling's real name can be invisible to every stem-derived seed.
    """

    SECRET = "deleteCreditCard"          # only reachable from its own near-miss
    TRIGGER = "deleteCreditCarZz"        # what variants("deleteCreditCard") emits

    def __init__(self):
        self.probes: list[str] = []

    def post(self, document: str) -> dict:
        self.probes.append(document)
        if self.TRIGGER in document:
            return {"errors": [{"message": f'Cannot query field "{self.TRIGGER}" on '
                                           f'type "BillingOps". Did you mean '
                                           f'"{self.SECRET}"?'}]}
        return {"errors": [{"message": 'Cannot query field "x" on type "BillingOps".'}]}


class TestEmptyNamespaceFallsBackToTheFieldDictionary(unittest.TestCase):
    """Rung-4: the generator must be able to reproduce its own output.

    `docs/GATEWAY.md` says it is generated by `tools/schema_map.py` and must not
    be hand-edited. 17 of its fields were first found by seeding empty
    namespaces with near-misses of field names from *other* namespaces. If that
    fallback is ever dropped, a regeneration silently returns fewer fields and
    re-labels real namespaces UNKNOWN -- the doc would then quietly disagree
    with the tool that claims to produce it, with nothing going red.
    """

    def setUp(self):
        import importlib.util
        path = Path(__file__).resolve().parent.parent / "tools" / "schema_map.py"
        if not path.is_file():
            self.skipTest("tools/schema_map.py not present in this checkout")
        spec = importlib.util.spec_from_file_location("schema_map", path)
        self.schema_map = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.schema_map)

    def _walk(self):
        from concurrent.futures import ThreadPoolExecutor
        gw = _SilentNamespaceGateway()
        with ThreadPoolExecutor(max_workers=2) as pool:
            found = self.schema_map.walk_fields(gw, "BillingOps", "mutation", pool)
        return gw, found

    def test_a_sibling_name_cracks_an_otherwise_silent_namespace(self):
        # A name known only from another namespace, exactly like the real run.
        self.schema_map.remember_fields({_SilentNamespaceGateway.SECRET})
        gw, found = self._walk()
        self.assertIn(_SilentNamespaceGateway.SECRET, found,
                      "the field dictionary fallback did not run for an empty "
                      "namespace; a regeneration would silently lose fields")
        self.assertTrue(any(_SilentNamespaceGateway.TRIGGER in p for p in gw.probes))

    def test_without_the_dictionary_the_namespace_stays_silent(self):
        """Non-vacuous: with an empty dictionary the same walk finds nothing."""
        self.schema_map.FIELD_VOCABULARY.clear()
        _, found = self._walk()
        self.assertEqual(found, set())

    def test_the_dictionary_is_not_used_when_normal_seeds_already_worked(self):
        """Cost guard: 300 names x 94 namespaces would be tens of thousands of
        extra requests, so the fallback must fire only for empty namespaces."""
        self.schema_map.remember_fields({"somethingUnrelated"})

        class Answers(_SuggestionParsingFake):
            def __init__(self): self.probes = []

            def post(self, document):
                self.probes.append(document)
                return {"errors": [{"message": 'Cannot query field "q" on type '
                                               '"Ops". Did you mean "getThing"?'}]}

        from concurrent.futures import ThreadPoolExecutor
        gw = Answers()
        with ThreadPoolExecutor(max_workers=2) as pool:
            found = self.schema_map.walk_fields(gw, "ThingOps", "query", pool)
        self.assertIn("getThing", found)
        self.assertFalse(any("somethingUnrelatedZz" in p for p in gw.probes),
                         "dictionary fallback ran despite normal seeds working")


def _jwt(lifetime_seconds: int, *, issued_offset: int = 0) -> str:
    """A structurally valid JWT with real timing claims and a junk signature.

    Nothing here verifies signatures -- only the `iat`/`exp` claims are read --
    so a fake is sufficient and no real credential is needed in a test file.
    """
    issued = int(datetime.now(timezone.utc).timestamp()) + issued_offset
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    body = json.dumps({"iat": issued, "exp": issued + lifetime_seconds,
                       "id": 1, "userType": "user", "version": 1}).encode()
    return b".".join([header, base64.urlsafe_b64encode(body).rstrip(b"="),
                      b"not-a-real-signature"]).decode()


class TestCredentialClassification(unittest.TestCase):
    """A stored credential must be identifiable as the wrong *kind*, offline.

    Regression for a real outage: the 1Password item in the refresh-token slot
    held a one-hour token, so every command failed a day later with "not
    accepted" -- a message that points at the network or the account, not at the
    credential. Both directions are asserted, because a classifier that answers
    "access" for everything would pass a one-sided test while breaking login.
    """

    def test_a_one_hour_token_is_an_access_token(self):
        facts = auth.classify_credential(_jwt(3600))
        self.assertEqual(facts["kind"], "access")
        self.assertEqual(facts["lifetime_seconds"], 3600)

    def test_a_long_lived_token_is_a_refresh_token(self):
        facts = auth.classify_credential(_jwt(30 * 24 * 3600))
        self.assertEqual(facts["kind"], "refresh")

    def test_a_non_jwt_is_opaque_rather_than_guessed(self):
        facts = auth.classify_credential("plain-opaque-token-value")
        self.assertEqual(facts["kind"], "opaque")
        self.assertIsNone(facts["expired"])

    def test_expiry_in_the_past_is_reported_as_expired(self):
        facts = auth.classify_credential(_jwt(3600, issued_offset=-86400))
        self.assertTrue(facts["expired"])

    def test_description_never_contains_the_token(self):
        token = _jwt(3600)
        self.assertNotIn(token, auth.describe_credential(token))
        self.assertNotIn(token.split(".")[1], auth.describe_credential(token))


class TestLoginRefusesAnUnrenewableCredential(unittest.TestCase):
    """Selecting `refresh_token` was never the guarantee; checking it is.

    The shipped build already read the right field and a one-hour token still
    ended up stored, because nothing inspected what actually arrived and nothing
    exercised it before writing it to 1Password.
    """

    def test_login_rejects_an_access_shaped_refresh_token(self):
        payload = {"UserOps": {"authRefreshToken": {
            "error": False, "token": "x", "refresh_token": _jwt(3600)}}}
        with mock.patch.object(graphql, "execute", return_value=payload):
            with self.assertRaises(auth.LoginError) as caught:
                auth.login("a@b.com", "pw")
        self.assertIn("ACCESS token", str(caught.exception))

    def test_login_accepts_a_genuine_refresh_token(self):
        good = _jwt(30 * 24 * 3600)
        payload = {"UserOps": {"authRefreshToken": {
            "error": False, "token": "x", "refresh_token": good}}}
        with mock.patch.object(graphql, "execute", return_value=payload):
            self.assertEqual(auth.login("a@b.com", "pw"), good)

    def test_nothing_is_stored_when_the_exchange_fails(self):
        """The whole point: a credential that cannot be exchanged never lands.

        Asserts on the *absence* of a write. A test that only checked the raised
        exception would pass even if the token had already been persisted before
        the check ran, which is precisely the ordering bug being fixed.
        """
        refresh = _jwt(30 * 24 * 3600)

        def fake_execute(document, variables=None, **kwargs):
            if "authRefreshToken" in document:
                return {"UserOps": {"authRefreshToken": {
                    "error": False, "token": "x", "refresh_token": refresh}}}
            # The gateway's house style for "no": success envelope, null token.
            return {"UserOps": {"authAccessToken": {"error": False, "token": None}}}

        # Built through the real parser rather than by hand. A hand-rolled
        # Namespace stops matching the command it stands in for the moment a
        # flag is added, and the test then dies on an AttributeError that has
        # nothing to do with the property it was written to check.
        args = cli.build_parser().parse_args(
            ["auth", "login", "--email", "a@b.com", "--store", "file",
             "--op-item", "T", "--op-vault", "V"])
        with mock.patch.object(auth, "prompt_password", return_value="pw"), \
                mock.patch.object(graphql, "execute", side_effect=fake_execute), \
                mock.patch.object(auth, "store_refresh_token") as store_file, \
                mock.patch.object(auth, "store_refresh_token_1password") as store_op:
            with self.assertRaises(auth.LoginError):
                cli.cmd_auth_login(args)
        store_file.assert_not_called()
        store_op.assert_not_called()


class TestTagWritesAreConfirmedNotClaimed(unittest.TestCase):
    """`{"error": false}` is the gateway's word, not evidence.

    Every other write in this client reads its result back. These assert the
    tag commands do the same, and -- more importantly -- that a create the
    gateway *claims* succeeded but which is absent afterwards is reported as a
    failure with a non-zero exit, rather than as success.
    """

    def _args(self, **overrides):
        base = dict(json=False, name="staging", color="#4c8bf5")
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_create_reports_failure_when_the_tag_is_not_there_afterwards(self):
        with mock.patch.object(auth, "access_token", return_value="t"), \
                mock.patch.object(graphql, "create_tag",
                                  return_value={"error": False, "watch_tag_id": 7}), \
                mock.patch.object(graphql, "get_user_tags",
                                  return_value={"tags": []}), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli_hexowatch.cmd_tag_create(self._args())
        self.assertEqual(code, 2)
        self.assertIn("not created", out.getvalue())

    def test_create_confirms_when_the_read_back_finds_it(self):
        with mock.patch.object(auth, "access_token", return_value="t"), \
                mock.patch.object(graphql, "create_tag",
                                  return_value={"error": False, "watch_tag_id": 7}), \
                mock.patch.object(graphql, "get_user_tags", return_value={
                    "tags": [{"id": 7, "name": "staging", "color": "#4c8bf5"}]}), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli_hexowatch.cmd_tag_create(self._args())
        self.assertEqual(code, 0)
        self.assertIn("confirmed", out.getvalue())

    def test_delete_reports_failure_when_the_tag_survives(self):
        with mock.patch.object(auth, "access_token", return_value="t"), \
                mock.patch.object(graphql, "delete_tag", return_value={"error": False}), \
                mock.patch.object(graphql, "get_user_tags", return_value={
                    "tags": [{"id": 7, "name": "staging", "color": "#fff"}]}), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli_hexowatch.cmd_tag_delete(argparse.Namespace(json=False, tag_id=7))
        self.assertEqual(code, 2)
        self.assertIn("still present", out.getvalue())


class TestDestructiveDefaultsAreRefused(unittest.TestCase):
    """Two mutations whose *empty* form is the destructive one.

    `updateWatchPropertyTags` replaces rather than appends, so `--tag` omitted
    would clear every tag on the monitor. Deleting alerts has no undo. Both must
    refuse rather than proceed, and must not reach the network to do so.
    """

    def test_tag_set_refuses_an_empty_list_without_clear(self):
        sent = []
        with mock.patch.object(auth, "access_token", side_effect=lambda: sent.append("token")), \
                mock.patch.object(graphql, "set_property_tags",
                                  side_effect=AssertionError("must not be called")), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli_hexowatch.cmd_tag_set(argparse.Namespace(
                json=False, monitoring_id=1, tags=[], clear=False))
        self.assertEqual(code, 2)
        self.assertIn("REPLACES", err.getvalue())
        self.assertEqual(sent, [], "refused before any credential was resolved")

    def test_alert_delete_refuses_without_yes(self):
        """Asserts the refusal happens *before* the credential is resolved.

        The first version of this test mocked `access_token` to return a token
        and only checked the exit code, so it passed while the command was in
        fact resolving a credential and hitting the network first -- which a
        live smoke run exposed as an auth error where a usage error belonged.
        Patching it with a `side_effect` that fails is what makes the ordering
        observable rather than assumed.
        """
        with mock.patch.object(auth, "access_token",
                               side_effect=AssertionError("resolved a credential "
                                                          "before refusing")), \
                mock.patch.object(graphql, "delete_alerts",
                                  side_effect=AssertionError("must not be called")), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli_hexowatch.cmd_alerts(argparse.Namespace(
                json=False, alert_action="delete", ids=[1, 2], yes=False, all=False))
        self.assertEqual(code, 2)
        self.assertIn("irreversible", err.getvalue())


class TestGatewayJsonStringsAreNeverAssumedToParse(unittest.TestCase):
    """`data` and `time_series` arrive as JSON *strings*, and sometimes do not.

    An error path can put a bare message in the same field. Turning that into a
    `JSONDecodeError` would replace a readable failure with a stack trace, so
    the raw value must survive.
    """

    def test_valid_json_is_parsed(self):
        self.assertEqual(cli_hexomatic._maybe_json('{"used": 12}'), {"used": 12})

    def test_a_bare_message_is_kept_verbatim(self):
        self.assertEqual(cli_hexomatic._maybe_json("no data for this period"),
                         "no data for this period")

    def test_a_non_string_passes_through(self):
        self.assertEqual(cli_hexomatic._maybe_json({"already": "parsed"}),
                         {"already": "parsed"})


class TestMonitorFiltersTravelAsVariables(unittest.TestCase):
    """Filter values must never be interpolated into the query document.

    Same rule the mutation path already enforces. A search term is user input
    and reaches a query language; the only safe place for it is a variable.
    """

    def test_search_and_tags_are_sent_as_variables(self):
        captured = {}

        def fake_execute(document, variables=None, **kwargs):
            captured["document"] = document
            captured["variables"] = variables
            return {"Watch": {"getUserWatchProperties":
                              {"totalCount": 0, "watchProperties": []}}}

        with mock.patch.object(graphql, "execute", side_effect=fake_execute):
            graphql.list_monitors("t", search='" } evil {', tags=[3, 4], tool="keywordTool")

        self.assertNotIn("evil", captured["document"])
        self.assertEqual(captured["variables"]["searchQuery"], '" } evil {')
        self.assertEqual(captured["variables"]["tags"], [3, 4])


class TestNoiseBreakdownSurvivesAnEmptyPeriod(unittest.TestCase):
    def test_zero_total_does_not_divide_by_zero(self):
        with mock.patch.object(auth, "access_token", return_value="t"), \
                mock.patch.object(graphql, "notification_breakdown",
                                  return_value=[{"field": "visual", "count": 0}]), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli_hexowatch.cmd_noise(
                argparse.Namespace(json=False, since=None, until=None))
        self.assertEqual(code, 0)
        self.assertIn("visual", out.getvalue())


class TestHexosparkStaysReadOnly(unittest.TestCase):
    """The read-only boundary, pinned structurally rather than by intention.

    Hexospark's writes create campaigns and attach contacts, which puts mail in
    front of real people. Two independent things must hold: the module ships no
    mutation document, and the allowlist refuses every Hexospark operation. A
    later change that adds one has to defeat both, and the second still holds
    even if this module is rewritten.
    """

    def test_the_module_contains_no_mutation_document(self):
        """Inspects the module's GraphQL constants, not its prose.

        A first version grepped the source for lines starting with `mutation`
        and failed on its own docstring, which is the standard way a structural
        test becomes something people delete instead of trust.
        """
        documents = [value for name in dir(hexospark)
                     if name.isupper()
                     for value in [getattr(hexospark, name)]
                     if isinstance(value, str)]
        offending = [d[:60] for d in documents
                     if re.match(r"\s*mutation\b", d)]
        self.assertEqual(offending, [],
                         "hexospark.py is read-only by design; a mutation appeared")

    def test_the_allowlist_refuses_every_hexospark_operation(self):
        for operation in ("HexosparkCampaignOps.create",
                          "HexosparkCampaignOps.addContacts",
                          "HexosparkCrmContactOps.create",
                          "HexosparkCommonOps.importCSV"):
            with self.assertRaises(HexactAPIError):
                graphql.mutate(operation, {}, token="t")


class TestNewGatewayOperationNamesArePinned(unittest.TestCase):
    """The vendor's names are undocumented and unversioned.

    A silent rename should fail here loudly rather than return null at runtime,
    where `unwrap` would report it as an auth failure and send the reader to
    re-login for no reason.
    """

    EXPECTED = {
        "graphql.USER_TAGS_QUERY": ["WatchTag", "getUserWatchTags"],
        "graphql.PROPERTY_TAGS_QUERY": ["WatchTag", "getWatchPropertyTags"],
        "graphql.USER_PROPERTIES_QUERY": ["Watch", "getUserWatchProperties"],
        "graphql.NOTIFICATIONS_PIE_QUERY": ["WatchNotification",
                                            "watchNotificationsPieChart"],
        "hexomatic.WORKFLOWS_QUERY": ["HexomaticWorkflow", "getWorkflows"],
        "hexomatic.WORKFLOW_RESULT_JSON_QUERY": ["HexomaticWorkflow",
                                                 "getWorkflowResultJSON"],
        "hexomatic.CREDIT_USAGE_QUERY": ["HexomaticAutomation",
                                         "getAutomationCreditUsage"],
        "hexospark.CRM_CONTACTS_QUERY": ["HexosparkCrmContact", "getCrmContacts"],
        "hexospark.CAMPAIGNS_QUERY": ["HexosparkCampaign", "getCampaigns"],
        "hexometer.PROPERTIES_QUERY": ["Property", "get"],
        "hexometer.ISSUES_QUERY": ["HexometerIssues", "getIssues"],
    }

    def test_every_document_names_the_namespace_and_field_it_unwraps(self):
        modules = {"graphql": graphql, "hexomatic": hexomatic,
                   "hexospark": hexospark, "hexometer": hexometer}
        for dotted, (namespace, field) in self.EXPECTED.items():
            module_name, _, attribute = dotted.partition(".")
            document = getattr(modules[module_name], attribute)
            self.assertIn(namespace, document, f"{dotted} lost its namespace")
            self.assertIn(field, document, f"{dotted} lost its field")


class TestDerivedReferencesStayReachable(unittest.TestCase):
    """A derived doc nobody can find is a doc that rots unnoticed.

    Asserts the route exists, not that anyone read it: TYPES.md is generated,
    and the only thing keeping it discoverable is a link from the curated
    reference. Both files also have to actually be there -- a link to a
    document that was never committed sends a reader somewhere worse than
    nowhere.
    """

    def test_api_md_links_both_derived_references(self):
        root = Path(__file__).resolve().parent.parent
        api = (root / "docs" / "API.md").read_text(encoding="utf-8")
        for name in ("GATEWAY.md", "TYPES.md"):
            self.assertTrue((root / "docs" / name).is_file(), f"docs/{name} is missing")
            self.assertIn(name, api, f"docs/API.md does not link {name}")


class TestUserAgentTracksTheVersion(unittest.TestCase):
    """A User-Agent that lies about its version is worse than an unversioned one.

    It was typed by hand in two files, and a bump updated neither, so the
    server-side log claimed a release that was never the one running. Cheap and
    decidable, so it is checked rather than remembered.
    """

    def test_the_agent_string_contains_the_package_version(self):
        from hexact import __version__
        from hexact.http import USER_AGENT
        self.assertIn(__version__, USER_AGENT)

    def test_no_module_hardcodes_a_different_version(self):
        from hexact import __version__
        root = Path(__file__).resolve().parent.parent
        stale = []
        for path in list((root / "hexact").glob("*.py")) + list((root / "tools").glob("*.py")):
            for match in re.finditer(r"hexact-cli/(\d+\.\d+\.\d+)", path.read_text(encoding="utf-8")):
                if match.group(1) != __version__:
                    stale.append(f"{path.name}: {match.group(0)}")
        self.assertEqual(stale, [], "a hardcoded agent string drifted from __version__")


class TestSessionErrorFitsEveryCommandThatRaisesIt(unittest.TestCase):
    """One session token serves the whole suite, so the "it is missing" message
    is shared by every GraphQL command -- and must therefore claim neither a
    product nor an operation.

    Pins the fix for a measured defect. The message read "No Hexowatch session
    token found. Delete and update are GraphQL-only and the REST API key does
    not authenticate there." and was printed verbatim by `matic credits`,
    `spark contacts` and `meter overview`. The remedy line underneath it was
    correct throughout, which is what made the wrong diagnosis expensive rather
    than merely untidy: a reader who does not own Hexowatch, or who ran a
    read-only command, has every reason to decide the error is about something
    else and stop before the fix.

    This exercises the real ``main()`` entry point rather than calling
    ``resolve_key`` directly, because the property under test is "what a user
    sees", and that is produced by the CLI's exception handler, not by the
    raise site.
    """

    # Spans all four wired products on purpose. A fifth product routed to the
    # same credential belongs in this list, not in an assumption that the
    # wording still fits it.
    COMMANDS = (
        ["watch", "tags", "list"],
        ["watch", "list"],
        ["watch", "noise"],
        ["matic", "credits"],
        ["meter", "overview"],
        ["spark", "contacts"],
    )

    # Wording that is false for at least one command in COMMANDS.
    FORBIDDEN = ("delete and update", "no hexowatch session")

    def _run(self, argv: list[str]) -> tuple[int, str]:
        with TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"HEXACT_HOME": tmp}, clear=False):
                err = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()):
                    with contextlib.redirect_stderr(err):
                        code = main(argv)
        return code, err.getvalue()

    def test_every_graphql_command_reaches_the_same_credential_error(self):
        """The premise of the test below: they really do share one message."""
        for argv in self.COMMANDS:
            with self.subTest(command=" ".join(argv)):
                code, err = self._run(argv)
                self.assertEqual(code, 1, err)
                self.assertIn("session token", err)
                self.assertIn("hexact auth login", err)

    def test_the_message_asserts_no_single_product_and_no_operation(self):
        for argv in self.COMMANDS:
            with self.subTest(command=" ".join(argv)):
                _, err = self._run(argv)
                lowered = err.lower()
                for phrase in self.FORBIDDEN:
                    self.assertNotIn(
                        phrase, lowered,
                        f"`hexact {' '.join(argv)}` is told {phrase!r}, which is "
                        "not what it was doing",
                    )


class TestNoModuleOutgrowsTheProjectsOwnCeiling(unittest.TestCase):
    """800 lines is this project's stated file ceiling. It was prose, and
    `cli.py` reached 1364 lines without anything going red.

    A line count is decidable, the cost of the drift repeated across two
    rounds, and the failure was silent -- so this is one of the few style
    rules worth spending a test on. It asserts the size, not the design; a
    module that stays small for bad reasons still passes, and that is fine.
    """

    CEILING = 800

    def test_every_module_is_under_the_ceiling(self):
        root = Path(__file__).resolve().parent.parent
        oversized = {}
        for path in sorted(root.glob("hexact/*.py")) + sorted(root.glob("tools/*.py")):
            count = len(path.read_text(encoding="utf-8").splitlines())
            if count > self.CEILING:
                oversized[path.name] = count
        self.assertEqual(
            oversized, {},
            f"over the {self.CEILING}-line ceiling; split by responsibility",
        )

    def test_the_ceiling_check_can_actually_fail(self):
        """The measurement itself, run against a file that is definitely over.

        Without this the test above would still pass if `glob` matched nothing
        -- a green light over an empty denominator.
        """
        with TemporaryDirectory() as tmp:
            fat = Path(tmp) / "fat.py"
            fat.write_text("x = 1\n" * (self.CEILING + 1), encoding="utf-8")
            self.assertGreater(
                len(fat.read_text(encoding="utf-8").splitlines()), self.CEILING
            )
        root = Path(__file__).resolve().parent.parent
        self.assertGreater(len(list(root.glob("hexact/*.py"))), 5,
                           "the ceiling test is looking at the wrong directory")


class TestTheCLICanSayWhichBuildItIs(unittest.TestCase):
    """`--version` is how a bug report stops starting with a guess."""

    def test_version_flag_prints_the_package_version(self):
        from hexact import __version__
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as raised:
                main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn(__version__, out.getvalue())

    def test_the_packaging_metadata_reads_the_same_version(self):
        """`pyproject.toml` must derive the version, never restate it.

        Two copies of a version string is how this project's User-Agent came to
        advertise a release that was never running.
        """
        root = Path(__file__).resolve().parent.parent
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('attr = "hexact.__version__"', pyproject)
        from hexact import __version__
        self.assertNotIn(f'version = "{__version__}"', pyproject)


class TestTheReleaseIsDescribedSomewhere(unittest.TestCase):
    """A version bump with no changelog entry is invisible to everyone
    installing from a package index or a git URL.

    Decidable, silent when it goes wrong, and it goes wrong every release --
    which is the whole case for spending a test on it. It checks that an entry
    *exists*, not that it is any good; no test can judge that.
    """

    def test_the_current_version_has_a_changelog_entry(self):
        from hexact import __version__
        root = Path(__file__).resolve().parent.parent
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(
            f"## {__version__}", changelog,
            f"CHANGELOG.md has no `## {__version__}` heading -- the release "
            "would ship with nothing said about it",
        )

    def test_the_check_would_notice_a_missing_entry(self):
        """Proves the assertion above is not vacuous on any string."""
        root = Path(__file__).resolve().parent.parent
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertNotIn("## 99.99.99", changelog)


class TestTheReadmeDoesNotOutliveTheAllowlist(unittest.TestCase):
    """The README described the write boundary with a number, and the number
    was wrong: it said "exactly ten mutations" while the allowlist held 19.

    Nothing went red, because a count in prose is a fact about the past written
    somewhere that never gets re-read. The fix is not a better number -- it is
    to derive the claim. This checks the marked block against the code, so the
    documented boundary and the enforced one cannot disagree.
    """

    MARKER_OPEN = "<!-- allowlist-namespaces -->"
    MARKER_CLOSE = "<!-- /allowlist-namespaces -->"

    def _documented(self) -> set[str]:
        root = Path(__file__).resolve().parent.parent
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn(self.MARKER_OPEN, readme, "the marked block was removed")
        block = readme.split(self.MARKER_OPEN, 1)[1].split(self.MARKER_CLOSE, 1)[0]
        return set(re.findall(r"`(\w+)`", block))

    def test_the_readme_lists_exactly_the_namespaces_the_allowlist_uses(self):
        enforced = {op.split(".", 1)[0] for op in graphql.MUTATION_ALLOWLIST}
        self.assertEqual(
            self._documented(), enforced,
            "README.md's allowlist-namespaces block disagrees with "
            "graphql.MUTATION_ALLOWLIST",
        )

    def test_the_readme_no_longer_states_a_count_that_can_drift(self):
        root = Path(__file__).resolve().parent.parent
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertNotRegex(
            readme, r"permits exactly \w+ mutations",
            "a hand-maintained count is how this went wrong the first time",
        )


class TestDriftAndSilenceAreDifferentVerdicts(unittest.TestCase):
    """`tools/validate_documents.py` had one failure bucket: exit 1.

    A renamed field and an unreachable gateway produced the same code, so any
    caller acting on it either treats an outage as drift -- and hunts a bug
    that does not exist -- or learns to ignore the signal, which is worse,
    because the one run that matters looks exactly like the noise. Three
    states now: 0 verified, 1 a real finding, 2 no verdict.

    The 2 cases are the point of this class. A check that cannot say "I did not
    manage to check" reports absence of evidence as evidence of absence.
    """

    CANARY_ERROR = {"message": 'Cannot query field "__zzzCanaryFieldThatCannotExist" on type "Query".'}

    def setUp(self):
        import importlib.util
        path = Path(__file__).resolve().parent.parent / "tools" / "validate_documents.py"
        if not path.is_file():
            self.skipTest("tools/validate_documents.py not present in this checkout")
        spec = importlib.util.spec_from_file_location("validate_documents", path)
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def _main_with(self, fake_post) -> int:
        with mock.patch.object(self.mod, "post", fake_post):
            with contextlib.redirect_stdout(io.StringIO()):
                with contextlib.redirect_stderr(io.StringIO()):
                    return self.mod.main()

    def test_every_document_valid_is_zero(self):
        self.assertEqual(
            self._main_with(lambda doc, variables=None: {"data": None,
                                                         "errors": [self.CANARY_ERROR]}),
            0,
        )

    def test_a_renamed_field_is_one(self):
        payload = {"data": None, "errors": [
            self.CANARY_ERROR,
            {"message": 'Cannot query field "totalCount" on type "WatchPropertiesType".'},
        ]}
        self.assertEqual(self._main_with(lambda doc, variables=None: payload), 1)

    def test_a_canary_that_stopped_stopping_execution_is_one(self):
        """Our own defect, not the vendor's: still a hard failure."""
        payload = {"data": {"Watch": {}}, "errors": [self.CANARY_ERROR]}
        self.assertEqual(self._main_with(lambda doc, variables=None: payload), 1)

    def test_an_unreachable_gateway_is_two_not_one(self):
        def unreachable(document, variables=None):
            raise self.mod.GatewaySilent("could not reach the gateway: [Errno 8]")
        self.assertEqual(self._main_with(unreachable), 2)

    def test_a_response_with_no_canary_error_is_two_not_one(self):
        """`Unauthorized`, a proxy envelope, an empty list -- all mean the
        document never reached a validator, so none of them is drift."""
        for messages in ([], [{"message": "Unauthorized"}]):
            with self.subTest(messages=messages):
                payload = {"data": None, "errors": messages}
                self.assertEqual(self._main_with(lambda doc, variables=None: payload), 2)

    def test_a_challenge_page_is_silence_rather_than_a_parsed_verdict(self):
        """HTTP 200 carrying HTML. The old code let the JSONDecodeError escape
        `main()` entirely, so the process died on a traceback -- which also
        exits 1, and looks nothing like a schema report."""
        html = b"<!DOCTYPE html><html><body>Enable JavaScript</body></html>"

        class _Body(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *exc): return False

        with mock.patch.object(self.mod.urllib.request, "urlopen",
                               return_value=_Body(html)):
            with self.assertRaises(self.mod.GatewaySilent) as raised:
                self.mod.post("query { x }")
        self.assertIn("non-JSON", str(raised.exception))

    def test_a_waf_block_is_silence_rather_than_an_empty_error_list(self):
        """A status code with an unreadable body used to become
        `{"_http": 403}`, whose empty error list was then reported per document
        as if each had been examined."""
        error = urllib.error.HTTPError(
            "https://example.invalid", 403, "Forbidden", {}, io.BytesIO(b"<html>blocked</html>")
        )
        with mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(self.mod.GatewaySilent) as raised:
                self.mod.post("query { x }")
        self.assertIn("403", str(raised.exception))


class TestEveryRemedyIsACommandThatRuns(unittest.TestCase):
    """`--email` is required on `auth login`, so a remedy line that omits it
    hands the user a command that exits 2 before doing anything.

    Five error paths said `Run: hexact auth login` while the CLI's own
    top-level handler already said `hexact auth login --email <you>`. Nothing
    could notice, because an error message is the one string no test asserts on
    unless someone writes this. The predicate is decidable: if a message names
    the login command, it must name the flag that command requires.
    """

    def test_login_still_requires_the_flag_this_test_is_about(self):
        """The premise. If `--email` ever becomes optional, delete this class
        rather than editing the messages to satisfy it."""
        login = cli.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                login.parse_args(["auth", "login"])
        self.assertEqual(raised.exception.code, 2)

    def test_no_source_file_suggests_the_command_without_it(self):
        root = Path(__file__).resolve().parent.parent
        offenders = []
        for path in sorted(root.glob("hexact/*.py")):
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "hexact auth login" not in line:
                    continue
                if "--email" in line:
                    continue
                # A prose mention that is not offered as a command to run.
                if re.search(r"``hexact auth login``|`hexact auth login`(?!\s*--)", line) \
                        and "Run:" not in line and "Fix:" not in line:
                    continue
                offenders.append(f"{path.name}:{number}: {line.strip()}")
        self.assertEqual(
            offenders, [],
            "these lines tell the user to run a command that will refuse",
        )


def _command_tree(parser, prefix=()):
    """Map every reachable subcommand path to the flags it accepts."""
    tree = {prefix: {opt for action in parser._actions for opt in action.option_strings}}
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if not isinstance(choices, dict):
            continue
        for name, sub in choices.items():
            if isinstance(sub, argparse.ArgumentParser):
                tree.update(_command_tree(sub, prefix + (name,)))
    return tree


class TestEveryCommandThisCLIPrintsCanActuallyRun(unittest.TestCase):
    """The generalisation of the `auth login --email` check, one rung up.

    That test asked a narrow question -- does every mention of `hexact auth
    login` carry `--email` -- and the answer stayed yes while a *different*
    printed command rotted: `hexact watch tags list` ended its output with
    "Filter monitors by one:  hexact watch monitors --tag <id>", and `watch
    monitors` is the REST listing, which takes no options at all. Copying it
    got `unrecognized arguments: --tag`. The narrow test could not see it
    because it was only ever looking at one command.

    So the predicate is widened to every command string the source prints:
    the subcommand path must exist, and every flag named must belong to it.
    Values are deliberately not checked -- `<id>` is a placeholder, and
    inventing a type for it would make this test about the test.
    """

    # `hexact` followed by words, then any --flags. Stops at a placeholder, a
    # quote or end of line, which is where prose resumes.
    _MENTION = re.compile(r"hexact ((?:[a-z_]+)(?: [a-z_]+)*(?: --[a-z-]+)*)")

    def _mentions(self):
        root = Path(__file__).resolve().parent.parent
        for path in sorted(root.glob("hexact/*.py")):
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                for found in self._MENTION.finditer(line):
                    yield f"{path.name}:{number}", found.group(1).split()

    def test_the_extractor_finds_the_commands_it_is_supposed_to_grade(self):
        """A regex that matched nothing would make this suite pass vacuously."""
        found = list(self._mentions())
        self.assertGreaterEqual(
            len(found), 8,
            "the mention regex stopped matching; this test is now checking nothing",
        )

    def test_every_printed_command_path_exists_and_accepts_its_flags(self):
        tree = _command_tree(cli.build_parser())
        offenders = []
        for where, words in self._mentions():
            path, flags = [], []
            for word in words:
                (flags if word.startswith("--") else path).append(word)
            # Longest prefix of `path` that is a real command; trailing words
            # are prose that ran on ("hexact watch channels to list them").
            best = ()
            for length in range(len(path), -1, -1):
                if tuple(path[:length]) in tree:
                    best = tuple(path[:length])
                    break
            if not best and path:
                offenders.append(f"{where}: `hexact {' '.join(words)}` -- no such command")
                continue
            unknown = [f for f in flags if f not in tree[best]]
            if unknown:
                offenders.append(
                    f"{where}: `hexact {' '.join(words)}` -- "
                    f"`hexact {' '.join(best)}` does not accept {', '.join(unknown)}")
        self.assertEqual(offenders, [], "\n".join([""] + offenders))


class TestAMessageOnlyClaimsWhatItsCallerCanSupport(unittest.TestCase):
    """Four shared strings that asserted one caller's situation for all of them.

    The project already fixed this once, in the session-token error. Running
    the installed 0.6.0 binary across all 27 read-only commands found four
    more, which is the argument for a test rather than another careful read.
    """

    def test_a_failed_exchange_does_not_invent_the_wrong_field_diagnosis(self):
        """The old text said "the stored value is an access token" directly
        above its own line saying the value is opaque and not a JWT."""
        remedy = auth._exchange_failure_remedy("not-a-jwt-at-all")
        self.assertNotIn("is an access token", remedy)
        self.assertIn("revoked", remedy)

    def test_but_it_still_says_so_when_the_evidence_is_there(self):
        """The wrong-field diagnosis is real and cost a day. Keep it for the
        case that actually shows it."""
        payload = base64.urlsafe_b64encode(
            json.dumps({"iat": 1_700_000_000, "exp": 1_700_003_600}).encode()
        ).decode().rstrip("=")
        access = f"eyJhbGciOiJIUzI1NiJ9.{payload}.sig"
        self.assertEqual(auth.classify_credential(access)["kind"], "access")
        self.assertIn("is an access token", auth._exchange_failure_remedy(access))

    def test_a_stored_token_failing_is_not_reported_as_a_failed_login(self):
        """Thirteen commands reach the gateway without anyone logging in."""
        self.assertTrue(issubclass(auth.SessionError, auth.LoginError))
        err = io.StringIO()
        with mock.patch.object(hexospark, "crm_contacts",
                               side_effect=auth.SessionError("token rejected")):
            with mock.patch.object(auth, "access_token", return_value="t"):
                with contextlib.redirect_stderr(err):
                    code = main(["spark", "contacts"])
        self.assertEqual(code, 1)
        self.assertIn("Session error", err.getvalue())
        self.assertNotIn("Login failed", err.getvalue())

    def test_the_hexometer_key_pointer_names_the_page_that_has_it(self):
        """Hexometer's key is per-property; the shared sentence sent people to
        account settings, which `hexact/hexometer.py` already said was wrong."""
        with self.assertRaises(config.CredentialError) as raised:
            config.resolve_key(config.HEXOMETER)
        message = str(raised.exception)
        self.assertIn("PROPERTY", message)
        self.assertIn("Hexometer", message)   # the product, not the internal id
        self.assertNotIn("API/Webhook", message)

    def test_a_null_gateway_field_admits_it_might_be_access_not_auth(self):
        """`unwrap` is shared by every read across four products, so "your
        token is bad" also greets someone who simply does not own Hexospark."""
        with self.assertRaises(graphql.AuthError) as raised:
            graphql.unwrap({"HexosparkContactOps": None}, "HexosparkContactOps", "x")
        self.assertIn("no access", str(raised.exception))

    def test_the_session_error_lists_every_route_the_resolver_reads(self):
        with self.assertRaises(config.CredentialError) as raised:
            config.resolve_key(config.HEXOWATCH_SESSION)
        message = str(raised.exception)
        for route in ("hexact auth login", "HEXOWATCH_REFRESH_OP_REF",
                      "HEXOWATCH_REFRESH_TOKEN", "credentials.env"):
            self.assertIn(route, message)


class TestUsageIsCheckedBeforeCredentialsAreSpent(unittest.TestCase):
    """Refuse a usage mistake before resolving anything, everywhere.

    `watch delete`, `watch alerts delete` and `watch tags set` already did.
    `watch unmute` and `watch changes` did not, so a missing flag or a typo
    surfaced as a credential error about something else -- and against a
    working credential, `unmute` paid a round trip to say no.
    """

    _TRAP = "credentials must not be resolved before the usage check"

    def test_unmute_without_a_channel_refuses_before_minting_a_token(self):
        args = cli.build_parser().parse_args(["watch", "unmute", "12"])
        with mock.patch.object(auth, "access_token",
                               side_effect=AssertionError(self._TRAP)):
            with self.assertRaises(ValueError) as raised:
                cli_hexowatch.cmd_watch_mute(args)
        self.assertIn("--channel", str(raised.exception))

    def test_a_bad_since_is_reported_as_a_bad_since_not_a_missing_key(self):
        args = cli.build_parser().parse_args(["watch", "changes", "--since", "notatime"])
        with mock.patch.object(cli_watch_rest, "resolve_key",
                               side_effect=AssertionError(self._TRAP)):
            with self.assertRaises(ValueError) as raised:
                cli_watch_rest.cmd_changes(args)
        self.assertIn("Invalid duration", str(raised.exception))

    def test_that_typo_exits_2_rather_than_reading_as_an_api_failure(self):
        """`argparse.ArgumentTypeError` inherits from Exception, not
        ValueError, so it fell past the usage branch into the last-resort
        handler: `Unexpected ArgumentTypeError`, exit 1."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["watch", "changes", "--since", "notatime"])
        self.assertEqual(code, 2, err.getvalue())
        self.assertIn("Usage error", err.getvalue())
        self.assertNotIn("Unexpected", err.getvalue())


class TestTheTwoSinceFlagsCannotBeSilentlyConfused(unittest.TestCase):
    """`m` is months, and `30m` returned a 900-day window with no complaint.

    The old error text read "Use forms like 24h, 7d, 2w, 1m" -- `m` in a list
    that opens with hours, where it reads as minutes. Nothing errored; the
    caller just summarised the wrong period.
    """

    def test_m_is_months_and_the_help_says_so_in_the_same_breath(self):
        now = datetime.now(timezone.utc)
        self.assertGreater((now - parse_since("3m")).days, 85)
        with self.assertRaises(ValueError) as raised:
            parse_since("bogus")
        message = str(raised.exception)
        self.assertIn("MONTHS", message)
        self.assertIn("Minutes are not supported", message)

    def test_the_date_flags_refuse_a_duration_rather_than_guessing(self):
        with self.assertRaises(ValueError) as raised:
            reject_duration_for_a_date_flag("7d")
        self.assertIn("watch changes", str(raised.exception))

    def test_but_a_date_passes_straight_through_unvalidated(self):
        """The gateway's accepted formats were never measured, so refusing
        something it would have taken is the worse error."""
        self.assertEqual(reject_duration_for_a_date_flag("2026-08-01"), "2026-08-01")
        self.assertIsNone(reject_duration_for_a_date_flag(None))


class TestAuthStatusSeparatesNoAnswerFromABadAnswer(unittest.TestCase):
    """Four verdicts, three exit codes -- and failures on stderr like everything
    else in this CLI.

    `auth.status()` goes to trouble to keep "the gateway never answered" apart
    from "the gateway refused", and the exit code threw it away by returning 1
    for both. A network outage was then indistinguishable from a dead
    credential to anything scripting it, which is how a working token gets
    rotated during an outage.
    """

    def _status(self, verdict):
        args = cli.build_parser().parse_args(["auth", "status"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(auth, "status", return_value=(verdict, "detail")):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli_auth.cmd_auth_status(args)
        return code, out.getvalue(), err.getvalue()

    def test_each_verdict_gets_its_own_exit_code(self):
        self.assertEqual(self._status("authenticated")[0], 0)
        self.assertEqual(self._status("rejected")[0], 1)
        self.assertEqual(self._status("missing")[0], 2)
        self.assertEqual(self._status("unknown")[0], 2)

    def test_only_the_pass_goes_to_stdout(self):
        code, out, err = self._status("authenticated")
        self.assertIn("authenticated", out)
        self.assertEqual(err, "")
        for bad in ("rejected", "missing", "unknown"):
            code, out, err = self._status(bad)
            self.assertIn(bad, err, f"{bad} should report on stderr")
            self.assertEqual(out, "", f"{bad} should not report on stdout")

    def test_doctor_looks_at_the_gateway_too(self):
        """Three REST keys printed [OK] [OK] [OK] and exited 0 while every
        GraphQL command failed on a credential nothing had examined."""
        args = cli.build_parser().parse_args(["doctor"])
        out = io.StringIO()
        with TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {"HEXACT_HOME": home,
                                              "HEXOWATCH_API_KEY": "k" * 64}):
                with mock.patch.object(hexowatch, "list_monitored_urls", return_value=[]):
                    with mock.patch.object(auth, "status",
                                           return_value=("rejected", "token refused")):
                        with contextlib.redirect_stdout(out):
                            code = cli.cmd_doctor(args)
        self.assertIn("gateway", out.getvalue())
        self.assertEqual(code, 1, out.getvalue())


class TestDoctorDoesNotPassAfterCheckingNothing(unittest.TestCase):
    """The quickstart's own front door was a green light over an empty set.

    `README.md` put `hexact doctor` in the Install block, twenty-two lines above
    the credentials table, so the first two commands a new user ran were
    `pipx install` and a `doctor` that had nothing to examine. It printed three
    `[SKIP]` lines and exited 0 -- indistinguishable, to a reader and to a
    script, from three products authenticating.

    Same shape as `tools/validate_documents.py` before it grew an exit 2, and
    same rule: a run that reached no verdict must not be phrased as a pass.
    """

    def _run(self, env: dict[str, str]):
        args = cli.build_parser().parse_args(["doctor"])
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.cmd_doctor(args)
        return code, out.getvalue(), err.getvalue()

    def test_no_credentials_anywhere_is_exit_2_not_exit_0(self):
        with TemporaryDirectory() as home:  # no credentials.env inside it
            code, out, err = self._run({"HEXACT_HOME": home})
        self.assertEqual(code, 2, f"stdout={out!r} stderr={err!r}")
        self.assertIn("SKIP", out)
        self.assertIn("No verdict", err)
        self.assertIn("not a pass", err)

    def test_one_product_authenticating_is_still_exit_0(self):
        """The refusal must not swallow the case it exists to protect."""
        with TemporaryDirectory() as home:
            with mock.patch.object(hexowatch, "list_monitored_urls", return_value=[]):
                code, out, err = self._run(
                    {"HEXACT_HOME": home, "HEXOWATCH_API_KEY": "k" * 64})
        self.assertEqual(code, 0, f"stdout={out!r} stderr={err!r}")
        self.assertIn("OK", out)
        self.assertNotIn("No verdict", err)

    def test_a_rejected_credential_is_exit_1_and_says_nothing_about_verdicts(self):
        """`1` is a finding; `2` is the absence of one. Never collapse them."""
        with TemporaryDirectory() as home:
            with mock.patch.object(
                hexowatch, "list_monitored_urls",
                side_effect=HexactAPIError("invalid api key"),
            ):
                code, out, err = self._run(
                    {"HEXACT_HOME": home, "HEXOWATCH_API_KEY": "k" * 64})
        self.assertEqual(code, 1, f"stdout={out!r} stderr={err!r}")
        self.assertIn("FAIL", out)
        self.assertNotIn("No verdict", err)


class TestAPasswordPromptWithNoTerminalIsRefused(unittest.TestCase):
    """`getpass` answers "no terminal" by echoing the password instead.

    Measured 2026-08-14 against the installed 0.6.0 binary, running the exact
    remedy string the CLI prints::

        $ hexact auth login --email x@example.com < /dev/null
        GetPassWarning: Can not control echo on the terminal.
        Warning: Password input may be echoed.
        Hexowatch password: Unexpected EOFError:

    Two defects in three lines. `getpass.getpass` cannot open ``/dev/tty`` in a
    pipeline, a CI job or an agent tool call, so it falls back to a **plain,
    echoing read of stdin** -- which writes the account password into whatever
    log is capturing that stream. It then raises ``EOFError`` on the empty pipe,
    and the run ends through the top-level last-line-of-defence handler, whose
    whole purpose is unforeseen types. A foreseeable condition arriving there
    reads as ``Unexpected EOFError:`` with no diagnosis and no remedy.

    The safety net was working. What was missing is that this case is not
    unexpected at all, and the right answer is to refuse before prompting.
    """

    def test_prompt_password_never_reaches_getpass_without_a_terminal(self):
        """Assert the absence with a trap, not with a return value.

        A stub returning a plausible password would hide the very thing under
        test: that `getpass` is not entered at all. Exploding on the call turns
        the ordering bug into a failure at the moment it happens.
        """
        with mock.patch.object(auth, "_terminal_available", return_value=False):
            with mock.patch.object(
                auth.getpass, "getpass",
                side_effect=AssertionError(
                    "getpass must not run when there is no terminal: its "
                    "fallback echoes the password"),
            ):
                with self.assertRaises(auth.LoginError) as raised:
                    auth.prompt_password()
        message = str(raised.exception)
        self.assertIn("nothing was sent", message)
        self.assertIn("--password-stdin", message)

    def test_the_refusal_names_only_routes_that_exist(self):
        """A remedy naming a variable nobody reads is the defect one rung down
        from a remedy naming a command that cannot run."""
        with mock.patch.object(auth, "_terminal_available", return_value=False):
            with self.assertRaises(auth.LoginError) as raised:
                auth.prompt_password()
        message = str(raised.exception)
        readable = set(config._ENV_VARS.values()) | set(config._OP_REF_VARS.values())
        for name in ("HEXOWATCH_REFRESH_TOKEN", "HEXOWATCH_REFRESH_OP_REF"):
            self.assertIn(name, message)
            self.assertIn(
                name, readable,
                f"{name} is advertised in the refusal but the resolver never reads it",
            )

    def test_a_terminal_still_gets_the_normal_prompt(self):
        """The refusal must not swallow the case it exists to protect."""
        with mock.patch.object(auth, "_terminal_available", return_value=True):
            with mock.patch.object(
                auth.getpass, "getpass", return_value="typed-at-a-tty"
            ) as prompt:
                self.assertEqual(auth.prompt_password(), "typed-at-a-tty")
        self.assertEqual(prompt.call_count, 1)

    def test_password_stdin_reads_one_line_and_keeps_trailing_spaces(self):
        """`.strip()` here would silently mangle a legitimate password."""
        with mock.patch.object(auth.sys, "stdin", io.StringIO("s3cret \n")):
            self.assertEqual(auth.read_password_from_stdin(), "s3cret ")

    def test_password_stdin_refuses_a_terminal_rather_than_echoing_it(self):
        """The mirror of the bug above: no pipe attached means `readline` sits
        there echoing every character typed."""
        tty = io.StringIO("s3cret\n")
        tty.isatty = lambda: True  # type: ignore[method-assign]
        with mock.patch.object(auth.sys, "stdin", tty):
            with self.assertRaises(auth.LoginError) as raised:
                auth.read_password_from_stdin()
        self.assertIn("nothing was sent", str(raised.exception).lower())

    def test_password_stdin_refuses_an_empty_pipe_instead_of_sending_blank(self):
        with mock.patch.object(auth.sys, "stdin", io.StringIO("")):
            with self.assertRaises(auth.LoginError) as raised:
                auth.read_password_from_stdin()
        self.assertIn("nothing was sent", str(raised.exception))

    def test_the_real_entry_point_refuses_a_pipe_without_echoing(self):
        """The unit tests above patch the detector; this one does not.

        Every mock in this class agrees to hide the thing that actually broke --
        a real process with no controlling terminal. One pass through the real
        entry point, with stdin genuinely closed, is what saw it.
        """
        env = {k: v for k, v in os.environ.items() if k not in _MANAGED_VARS}
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
        completed = subprocess.run(
            [sys.executable, "-m", "hexact", "auth", "login",
             "--email", "nobody@example.invalid"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            env=env, cwd="/", timeout=60,
        )
        combined = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 1, combined)
        self.assertNotIn("may be echoed", combined)
        self.assertNotIn("EOFError", combined)
        self.assertNotIn("Traceback", combined)
        self.assertIn("--password-stdin", combined)


class TestUnauthenticatedReadIsNotAnEmptyAccount(unittest.TestCase):
    """Three commands reported an expired session as an account with nothing in it.

    Measured 2026-08-14 with a deliberately invalid token, against an account
    that REST simultaneously reported as 48 monitors and 3 notification
    channels. The gateway is honest -- every member of the container comes back
    ``null``. The empty answer was manufactured locally, by an ``or []`` in each
    renderer: the idiom this project's style rules reserve for optional addends
    whose default is genuinely the neutral element, used here on values a reader
    takes as fact.

    ``unwrap`` cannot catch this. It guards the two levels GraphQL wraps every
    answer in, and both of those are non-null; the nulls are one level further
    down, inside the payload.
    """

    # Verbatim from the probe against the live gateway. Do not "tidy" these
    # into empty lists -- an empty list is the shape the bug produced, not the
    # shape the server sends.
    LIST = {"data": {"Watch": {"getUserWatchProperties": {
        "totalCount": None, "watchProperties": None}}}}
    CHANNELS = {"data": {"WatchIntegration": {"getUserIntegrations": {
        "integrations": None}}}}
    SETTINGS = {"data": {"UserWatchSettings": {"get": {
        "emails": None, "webhooks": None}}}}

    # The same reads on an account that genuinely has nothing. These must keep
    # working: a guard that cannot tell "unreadable" from "empty" has only moved
    # the lie, not removed it.
    EMPTY_LIST = {"data": {"Watch": {"getUserWatchProperties": {
        "totalCount": 0, "watchProperties": []}}}}
    EMPTY_CHANNELS = {"data": {"WatchIntegration": {"getUserIntegrations": {
        "integrations": []}}}}
    EMPTY_SETTINGS = {"data": {"UserWatchSettings": {"get": {
        "emails": [], "webhooks": []}}}}

    def _run(self, argv, payload):
        out, err = io.StringIO(), io.StringIO()
        # Patched on the module that defines it, so the patch survives the
        # command moving between cli_* modules.
        with mock.patch.object(auth, "access_token", return_value="live-looking"):
            with _respond_with(payload):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_watch_list_refuses_instead_of_reporting_zero_monitors(self):
        code, out, err = self._run(["watch", "list"], self.LIST)
        self.assertNotEqual(code, 0, out + err)
        self.assertNotIn("0 of", out)
        self.assertNotIn("monitor(s)", out)
        self.assertIn("empty", (out + err).lower())

    def test_watch_channels_refuses_instead_of_reporting_no_channels(self):
        code, out, err = self._run(["watch", "channels"], self.CHANNELS)
        self.assertNotEqual(code, 0, out + err)
        self.assertNotIn("No notification channels registered", out)

    def test_watch_settings_refuses_instead_of_reporting_zero_recipients(self):
        code, out, err = self._run(["watch", "settings"], self.SETTINGS)
        self.assertNotEqual(code, 0, out + err)
        self.assertNotIn("(0)", out)

    def test_json_output_carries_no_fabricated_empty_collection(self):
        """``--json`` is what a script reads, and it lied in the same way.

        The renderer was not the only place the empty list was invented: the
        payload handed to ``emit`` carried it too, so a consumer piping
        ``--json`` saw ``"watchProperties": []`` for an account with 48.
        """
        code, out, _ = self._run(["--json", "watch", "list"], self.LIST)
        self.assertNotEqual(code, 0)
        self.assertNotIn("[]", out)

    def test_a_genuinely_empty_account_still_renders(self):
        for argv, payload in (
            (["watch", "list"], self.EMPTY_LIST),
            (["watch", "channels"], self.EMPTY_CHANNELS),
            (["watch", "settings"], self.EMPTY_SETTINGS),
        ):
            with self.subTest(argv=argv):
                code, out, err = self._run(argv, payload)
                self.assertEqual(code, 0, out + err)

    def test_a_partially_null_payload_reports_that_part_as_unreadable(self):
        """Not every null is an auth failure, and not every null is a zero.

        A container with one real member is a live read, so it must not be
        refused -- but the member that came back null still has no count, and
        printing ``0`` for it would be the original bug at a smaller scale.
        """
        payload = {"data": {"UserWatchSettings": {"get": {
            "emails": [{"email": "a@b.test", "enabled": True, "verified": True}],
            "webhooks": None}}}}
        code, out, err = self._run(["watch", "settings"], payload)
        self.assertEqual(code, 0, out + err)
        self.assertIn("a@b.test", out)
        self.assertNotIn("Account webhooks (0)", out)
        self.assertIn("unreadable", out.lower())
