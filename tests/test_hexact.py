"""Tests for hexact-cli.

**Hermetic by construction.** Every variable this package reads is scrubbed at
import, before any test runs. Without that, a developer who has exported
``HEXOWATCH_API_KEY`` would see the credential tests pass for the wrong
reason -- the resolver would find a real key and never exercise the branch
under test. Individual tests opt back in with ``mock.patch.dict``.
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import io
import json
import os
import stat
import subprocess
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

_MANAGED_VARS = (
    "HEXOWATCH_API_KEY", "HEXOMATIC_API_KEY",
    "HEXOWATCH_OP_REF", "HEXOMATIC_OP_REF",
    "HEXOWATCH_REFRESH_TOKEN", "HEXOWATCH_REFRESH_OP_REF",
    "HEXACT_OP_CMD", "HEXACT_HOME",
)
for _name in _MANAGED_VARS:
    os.environ.pop(_name, None)

from hexact import auth, cli, config, graphql, hexomatic, hexowatch  # noqa: E402
from hexact.cli import (  # noqa: E402
    _is_paused, _normalise_address, _parse_timestamp, _rows, _state_label,
    main, parse_since, resolve_tool_from_payload,
)
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
        with mock.patch.object(cli.hexowatch, "list_monitored_urls", return_value=monitors), \
             mock.patch.object(cli.hexowatch, "monitoring_logs",
                               side_effect=lambda key, mid, **kw: {
                                   "error": False, "tool": tools[int(mid)],
                                   "monitoring_results": []}), \
             mock.patch.object(cli, "resolve_key", return_value="k"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.cmd_duplicates(argparse.Namespace(json=True))
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
        with mock.patch.object(cli.hexowatch, "list_monitored_urls", return_value=monitors), \
             mock.patch.object(cli.hexowatch, "monitoring_logs",
                               return_value={"error": False, "monitoring_results": []}), \
             mock.patch.object(cli, "resolve_key", return_value="k"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.cmd_duplicates(argparse.Namespace(json=True))
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

    def test_the_four_operations_we_rely_on_are_listed(self):
        # Pins the vendor's undocumented, unversioned names. A silent rename
        # should fail here rather than quietly return nothing at runtime.
        self.assertEqual(graphql.MUTATION_ALLOWLIST, frozenset({
            "WatchOps.deleteWatchProperty",
            "WatchOps.deleteWatchProperties",
            "WatchOps.updateWatchProperty",
            "WatchOps.updateWatchProperties",
        }))

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
