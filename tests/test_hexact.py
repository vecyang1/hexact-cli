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
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

_MANAGED_VARS = (
    "HEXOWATCH_API_KEY", "HEXOMATIC_API_KEY",
    "HEXOWATCH_OP_REF", "HEXOMATIC_OP_REF",
    "HEXACT_OP_CMD", "HEXACT_HOME",
)
for _name in _MANAGED_VARS:
    os.environ.pop(_name, None)

from hexact import cli, config, hexomatic, hexowatch  # noqa: E402
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
