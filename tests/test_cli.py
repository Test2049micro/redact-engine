"""CLI behaviour, including the failure modes that matter most: what refuses to
run, and what gets written where."""

from __future__ import annotations


import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from redact_engine import cli

KEY = b"k" * 32

EVENTS = "\n".join([
    json.dumps({"timestamp": "2026-10-17T09:00:00", "app": "com.example.mail",
                "text": "reply to li@example.com about the invoice"}),
    json.dumps({"timestamp": "2026-10-17T09:05:00", "app": "com.example.chat",
                "text": "call 13812345678", "raw_chat_history": "everything unsent"}),
    "{ this line is not json and must be skipped",
    json.dumps({"timestamp": "2026-10-17T09:10:00", "app": "com.example.ide",
                "text": "refactored the parser, nothing personal"}),
])


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.source = self.root / "events.jsonl"
        self.source.write_text(EVENTS, encoding="utf-8")
        self.key = self.root / "alias.key"
        self.key.write_bytes(KEY)
        os.chmod(self.key, 0o600)
        self.out = self.root / "projection"

    def run_cli(self, argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(stdin)), redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()


class ProjectTest(Sandbox):
    def project(self, extra=()):
        return self.run_cli(["project", "--key", str(self.key), "--source", str(self.source),
                             "--out", str(self.out), "--verify", *extra])

    def test_happy_path_writes_and_verifies(self):
        code, out, err = self.project()
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["events"], 3)
        self.assertEqual(payload["aliasing"], "stable")
        self.assertGreaterEqual(payload["redactions"].get("email", 0), 1)

    def test_no_secret_survives_in_output(self):
        self.project()
        body = (self.out / "safe" / "events.jsonl").read_text(encoding="utf-8")
        for secret in ("li@example.com", "13812345678", "everything unsent"):
            self.assertNotIn(secret, body)
        self.assertIn("[email-", body)

    def test_unexpected_field_never_reaches_disk(self):
        self.project()
        body = (self.out / "safe" / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("raw_chat_history", body)

    def test_output_is_owner_only(self):
        self.project()
        self.assertEqual((self.out / "safe").stat().st_mode & 0o777, 0o700)
        for path in (self.out / "safe").iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, str(path))

    def test_summary_contains_no_text(self):
        self.project()
        summary = (self.out / "safe" / "summary.json").read_text(encoding="utf-8")
        self.assertNotIn("invoice", summary)
        self.assertNotIn("li@example.com", summary)
        self.assertFalse(json.loads(summary)["coverage_assessed"])

    def test_unstable_flag_breaks_correlation_between_runs(self):
        self.project()
        first = (self.out / "safe" / "events.jsonl").read_text(encoding="utf-8")
        second_out = self.root / "projection2"
        self.run_cli(["project", "--key", str(self.key), "--source", str(self.source),
                      "--out", str(second_out), "--unstable"])
        second = (second_out / "safe" / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotEqual(first, second)
        self.assertNotIn("li@example.com", second)

    def test_identity_map_is_written_and_gitignored(self):
        target = self.out / "consented" / "identity-map.json"
        code, _, err = self.project(["--identity-map", str(target)])
        self.assertEqual(code, 0, err)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        ignore = (target.parent / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("*", ignore.split())
        rows = json.loads(target.read_text(encoding="utf-8"))
        self.assertTrue(any(row["value"] == "li@example.com" for row in rows))

    def test_existing_output_file_is_replaced_not_appended(self):
        self.project()
        before = (self.out / "safe" / "events.jsonl").read_text(encoding="utf-8").count("\n")
        self.project()
        after = (self.out / "safe" / "events.jsonl").read_text(encoding="utf-8").count("\n")
        self.assertEqual(before, after, "a rerun must not double-count the same window")


class RefusalTest(Sandbox):
    def test_symlinked_source_is_refused(self):
        real = self.root / "real.jsonl"
        real.write_text(EVENTS, encoding="utf-8")
        link = self.root / "link.jsonl"
        link.symlink_to(real)
        code, _, err = self.run_cli(["project", "--key", str(self.key), "--source", str(link),
                                     "--out", str(self.out)])
        self.assertEqual(code, 4)
        self.assertIn("symlink", err)

    def test_symlinked_key_is_refused(self):
        real = self.root / "real.key"
        real.write_bytes(KEY)
        os.chmod(real, 0o600)
        link = self.root / "link.key"
        link.symlink_to(real)
        code, _, err = self.run_cli(["project", "--key", str(link), "--source", str(self.source),
                                     "--out", str(self.out)])
        self.assertEqual(code, 4)
        self.assertIn("symlink", err)

    def test_symlinked_output_directory_is_refused(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (self.root / "linkout").symlink_to(elsewhere)
        code, _, err = self.run_cli(["project", "--key", str(self.key), "--source", str(self.source),
                                     "--out", str(self.root / "linkout")])
        self.assertEqual(code, 4)
        self.assertIn("symlink", err)

    def test_no_neither_source_nor_root_is_usage_error(self):
        code, _, err = self.run_cli(["project", "--key", str(self.key), "--out", str(self.out)])
        self.assertEqual(code, 6)
        self.assertIn("--source", err)

    def test_missing_key_parent_is_created_owner_only(self):
        nested = self.root / "keys" / "alias.key"
        code, _, err = self.run_cli(["init-key", "--key", str(nested)])
        self.assertEqual(code, 0, err)
        self.assertEqual(nested.stat().st_mode & 0o777, 0o600)
        self.assertEqual(nested.parent.stat().st_mode & 0o777, 0o700)


class CoverageGapTest(Sandbox):
    def test_empty_root_reports_no_records_not_no_activity(self):
        empty = self.root / "rec"
        empty.mkdir()
        code, out, _ = self.run_cli(["project", "--key", str(self.key), "--root", str(empty),
                                     "--out", str(self.out)])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["status"], "no-records")
        self.assertFalse(payload["coverage_assessed"])

    def test_segment_discovery_finds_nested_event_files(self):
        segment = self.root / "rec" / "2026-10-17T09"
        segment.mkdir(parents=True)
        (segment / "events.jsonl").write_text(EVENTS, encoding="utf-8")
        code, out, err = self.run_cli(["project", "--key", str(self.key), "--root", str(self.root / "rec"),
                                        "--out", str(self.out), "--verify"])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["events"], 3)


class MappingTest(Sandbox):
    def test_custom_mapping_reads_nested_fields(self):
        source = self.root / "ax.jsonl"
        source.write_text(json.dumps({
            "ts": 1_800_000_000,
            "app": {"bundleIdentifier": "com.example.chat"},
            "payload": {"lines": ["message to li@example.com", "and 13812345678"]},
        }) + "\n", encoding="utf-8")
        mapping = self.root / "map.json"
        mapping.write_text(json.dumps({"timestamp": "ts", "app": "app.bundleIdentifier",
                                       "text": "payload.lines"}), encoding="utf-8")
        code, out, err = self.run_cli(["project", "--key", str(self.key), "--source", str(source),
                                       "--mapping", str(mapping), "--out", str(self.out), "--verify"])
        self.assertEqual(code, 0, err)
        body = (self.out / "safe" / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("li@example.com", body)
        self.assertIn("com.example.chat", body)

    def test_mapping_without_text_field_is_rejected(self):
        mapping = self.root / "bad.json"
        mapping.write_text(json.dumps({"app": "a"}), encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.run_cli(["project", "--key", str(self.key), "--source", str(self.source),
                          "--mapping", str(mapping), "--out", str(self.out)])


class RedactTextTest(Sandbox):
    def test_stdin_to_stdout(self):
        code, out, _ = self.run_cli(["redact-text", "--key", str(self.key)], stdin="mail li@example.com ok")
        self.assertEqual(code, 0)
        self.assertIn("[email-", out)
        self.assertNotIn("li@example.com", out)

    def test_stats_reported_on_stderr(self):
        code, _, err = self.run_cli(["redact-text", "--key", str(self.key), "--stats"], stdin="1 13812345678")
        self.assertEqual(code, 0)
        self.assertIn("phone_cn", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
