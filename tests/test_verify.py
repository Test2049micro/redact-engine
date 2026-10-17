"""Regression tests for the false-guarantee bugs found in pre-publication review.

Every case here reproduces a claim the README made that the code did not keep.
They are deliberately written as *adversarial* cases (rule set narrowed, nested
payloads, bare filenames, symlink swap), because the original suite only tested
the honest path -- which is why a `--verify` that passes while secrets are on disk
survived 43 green tests.
"""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from redact_engine.alias import create_key, load_key, InsecureKeyFile
from redact_engine.projection import Redactor, _flatten, leaked_kinds

KEY = b"v" * 32


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.key = self.dir / "alias.key"
        self.key.write_bytes(KEY)
        os.chmod(self.key, 0o600)
        self.source = self.dir / "events.jsonl"
        self.source.write_text("\n".join([
            json.dumps({"timestamp": "t1", "app": "com.example.mail",
                        "text": "reply to li@example.com, call 13812345678"}),
            json.dumps({"timestamp": "t2", "app": "com.example.chat",
                        "text": "验证码 830291 and token sk-abcdef1234567890xyz"}),
        ]) + "\n", encoding="utf-8")
        self.out = self.dir / "out"

    def run_cli(self, argv):
        from redact_engine import cli
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest import mock
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("[]")), redirect_stdout(out), redirect_stderr(err):
            return cli.main(argv), out.getvalue(), err.getvalue()

    def project(self, extra=()):
        return self.run_cli(["project", "--key", str(self.key), "--source", str(self.source),
                             "--out", str(self.out), "--verify", *extra])

    def test_full_rules_pass(self):
        code, _, err = self.project()
        self.assertEqual(code, 0, err)
        self.assertTrue((self.out / "safe" / "events.jsonl").exists())

    def test_narrowed_rules_fail_instead_of_passing(self):
        # the shipped bug: verify compared only what the active rules had matched, so
        # `--kind url` left every email/phone/token on disk and still exited 0
        code, _, err = self.project(["--kind", "url"])
        self.assertEqual(code, 5, err)
        self.assertIn("LEAK CHECK FAILED", err)
        self.assertIn("email", err)
        self.assertFalse((self.out / "safe" / "events.jsonl").exists(),
                         "an unsafe projection must not be left behind")
        self.assertFalse((self.out / "safe" / "summary.json").exists())

    def test_failure_message_never_quotes_the_secret(self):
        _, _, err = self.project(["--kind", "url"])
        for secret in ("li@example.com", "13812345678", "830291", "sk-abcdef1234567890xyz"):
            self.assertNotIn(secret, err, "the error channel is not a safe place for raw values")

    def test_identity_map_needs_a_directory(self):
        # a bare filename resolves to the CWD: the command would have created or
        # tightened that directory and dropped a .gitignore into it
        sandbox = self.dir / "standing-here"
        sandbox.mkdir()
        cwd = os.getcwd()
        try:
            os.chdir(sandbox)
            code, _, err = self.project(["--identity-map", "identity-map.json"])
        finally:
            os.chdir(cwd)
        self.assertEqual(code, 6, err)
        self.assertIn("directory component", err)
        self.assertEqual(list(sandbox.iterdir()), [], "nothing may be created in the caller's CWD")

    def test_summary_does_not_publish_absolute_paths(self):
        self.project()
        summary = (self.out / "safe" / "summary.json").read_text(encoding="utf-8")
        payload = json.loads(summary)
        self.assertEqual(payload["sources"], ["events.jsonl"])
        self.assertNotIn(str(self.dir), summary)

    def test_existing_output_directory_is_not_repermissioned(self):
        target = self.dir / "existing"
        target.mkdir(mode=0o755)
        self.project(["--out", str(target)])
        self.assertEqual(target.stat().st_mode & 0o777, 0o755,
                         "the tool must not silently change modes on a directory it did not create")

    def test_nested_structures_in_whitelisted_fields_are_redacted(self):
        # the shipped bug: a dict/list under a whitelisted name was serialised as-is
        from redact_engine.projection import DEFAULT_FIELDS
        redactor = Redactor(KEY)
        projected = redactor.project({"timestamp": {"note": "home: li@example.com"},
                                      "app": ["com.example.a", "call 13812345678"],
                                      "text": "ok"}, DEFAULT_FIELDS)
        body = json.dumps(projected)
        self.assertNotIn("li@example.com", body)
        self.assertNotIn("13812345678", body)
        self.assertIn("[email-", body)

    def test_flatten_is_the_fallback_for_unknown_shapes(self):
        # nested shapes become one string so the rules can see inside them; the
        # exact rendering matters less than the fact that it is redactable at all
        self.assertIn("abc", _flatten({"text": "abc"}))
        self.assertEqual(_flatten(["a", "b"]), "a\nb")
        self.assertEqual(_flatten(7), "7")
        self.assertEqual(_flatten("x" * 5000)[:10], "xxxxxxxxxx")


class SymlinkSafetyTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_key_read_refuses_a_symlink(self):
        real = self.dir / "real.key"
        real.write_bytes(KEY)
        os.chmod(real, 0o600)
        link = self.dir / "swap.key"
        link.symlink_to(real)
        with self.assertRaises(InsecureKeyFile):
            load_key(link)
        self.assertTrue(real.exists())

    def test_map_write_refuses_a_symlink_target(self):
        victim = self.dir / "victim.json"
        victim.write_text("do-not-overwrite", encoding="utf-8")
        link = self.dir / "map.json"
        link.symlink_to(victim)
        with self.assertRaises((ValueError, OSError)):
            Redactor(KEY, persist_map=link)
        self.assertEqual(victim.read_text(encoding="utf-8"), "do-not-overwrite")

    def test_map_append_refuses_a_symlink_even_when_it_already_loaded(self):
        # the constructor check is not enough: _append_map reopens the path on every
        # new subject, so the O_NOFOLLOW flag is what stops a later swap from
        # overwriting an unrelated file the user can write
        victim = self.dir / "victim.txt"
        victim.write_text("keep", encoding="utf-8")
        map_path = self.dir / "map.json"
        map_path.write_text("[]", encoding="utf-8")
        os.chmod(map_path, 0o600)
        redactor = Redactor(KEY, persist_map=map_path)
        map_path.unlink()
        map_path.symlink_to(victim)
        with self.assertRaises((OSError, ValueError)):
            redactor._append_map(("email", "a@b.co"), "[email-1]")
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep")


class LeakedKindsTest(unittest.TestCase):
    def test_reports_kinds_and_counts_only(self):
        text = "li@example.com and 13812345678"
        auditor = Redactor(KEY, stable=False)
        auditor.redact(text)
        hits = auditor.all_hits
        kinds = leaked_kinds(text, hits)
        self.assertEqual(kinds, {"email": 1, "phone_cn": 1})
        self.assertNotIn("li@example.com", json.dumps(kinds))
        self.assertNotIn("13812345678", json.dumps(kinds))
        # and the honest case: redacted output reports nothing leaked
        self.assertEqual(leaked_kinds(auditor.redact(text).text, hits), {})

    def test_short_values_are_not_claimed_as_leaks(self):
        # a 2-digit match would flag half the prose on the page; the floor keeps the
        # signal honest without pretending short values cannot ever matter
        from redact_engine.projection import Hit
        self.assertEqual(leaked_kinds("code 12 issued", [Hit(kind="otp", value="12", alias="[otp-x]")]), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
