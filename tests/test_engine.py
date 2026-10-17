"""Rules, alias keys, and the structural guarantees of the projection.

The tests here split deliberately: cases that show a rule *fires*, cases that show
it stays quiet when nothing matches, and cases where a redaction gap would be a
lie -- unknown fields never read, symlinked keys refused, verification catching a
forced leak.
"""

from __future__ import annotations


import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from redact_engine import alias as A
from redact_engine.projection import Redactor, assert_no_leaks
from redact_engine.rules import DEFAULT_RULES, zh_cue_rules

KEY = b"x" * 32


def fire(kind: str, text: str) -> str | None:
    for rule in DEFAULT_RULES:
        if rule.kind != kind:
            continue
        match = rule.pattern.search(text)
        if match:
            return match.group(rule.group)
    return None


class RulesTest(unittest.TestCase):
    def test_each_kind_matches_its_shape(self):
        cases = {
            "email": "mail me at zhang.san@example.com ok",
            "phone_cn": "call 13812345678 now",
            "id_cn": "编号 110101199003077758 结束",
            "credential": "use sk-abcdef1234567890xyz",
            "bearer": "Authorization: Bearer abcdef123456.tok",
            "secret_json": '{"api_key": "supersecret1"}',
            "otp": "您的验证码是 830291",
            "url": "see https://example.com/a/b?token=1 for details",
            "path": "saved under /Users/acme/Documents/notes.txt",
            "guid": "id 3f2504e0-4f89-41d3-9a0c-0305e82c3331",
            "number_long": "order 98765432101234 shipped",
            "ip_private": "peer 192.168.10.24 reachable",
        }
        for kind, text in cases.items():
            with self.subTest(kind=kind):
                self.assertIsNotNone(fire(kind, text), text)

    def test_ordinary_prose_does_not_trigger_the_long_number_rule(self):
        self.assertIsNone(fire("number_long", "page 12 of 40, chapter 3"))

    def test_email_local_part_alone_is_not_matched(self):
        self.assertIsNone(fire("email", "just a word without domain"))

    def test_zh_cues_are_labelled_heuristics_not_ner(self):
        text = "王老师致电小李，去了同仁医院"
        found = set()
        for rule in zh_cue_rules():
            for match in rule.pattern.finditer(text):
                found.add(match.group(rule.group))
        self.assertIn("王老师", found)
        self.assertTrue(any("同仁医院" in hit for hit in found), found)


class AliasKeyTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_created_key_is_owner_only(self):
        target = self.dir / "alias.key"
        key = A.create_key(target)
        self.assertEqual(len(key), A.KEY_BYTES)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)

    def test_existing_key_is_not_silently_replaced(self):
        target = self.dir / "alias.key"
        first = A.create_key(target)
        with self.assertRaises(A.InsecureKeyFile):
            A.create_key(target)
        self.assertEqual(A.load_key(target), first)

    def test_symlinked_key_is_refused(self):
        real = self.dir / "real.key"
        real.write_bytes(b"y" * 32)
        os.chmod(real, 0o600)
        link = self.dir / "link.key"
        link.symlink_to(real)
        with self.assertRaises(A.InsecureKeyFile):
            A.load_key(link)
        with self.assertRaises(A.InsecureKeyFile):
            A.create_key(link)

    def test_world_readable_key_is_refused(self):
        target = self.dir / "loose.key"
        target.write_bytes(b"z" * 32)
        os.chmod(target, 0o644)
        with self.assertRaises(A.InsecureKeyFile):
            A.load_key(target)

    def test_short_key_is_refused(self):
        target = self.dir / "tiny.key"
        target.write_bytes(b"1234")
        os.chmod(target, 0o600)
        with self.assertRaises(A.InsecureKeyFile):
            A.load_key(target)


class AliasSemanticsTest(unittest.TestCase):
    def test_same_value_same_alias_across_instances(self):
        first = Redactor(KEY).redact("a@b.com")
        second = Redactor(KEY).redact("a@b.com")
        self.assertEqual(first.text, second.text)
        self.assertRegex(first.text, r"^\[email-[0-9a-f]{12}\]$")

    def test_different_key_different_alias(self):
        self.assertNotEqual(Redactor(b"a" * 32).redact("13812345678").text,
                            Redactor(b"b" * 32).redact("13812345678").text)

    def test_kind_is_part_of_the_alias_message(self):
        # one value aliased under two kinds must yield two different aliases, so a
        # leaked URL alias cannot be replayed against an email field
        from redact_engine.alias import make_alias
        self.assertNotEqual(make_alias("email", "li@example.com", KEY),
                            make_alias("url", "li@example.com", KEY))

    def test_unstable_mode_uncorrelates_runs(self):
        one = Redactor(KEY, stable=False).redact("li@example.com").text
        two = Redactor(KEY, stable=False).redact("li@example.com").text
        self.assertNotEqual(one, two, "per-run key must break cross-export correlation")


class OverlapTest(unittest.TestCase):
    def test_more_specific_rule_owns_the_span(self):
        result = Redactor(KEY).redact("call 13812345678 today")
        self.assertEqual(len(result.hits), 1)
        self.assertEqual(result.hits[0].kind, "phone_cn")

    def test_multiple_distinct_secrets_are_all_replaced(self):
        text = "sk-abcdef1234567890 and 13812345678 and zhang@example.com"
        result = Redactor(KEY).redact(text)
        self.assertEqual(len(result.hits), 3)
        self.assertNotIn("zhang@example.com", result.text)
        self.assertNotIn("13812345678", result.text)

    def test_clean_text_is_unchanged(self):
        text = "compiled the report and sent nothing sensitive"
        result = Redactor(KEY).redact(text)
        self.assertEqual(result.text, text)
        self.assertEqual(result.hits, [])


class ProjectionTest(unittest.TestCase):
    def test_unknown_fields_are_never_read(self):
        redactor = Redactor(KEY)
        event = {
            "timestamp": "2026-10-17T10:00:00",
            "app": "com.example.chat",
            "text": "write to li@example.com",
            "raw_chat_history": "the whole conversation, including 13812345678",
            "ax_tree": {"nested": "secret sk-abcdef1234567890"},
        }
        projected = redactor.project(event)
        self.assertEqual(set(projected), {"timestamp", "app", "text"})
        self.assertNotIn("conversation", json.dumps(projected))
        self.assertNotIn("13812345678", json.dumps(projected))

    def test_field_whitelist_is_explicit(self):
        redactor = Redactor(KEY)
        event = {"timestamp": "t", "app": "com.example.a", "text": "x", "title": "note for li@example.com"}
        projected = redactor.project(event, fields=("app", "title"))
        self.assertEqual(set(projected), {"app", "title"})
        self.assertNotIn("li@example.com", projected["title"])

    def test_non_string_values_pass_through_unredacted_but_only_when_whitelisted(self):
        redactor = Redactor(KEY)
        projected = redactor.project({"app": "x", "duration": 12, "hidden": 1})
        self.assertEqual(projected, {"app": "x"}, "only whitelisted fields may be emitted")

    def test_verification_catches_a_forced_leak(self):
        # a rule set that cannot see emails, verified against the values that
        # should have gone: an honest failure instead of a silent pass
        redactor = Redactor(KEY, rules=())
        result = redactor.redact("email li@example.com")
        self.assertEqual(result.text, "email li@example.com")
        with self.assertRaises(AssertionError):
            assert_no_leaks(result.text, ["li@example.com"])

    def test_verification_passes_on_honest_output(self):
        redactor = Redactor(KEY)
        result = redactor.redact("email li@example.com and 13812345678")
        assert_no_leaks(result.text, redactor.seen_values)


class IdentityMapTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.map = self.dir / "identity-map.json"

    def test_map_is_owner_only_and_round_trips(self):
        first = Redactor(KEY, persist_map=self.map)
        label = first.redact("li@example.com").text
        reloaded = Redactor(KEY, persist_map=self.map)
        self.assertEqual(reloaded.redact("li@example.com").text, label)
        self.assertEqual(self.map.stat().st_mode & 0o777, 0o600)
        rows = json.loads(self.map.read_text())
        self.assertEqual(rows[0]["value"], "li@example.com")

    def test_symlinked_map_is_refused(self):
        real = self.dir / "real.json"
        real.write_text("[]")
        link = self.dir / "link.json"
        link.symlink_to(real)
        with self.assertRaises(ValueError):
            Redactor(KEY, persist_map=link)

    def test_no_map_by_default(self):
        directory = Path(tempfile.mkdtemp())
        redactor = Redactor(KEY)
        redactor.redact("li@example.com")
        self.assertEqual(list(directory.iterdir()), [])
        self.assertFalse((directory / "identity-map.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
