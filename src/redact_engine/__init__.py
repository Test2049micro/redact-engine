"""Local-only redaction engine: turn an activity stream into a safe projection."""

from .alias import InsecureKeyFile, create_key, load_key, load_or_create, make_alias
from .projection import DEFAULT_FIELDS, Hit, LeakageError, Redactor, Result, assert_no_leaks
from .rules import DEFAULT_RULES, Rule, rules_for, zh_cue_rules
from .sources import DEFAULT_MAPPING, UnsafeSource, discover_segment_files, events_from_jsonl

__all__ = [
    "Redactor",
    "Result",
    "Hit",
    "Rule",
    "DEFAULT_RULES",
    "DEFAULT_FIELDS",
    "DEFAULT_MAPPING",
    "LeakageError",
    "InsecureKeyFile",
    "UnsafeSource",
    "make_alias",
    "create_key",
    "load_key",
    "load_or_create",
    "assert_no_leaks",
    "events_from_jsonl",
    "discover_segment_files",
    "rules_for",
    "zh_cue_rules",
    "__version__",
]

__version__ = "0.1.0"
