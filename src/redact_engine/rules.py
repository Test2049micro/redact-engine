"""Redaction rules: patterns, and what each one becomes.

Two deliberate choices differ from a general PII library:

* Every rule names a ``kind``, and the replacement is ``[kind-<hmac12>]``, not
  ``<REDACTED>``. A single token repeated across an activity stream must stay
  recognisable as the same subject, or the projection is unusable for any task
  that needs continuity ("what was I doing in that app all week").
* Patterns that are *shapeless* in the source text (a Chinese person reference, a
  place mention) are handled by an optional entity extractor, never by pretending
  the regex layer found them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Pattern

# Order matters: the most specific patterns run first so a credential inside a
# URL is not mangled into a path by the earlier, looser rule.
DEFAULT_RULES: tuple["Rule", ...] = ()


@dataclass(frozen=True)
class Rule:
    kind: str
    pattern: Pattern[str]
    group: int = 1
    enabled: bool = True

    def finditer(self, text: str):
        return self.pattern.finditer(text)

    def span(self, match) -> tuple[int, int]:
        """Span of the intended group, falling back to the whole match.

        A pattern with no capture group must not raise: rules are user-editable,
        and one wrong ``group`` number would otherwise abort a projection partway
        through -- leaving text after that point unredacted.
        """
        group = self.group if self.group <= len(match.groups()) else 0
        return match.span(group)

    def value(self, match) -> str:
        group = self.group if self.group <= len(match.groups()) else 0
        return match.group(group)


def _rule(kind: str, pattern: str, group: int = 0, flags: int = re.IGNORECASE) -> Rule:
    return Rule(kind=kind, pattern=re.compile(pattern, flags), group=group)


_BUILTIN = (
    _rule("credential", r"\b(?:sk|pk|api|key|token)-[A-Za-z0-9_\-]{12,}"),
    _rule("credential", r"\b(?:ghp|gho|github_pat|xai|AIza|AKIA|ASIA)[A-Za-z0-9_\-]{8,}"),
    _rule("bearer", r"[Bb]earer\s+([A-Za-z0-9._\-]{8,})", group=1),
    _rule("secret_json", r'"(?:api[_-]?key|token|secret|password)"\s*:\s*"([^"]{4,})"', group=1),
    _rule("email", r"[\w.+\-]+@[\w\-]+\.[\w.\-]+"),
    _rule("phone_cn", r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    _rule("id_cn", r"(?<!\d)\d{17}[\dXx](?!\d)"),
    _rule("otp", r"(?:验证码|verification code|one[- ]?time code|OTP)\D{0,6}(\d{4,8})", group=1),
    _rule("url", r"https?://[^\s<>\"]+", group=0),
    _rule("path", r"(?:/[A-Za-z0-9._\-@+]+){2,}", group=0),
    _rule("guid", r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    _rule("number_long", r"(?<![\d.])\d{9,}(?:\.\d+)?(?![\d.])"),
    _rule("iban", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    _rule("ip_private", r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}\b"),
)

DEFAULT_RULES = tuple(rule for rule in _BUILTIN if rule.enabled)

# References that a shapeless-text extractor may add: person/place/organisation.
ENTITY_KINDS = ("person", "place", "org")

_CUE_CACHE: dict[str, re.Pattern[str]] = {}


def zh_cue_rules() -> list[Rule]:
    """Heuristic Chinese person/place cues, used when no NER backend is wired.

    Deliberately conservative and labelled as such: these catch honorific and
    verb-adjacent references (「王老师」「致电小李」), not arbitrary names. A miss
    here is a redaction gap, so the CLI reports which extractor was in use.
    """
    patterns = (
        ("person", r"[\u4e00-\u9fa5]{1,3}(?:老师|经理|医生|律师|同学|女士|先生|总)"),
        ("person", r"(?:致电|联系|找|问)([\u4e00-\u9fa5]{2,4})(?=[，。！？\s]|$)"),
        ("place", r"[\u4e00-\u9fa5]{2,6}(?:医院|学校|大学|公司|机场|火车站|地铁[^\s，。]{0,4}站)"),
    )
    rules = []
    for kind, pattern in patterns:
        compiled = _CUE_CACHE.get(pattern) or re.compile(pattern)
        _CUE_CACHE[pattern] = compiled
        rules.append(Rule(kind=kind, pattern=compiled, group=0))
    return rules


def rules_for(kinds: Iterable[str] | None = None) -> tuple[Rule, ...]:
    if kinds is None:
        return DEFAULT_RULES
    wanted = set(kinds)
    return tuple(rule for rule in DEFAULT_RULES if rule.kind in wanted)
