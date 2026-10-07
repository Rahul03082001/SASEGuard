"""Text-only data loss prevention rules.

Scope, stated plainly: this is a regular-expression scanner over UTF-8 text
that a caller submitted as JSON. It is a teaching implementation of the
*shape* of DLP — deterministic rules, stable rule IDs, a block decision taken
before the data reaches storage, and findings that never contain the matched
value. It is not comparable to a commercial DLP or CASB product. See
docs/threat-model.md for the full list of what it misses.

The one property worth defending: ``scan`` returns rule IDs and match counts
only. The matched substrings are never returned, logged, or persisted, so an
audit row cannot become a second copy of the secret it was protecting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """A single named detector."""

    rule_id: str
    name: str
    description: str
    pattern: re.Pattern[str]


# Why these three patterns:
#
# * The synthetic-secret and customer-ID rules are *anchored and exact-length*.
#   ``\b`` on both sides plus a fixed repeat count means SG-DEMO-SECRET-ABC123
#   (too short) and SG-DEMO-SECRET-ABCDEFGHI (too long) both fail to match.
#   Exact-length tokens are the easy case and the one DLP products get right.
#
# * The email rule is the hard case, and it is deliberately included so the
#   false-positive discussion in the docs has something concrete to point at.
#   It matches things that merely look like addresses.
RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="SG-DLP-001",
        name="synthetic-credential",
        description="Lab secret token: SG-DEMO-SECRET- followed by exactly 8 uppercase letters or digits.",
        pattern=re.compile(r"\bSG-DEMO-SECRET-[A-Z0-9]{8}\b"),
    ),
    Rule(
        rule_id="SG-DLP-002",
        name="synthetic-customer-id",
        description="Lab customer identifier: SG-CUSTOMER- followed by exactly 6 digits.",
        pattern=re.compile(r"\bSG-CUSTOMER-[0-9]{6}\b"),
    ),
    Rule(
        rule_id="SG-DLP-003",
        name="email-address",
        description="Email-address-shaped text (local@domain.tld).",
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in RULES}


@dataclass(frozen=True)
class Finding:
    """One rule that fired, and how many times. Never the matched text."""

    rule_id: str
    name: str
    count: int

    def as_dict(self) -> dict[str, object]:
        return {"rule_id": self.rule_id, "rule_name": self.name, "match_count": self.count}


@dataclass(frozen=True)
class ScanResult:
    """The outcome of scanning one piece of text."""

    findings: tuple[Finding, ...]
    scanned_chars: int

    @property
    def blocked(self) -> bool:
        """Any finding blocks. There is no severity threshold in the MVP."""
        return bool(self.findings)

    @property
    def rule_ids(self) -> list[str]:
        return [finding.rule_id for finding in self.findings]

    def as_dict(self) -> dict[str, object]:
        return {
            "blocked": self.blocked,
            "scanned_chars": self.scanned_chars,
            "findings": [finding.as_dict() for finding in self.findings],
        }


def scan(text: str) -> ScanResult:
    """Apply every rule to ``text`` and return the findings.

    All rules always run — we do not stop at the first hit — because a
    reviewer looking at a blocked upload wants the complete list of reasons,
    not just the alphabetically first one.
    """
    if not isinstance(text, str):
        raise TypeError("scan() expects str")

    findings: list[Finding] = []
    for rule in RULES:
        matches = rule.pattern.findall(text)
        if matches:
            findings.append(Finding(rule_id=rule.rule_id, name=rule.name, count=len(matches)))

    return ScanResult(findings=tuple(findings), scanned_chars=len(text))


def describe_rules() -> list[dict[str, str]]:
    """Rule metadata for the dashboard and the OpenAPI description.

    The regex source is included on purpose: a user of a DLP system should be
    able to see why their upload was blocked.
    """
    return [
        {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "pattern": rule.pattern.pattern,
        }
        for rule in RULES
    ]
