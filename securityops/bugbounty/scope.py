"""Engagement scope: import, model, and validation.

The scope is the authorization boundary. Nothing in the bug bounty module targets
an asset that is not explicitly in scope (and not excluded). Matching supports:

* exact hostnames and their subdomains (``example.com`` also covers ``a.example.com``)
* wildcard hostnames (``*.example.com``)
* IPs and CIDR ranges (``10.0.0.0/24``)
* URLs (reduced to their host)

Out-of-scope rules always win over in-scope rules.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum


class TargetType(str, Enum):
    """The kind of asset being assessed; drives methodology selection."""

    WEB = "Web Application"
    API = "API"
    MOBILE_BACKEND = "Mobile Backend"
    DESKTOP = "Desktop Application"
    NETWORK = "Network / Host"
    OTHER = "Other"


@dataclass
class Scope:
    """A parsed engagement scope."""

    program: str = ""
    platform: str = ""                       # e.g. "HackerOne", "Bugcrowd", "Self-owned"
    target_type: TargetType = TargetType.WEB
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    rules: str = ""                          # free-text engagement rules / notes

    def is_empty(self) -> bool:
        return not self.in_scope


@dataclass
class ScopeDecision:
    """Result of validating a target against a scope."""

    in_scope: bool
    matched: str = ""          # the rule that matched
    reason: str = ""


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
_IN_HEADERS = re.compile(r"^\s*(in[\s-]?scope|targets?|assets?|included)\s*:?\s*$", re.I)
_OUT_HEADERS = re.compile(r"^\s*(out[\s-]?of[\s-]?scope|excluded|exclusions?)\s*:?\s*$", re.I)
_RULES_HEADERS = re.compile(r"^\s*(rules|notes|policy|engagement)\s*:?\s*$", re.I)


def parse_scope_text(text: str) -> Scope:
    """Parse a pasted scope definition into a :class:`Scope`.

    Recognizes optional ``In scope:`` / ``Out of scope:`` / ``Rules:`` section
    headers. Lines may be bare or bullet-prefixed (``-``, ``*``, ``•``). Without
    any header, every non-empty line is treated as in-scope.
    """
    scope = Scope()
    section = "in"  # default bucket
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _IN_HEADERS.match(line):
            section = "in"
            continue
        if _OUT_HEADERS.match(line):
            section = "out"
            continue
        if _RULES_HEADERS.match(line):
            section = "rules"
            continue

        item = line.lstrip("-*•").strip()
        if section == "in":
            _add(scope.in_scope, item)
        elif section == "out":
            _add(scope.out_of_scope, item)
        else:
            scope.rules = (scope.rules + "\n" + line).strip()
    return scope


def _add(bucket: list[str], item: str) -> None:
    norm = _normalize(item)
    if norm and norm not in bucket:
        bucket.append(norm)


def _normalize(item: str) -> str:
    """Reduce a scope entry to a comparable form (strip scheme/path, lowercase)."""
    item = item.strip()
    item = re.sub(r"^\w+://", "", item)        # drop scheme
    item = item.split("/")[0] if "/" not in _cidr_part(item) else item
    return item.strip().lower()


def _cidr_part(item: str) -> str:
    """Return the item unchanged if it looks like a CIDR (so we keep the /nn)."""
    return item if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", item.strip()) else ""


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
class ScopeValidator:
    """Validates whether a target is authorized under a :class:`Scope`."""

    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    def classify(self, target: str) -> ScopeDecision:
        host = self._host_of(target)
        if not host:
            return ScopeDecision(False, reason="Could not parse a host from the target.")

        # Out-of-scope always wins.
        for rule in self._scope.out_of_scope:
            if self._matches(rule, host):
                return ScopeDecision(False, matched=rule,
                                     reason=f"Target matches out-of-scope rule '{rule}'.")

        for rule in self._scope.in_scope:
            if self._matches(rule, host):
                return ScopeDecision(True, matched=rule,
                                     reason=f"Target authorized by in-scope rule '{rule}'.")

        return ScopeDecision(False,
                             reason="Target is not listed in the engagement's in-scope assets.")

    def is_in_scope(self, target: str) -> bool:
        return self.classify(target).in_scope

    # ------------------------------------------------------------------ #
    @staticmethod
    def _host_of(target: str) -> str:
        t = target.strip()
        t = re.sub(r"^\w+://", "", t)
        t = t.split("/")[0].split(":")[0]
        return t.lower()

    @staticmethod
    def _matches(rule: str, host: str) -> bool:
        rule = rule.strip().lower()
        if not rule:
            return False

        # CIDR / IP rules.
        if "/" in rule and re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", rule):
            try:
                net = ipaddress.ip_network(rule, strict=False)
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        try:
            # Both are plain IPs.
            return ipaddress.ip_address(rule) == ipaddress.ip_address(host)
        except ValueError:
            pass

        # Wildcard hostnames: *.example.com
        if rule.startswith("*."):
            base = rule[2:]
            return host == base or host.endswith("." + base)

        # Plain hostname: matches exact host and any subdomain.
        return host == rule or host.endswith("." + rule)
