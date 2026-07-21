"""Curate verified findings for disclosure.

Deduplicates findings, ranks them by severity then confidence then CVSS, and
separates out the items that still require manual verification. This never
invents findings — it only organizes what the analyst has already recorded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Confidence, Finding, Severity


@dataclass
class CuratedFindings:
    """The organized result of curating a project's findings."""

    ranked: list[Finding] = field(default_factory=list)
    needs_verification: list[Finding] = field(default_factory=list)
    duplicates_removed: int = 0
    severity_counts: dict[Severity, int] = field(default_factory=dict)

    @property
    def reportable(self) -> list[Finding]:
        """All ranked findings (verification-flagged ones are marked, not dropped)."""
        return self.ranked


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Remove duplicate findings (same normalized title + affected asset).

    When duplicates collide, the one with the higher (severity, confidence) is
    kept so information is never downgraded.
    """
    best: dict[tuple[str, str], Finding] = {}
    order: list[tuple[str, str]] = []
    removed = 0
    for f in findings:
        key = (_norm(f.title), _norm(f.affected_asset))
        if key not in best:
            best[key] = f
            order.append(key)
        else:
            removed += 1
            incumbent = best[key]
            if (f.severity.rank, f.confidence.rank) > (incumbent.severity.rank,
                                                       incumbent.confidence.rank):
                best[key] = f
    return [best[k] for k in order], removed


def rank(findings: list[Finding]) -> list[Finding]:
    """Rank findings by severity, then confidence, then CVSS score (descending)."""
    return sorted(
        findings,
        key=lambda f: (f.severity.rank, f.confidence.rank, f.cvss_score or 0.0),
        reverse=True,
    )


def curate_findings(findings: list[Finding]) -> CuratedFindings:
    """Deduplicate, rank, and classify a project's findings for disclosure."""
    deduped, removed = deduplicate(findings)
    ranked = rank(deduped)
    needs = [f for f in ranked if f.confidence.needs_verification]
    counts: dict[Severity, int] = {}
    for f in ranked:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return CuratedFindings(
        ranked=ranked,
        needs_verification=needs,
        duplicates_removed=removed,
        severity_counts=counts,
    )
