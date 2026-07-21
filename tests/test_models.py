"""Tests for domain model behavior (enums, CVSS mapping)."""

from __future__ import annotations

import pytest

from securityops.models import Severity


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_severity_from_cvss(score: float, expected: Severity) -> None:
    assert Severity.from_cvss(score) is expected


def test_severity_rank_ordering() -> None:
    ranks = [s.rank for s in
             (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert ranks == sorted(ranks)
    assert ranks == [0, 1, 2, 3, 4]


def test_severity_has_color() -> None:
    for sev in Severity:
        assert sev.color.startswith("#") and len(sev.color) == 7
