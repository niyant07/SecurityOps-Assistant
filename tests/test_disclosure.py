"""Tests for the Responsible Disclosure & Reporting module."""

from __future__ import annotations

from securityops.disclosure.curate import curate_findings, deduplicate, rank
from securityops.disclosure.email_gen import build_disclosure_email
from securityops.disclosure.report import DisclosureReportBundle, DisclosureReportGenerator
from securityops.disclosure.security_txt import parse_security_txt
from securityops.models import (
    Confidence,
    Disclosure,
    DisclosureStatus,
    Finding,
    Project,
    Severity,
)


def _f(title, sev, conf=Confidence.FIRM, asset="app.example.com", cvss=None):
    return Finding(project_id=1, title=title, severity=sev, confidence=conf,
                   affected_asset=asset, cvss_score=cvss)


# --------------------------------------------------------------------------- #
# security.txt
# --------------------------------------------------------------------------- #
def test_parse_security_txt_contacts() -> None:
    c = parse_security_txt(
        "# comment\nContact: mailto:security@example.com\n"
        "Contact: https://example.com/report\nPolicy: https://example.com/policy\n"
        "Expires: 2027-01-01T00:00:00Z")
    assert c.has_contact
    assert c.primary_email == "security@example.com"
    assert c.primary_url == "https://example.com/report"
    assert c.policy.endswith("/policy")


def test_parse_security_txt_email_without_scheme() -> None:
    c = parse_security_txt("Contact: security@example.com")
    assert c.primary_email == "security@example.com"


def test_parse_empty_has_no_contact() -> None:
    assert not parse_security_txt("Policy: https://x/p").has_contact


# --------------------------------------------------------------------------- #
# Curation: dedup + rank + flag
# --------------------------------------------------------------------------- #
def test_deduplicate_keeps_higher_severity() -> None:
    findings = [
        _f("SQL Injection", Severity.MEDIUM, Confidence.FIRM),
        _f("sql injection", Severity.HIGH, Confidence.CONFIRMED),  # dup, stronger
    ]
    deduped, removed = deduplicate(findings)
    assert removed == 1
    assert len(deduped) == 1
    assert deduped[0].severity == Severity.HIGH


def test_dedup_distinct_assets_not_merged() -> None:
    findings = [_f("XSS", Severity.LOW, asset="a.example.com"),
                _f("XSS", Severity.LOW, asset="b.example.com")]
    deduped, removed = deduplicate(findings)
    assert removed == 0 and len(deduped) == 2


def test_rank_orders_by_severity_then_confidence() -> None:
    findings = [
        _f("low-firm", Severity.LOW, Confidence.FIRM),
        _f("high-tentative", Severity.HIGH, Confidence.TENTATIVE),
        _f("high-confirmed", Severity.HIGH, Confidence.CONFIRMED),
    ]
    ordered = [f.title for f in rank(findings)]
    assert ordered == ["high-confirmed", "high-tentative", "low-firm"]


def test_curate_flags_verification() -> None:
    curated = curate_findings([
        _f("Confirmed issue", Severity.HIGH, Confidence.CONFIRMED),
        _f("Needs check", Severity.MEDIUM, Confidence.TENTATIVE),
    ])
    assert len(curated.needs_verification) == 1
    assert curated.needs_verification[0].title == "Needs check"
    assert curated.ranked[0].title == "Confirmed issue"


# --------------------------------------------------------------------------- #
# Email generation
# --------------------------------------------------------------------------- #
def test_email_is_professional_and_factual() -> None:
    curated = curate_findings([_f("SQLi", Severity.HIGH, Confidence.CONFIRMED),
                               _f("Header", Severity.LOW, Confidence.TENTATIVE)])
    email = build_disclosure_email("Example Corp", "example.com", curated,
                                   recipient="security@example.com", report_version="v2")
    assert "example.com" in email.subject and "v2" in email.subject
    assert email.recipient == "security@example.com"
    assert "good faith" in email.body.lower()
    assert "verification" in email.body.lower()  # tentative item mentioned


def test_email_no_findings_still_builds() -> None:
    email = build_disclosure_email("Org", "t", curate_findings([]))
    assert email.subject and email.body


# --------------------------------------------------------------------------- #
# Report generation
# --------------------------------------------------------------------------- #
def test_disclosure_report_sections() -> None:
    project = Project(name="P", authorized=True)
    project.id = 1
    findings = [_f("SQLi", Severity.HIGH, Confidence.CONFIRMED, cvss=8.2)]
    findings[0].business_impact = "Attacker can read the database."
    findings[0].reproduction = "1. Send payload"
    gen = DisclosureReportGenerator({"author": "R", "classification": "CONFIDENTIAL"})
    bundle = DisclosureReportBundle(project=project, target="example.com", findings=findings)
    html = gen.render_html(bundle)
    md = gen.render_markdown(bundle)
    for section in ("Executive Summary", "Scope", "Assessment Methodology",
                    "Technical Findings", "Timeline of Assessment"):
        assert section in html, section
    assert "Business impact" in html
    assert "Attacker can read the database." in html
    assert "Confidence" in html
    assert "Steps to reproduce" in md


# --------------------------------------------------------------------------- #
# Persistence: disclosure records + versioning
# --------------------------------------------------------------------------- #
def test_disclosure_records_and_versioning(db, project_id) -> None:
    assert db.disclosures.next_version(project_id) == "v1"
    db.disclosures.create(Disclosure(project_id=project_id, report_version="v1",
                                     recipient="security@example.com", method="email",
                                     status=DisclosureStatus.PREPARED))
    assert db.disclosures.next_version(project_id) == "v2"
    records = db.disclosures.list_for_project(project_id)
    assert len(records) == 1
    assert records[0].status == DisclosureStatus.PREPARED


def test_finding_confidence_persists(db, project_id) -> None:
    db.findings.create(Finding(project_id=project_id, title="X", severity=Severity.LOW,
                               confidence=Confidence.TENTATIVE, business_impact="impact"))
    got = db.findings.list_for_project(project_id)[0]
    assert got.confidence == Confidence.TENTATIVE
    assert got.business_impact == "impact"
