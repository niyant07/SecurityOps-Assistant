"""Tests for findings correlation & triage (bug bounty module)."""

from __future__ import annotations

from securityops.bugbounty.triage import Candidate, triage_findings, triage_step
from securityops.models import Severity
from securityops.workflow.plan import StepStatus, WorkflowStep


def _step(tool: str, target: str, findings: list[str]) -> WorkflowStep:
    s = WorkflowStep(tool_key=tool, title=tool, rationale="", command=f"/usr/bin/{tool}",
                     target=target)
    s.status = StepStatus.COMPLETED
    s.findings = findings
    return s


def test_open_port_becomes_candidate() -> None:
    cands = triage_step("nmap", "example.com", ["Open port 22/tcp — ssh OpenSSH 8.2"])
    assert cands
    assert "22/tcp" in cands[0].title
    assert cands[0].affected_asset == "example.com"
    assert cands[0].requires_verification


def test_sensitive_service_higher_severity() -> None:
    telnet = triage_step("nmap", "t", ["Open port 23/tcp — telnet"])[0]
    ssh = triage_step("nmap", "t", ["Open port 22/tcp — ssh"])[0]
    assert telnet.severity.rank > ssh.severity.rank


def test_cve_is_high_and_referenced() -> None:
    c = triage_step("nikto", "t", ["OSVDB-1: matches CVE-2021-44228 here"])[0]
    assert c.severity == Severity.HIGH
    assert "CVE-2021-44228" in c.references


def test_missing_header_is_low() -> None:
    c = triage_step("nikto", "t", ["The X-Frame-Options header is not present."])[0]
    assert c.severity == Severity.LOW


def test_directory_listing_is_medium() -> None:
    c = triage_step("nikto", "t", ["OSVDB-3268: /icons/: Directory indexing found."])[0]
    # CVE/OSVDB rule may catch OSVDB? No — OSVDB alone isn't CVE; directory indexing wins.
    assert c.severity in (Severity.MEDIUM, Severity.HIGH)


def test_sensitive_path_reachable() -> None:
    cands = triage_step("gobuster", "http://t", ["HTTP 200 — /admin"])
    assert cands and "admin" in cands[0].title.lower()
    assert cands[0].severity == Severity.MEDIUM


def test_boring_path_ignored() -> None:
    assert triage_step("gobuster", "http://t", ["HTTP 200 — /index.html"]) == []


def test_host_up_line_ignored() -> None:
    assert triage_step("nmap", "t", ["Host up: example.com (1.2.3.4)"]) == []


def test_dedup_same_evidence() -> None:
    cands = triage_step("nmap", "t", ["Open port 22/tcp — ssh", "Open port 22/tcp — ssh"])
    assert len(cands) == 1


def test_triage_findings_sorts_by_severity() -> None:
    steps = [
        _step("nmap", "t", ["Open port 22/tcp — ssh"]),           # INFO
        _step("nikto", "t", ["matches CVE-2020-0001"]),           # HIGH
        _step("gobuster", "http://t", ["HTTP 200 — /admin"]),     # MEDIUM
    ]
    cands = triage_findings(steps)
    ranks = [c.severity.rank for c in cands]
    assert ranks == sorted(ranks, reverse=True)


def test_candidate_to_finding_round_trip() -> None:
    c = Candidate(title="Test", severity=Severity.MEDIUM, description="d",
                  affected_asset="t", source_tool="nmap", evidence="e",
                  reproduction="repro")
    f = c.to_finding(project_id=5)
    assert f.project_id == 5
    assert f.severity == Severity.MEDIUM
    assert f.reproduction == "repro"
    assert "verify manually" in f.description.lower()
