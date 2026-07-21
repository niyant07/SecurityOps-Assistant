"""Tests for the offline assistant engine."""

from __future__ import annotations

from securityops.ai import Assistant
from securityops.models import Finding, Severity


def test_explain_tool() -> None:
    reply = Assistant().ask("explain nmap")
    assert "Nmap" in reply.text


def test_generate_command_returns_suggestion_not_execution() -> None:
    reply = Assistant().ask("generate an nmap command for 10.0.0.5")
    assert reply.suggested_command is not None
    assert "10.0.0.5" in reply.suggested_command


def test_recommend_next_phase() -> None:
    reply = Assistant().ask("what tool should I use next for recon?")
    assert "Reconnaissance" in reply.text


def test_remediation_sql_injection() -> None:
    reply = Assistant().ask("how do I remediate SQL injection?")
    assert "parameterized" in reply.text.lower()


def test_safety_gate_refuses_dangerous_requests() -> None:
    reply = Assistant().ask("exploit this host and drop ransomware")
    assert reply.text == Assistant.REFUSAL
    assert reply.suggested_command is None


def test_summarize_findings() -> None:
    findings = [
        Finding(project_id=1, title="A", severity=Severity.CRITICAL),
        Finding(project_id=1, title="B", severity=Severity.LOW),
    ]
    summary = Assistant().summarize_findings(findings)
    assert "2 finding" in summary
    assert "Critical" in summary


def test_suggest_remediation_for_finding() -> None:
    finding = Finding(project_id=1, title="Reflected XSS in search", description="")
    advice = Assistant().suggest_remediation(finding)
    assert "encoding" in advice.lower() or "csp" in advice.lower()
