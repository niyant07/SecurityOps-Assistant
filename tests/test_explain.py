"""Tests for the deterministic (no-LLM) explanation fallback."""

from __future__ import annotations

from securityops.workflow.explain import Explainer
from securityops.workflow.plan import StepStatus, WorkflowPlan, WorkflowStep


def _completed_step(tool: str, findings: list[str]) -> WorkflowStep:
    step = WorkflowStep(tool_key=tool, title=tool, rationale="", command=f"/usr/bin/{tool}")
    step.status = StepStatus.COMPLETED
    step.findings = findings
    return step


def test_explain_step_with_findings() -> None:
    explainer = Explainer(llm=None)
    step = _completed_step("nmap", ["Open port 22/tcp — ssh", "Open port 80/tcp — http"])
    text = explainer.explain_step(step)
    assert "nmap" in text
    assert "2 item" in text


def test_explain_step_no_findings() -> None:
    explainer = Explainer(llm=None)
    step = _completed_step("whatweb", [])
    text = explainer.explain_step(step)
    assert "no notable" in text.lower()


def test_explain_failed_step() -> None:
    explainer = Explainer(llm=None)
    step = WorkflowStep(tool_key="nmap", title="nmap", rationale="", command="x")
    step.status = StepStatus.FAILED
    assert "did not complete" in explainer.explain_step(step)


def test_explain_plan_summarizes_counts() -> None:
    explainer = Explainer(llm=None)
    plan = WorkflowPlan(goal="scan example.com", summary="")
    plan.steps = [
        _completed_step("nmap", ["Host up: example.com", "Open port 22/tcp — ssh"]),
        _completed_step("nikto", ["OSVDB-1234: something"]),
    ]
    text = explainer.explain_plan(plan)
    assert "nmap" in text and "nikto" in text
    assert "open port" in text.lower()


def test_explain_plan_no_completed_steps() -> None:
    explainer = Explainer(llm=None)
    plan = WorkflowPlan(goal="x", summary="")
    assert "no results" in explainer.explain_plan(plan).lower()
