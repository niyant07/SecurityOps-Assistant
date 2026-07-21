"""Plain-language explanation of workflow results.

Uses a local LLM when available for fluent summaries, and always has a
deterministic template fallback so explanations work fully offline. Explanations
are descriptive only — they never recommend or perform exploitation.
"""

from __future__ import annotations

from ..core.logging_config import get_logger
from .plan import StepStatus, WorkflowPlan, WorkflowStep

_LOG = get_logger("workflow.explain")


class Explainer:
    """Summarize steps and whole plans in plain English."""

    _SYSTEM = (
        "You are a security assessment assistant. Explain tool output plainly and "
        "factually for a non-expert reader. Describe what was found and why it "
        "matters defensively. Do not provide exploitation instructions."
    )

    def __init__(self, llm=None) -> None:  # noqa: ANN001
        self._llm = llm

    # ------------------------------------------------------------------ #
    def explain_step(self, step: WorkflowStep) -> str:
        """Explain a single completed step."""
        if step.status == StepStatus.FAILED:
            return (f"The {step.tool_key} step did not complete successfully. "
                    f"Review the output for the error and check the target is "
                    f"reachable and in scope.")
        if step.status == StepStatus.SKIPPED:
            return f"The {step.tool_key} step was skipped."

        if self._llm is not None and self._llm.available():
            explanation = self._llm_explain_step(step)
            if explanation:
                return explanation
        return self._template_step(step)

    def explain_plan(self, plan: WorkflowPlan) -> str:
        """Explain the overall outcome of a plan."""
        completed = [s for s in plan.steps if s.status == StepStatus.COMPLETED]
        findings = plan.all_findings()
        if not completed:
            return "No steps completed, so there are no results to explain yet."

        if self._llm is not None and self._llm.available():
            explanation = self._llm_explain_plan(plan, findings)
            if explanation:
                return explanation
        return self._template_plan(plan, completed, findings)

    # ------------------------------------------------------------------ #
    # LLM paths
    # ------------------------------------------------------------------ #
    def _llm_explain_step(self, step: WorkflowStep) -> str | None:
        excerpt = step.output[:4000]
        prompt = (f"Tool: {step.tool_key}\nGoal of step: {step.rationale}\n\n"
                  f"Output:\n{excerpt}\n\nExplain the results in 2-4 sentences.")
        return self._llm.generate(prompt, system=self._SYSTEM)

    def _llm_explain_plan(self, plan: WorkflowPlan, findings: list[str]) -> str | None:
        joined = "\n".join(f"- {f}" for f in findings[:40]) or "(no notable findings)"
        prompt = (f"Assessment goal: {plan.goal}\n\nKey findings:\n{joined}\n\n"
                  f"Write a short plain-English summary (3-5 sentences) of what was "
                  f"learned about the target's security posture.")
        return self._llm.generate(prompt, system=self._SYSTEM)

    # ------------------------------------------------------------------ #
    # Deterministic fallback
    # ------------------------------------------------------------------ #
    @staticmethod
    def _template_step(step: WorkflowStep) -> str:
        n = len(step.findings)
        if n == 0:
            return (f"{step.tool_key} completed but produced no notable highlights. "
                    f"The full output is available for manual review.")
        preview = "; ".join(step.findings[:5])
        more = f" (and {n - 5} more)" if n > 5 else ""
        return (f"{step.tool_key} completed and surfaced {n} item(s): {preview}{more}. "
                f"Review these against what you expect to be exposed.")

    @staticmethod
    def _template_plan(plan: WorkflowPlan, completed: list[WorkflowStep],
                       findings: list[str]) -> str:
        tools = ", ".join(dict.fromkeys(s.tool_key for s in completed))
        if not findings:
            return (f"Ran {len(completed)} step(s) ({tools}) against the target. "
                    f"Nothing notable was automatically highlighted; review the raw "
                    f"output for detail.")
        # Categorize highlights for a fuller summary.
        ports = [f for f in findings if f.lower().startswith("open port")]
        hosts = [f for f in findings if f.lower().startswith("host up")]
        parts: list[str] = [
            f"Completed {len(completed)} step(s) using {tools}."
        ]
        if hosts:
            parts.append(f"{len(hosts)} live host(s) confirmed.")
        if ports:
            parts.append(f"{len(ports)} open port(s)/service(s) identified.")
        other = len(findings) - len(ports) - len(hosts)
        if other > 0:
            parts.append(f"{other} additional item(s) worth reviewing.")
        parts.append("Validate each highlight manually before treating it as a finding.")
        return " ".join(parts)
