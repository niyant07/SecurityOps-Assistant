"""Scope-aware bug bounty planner.

Builds a reviewable assessment plan from a natural-language objective and an
imported :class:`Scope`. Two hard gates run before any step is produced:

1. the shared harmful-goal guardrail, and
2. **scope validation** — the chosen target must be in scope and not excluded.

Tool selection follows the target-type methodology (deterministic), and commands
are built from the same vetted templates the rest of the platform uses.
"""

from __future__ import annotations

from ..core.logging_config import get_logger
from ..core.tools import ToolRegistry
from ..workflow.plan import StepStatus, WorkflowPlan
from ..workflow.planner import RuleBasedPlanner, _harmful_reason, extract_target
from .methodology import methodology_for, tool_chain_for
from .scope import Scope, ScopeValidator

_LOG = get_logger("bugbounty.planner")


class BugBountyPlanner:
    """Produce scope-validated, methodology-driven assessment plans."""

    def __init__(self, tools: ToolRegistry) -> None:
        self._tools = tools
        self._rules = RuleBasedPlanner(tools)

    # ------------------------------------------------------------------ #
    def plan(self, goal: str, scope: Scope) -> WorkflowPlan:
        reason = _harmful_reason(goal)
        if reason:
            return WorkflowPlan(goal=goal, summary="Request refused.",
                                refused=True, refusal_reason=reason, source="bugbounty")

        if scope.is_empty():
            return WorkflowPlan(
                goal=goal, source="bugbounty",
                summary="No in-scope assets are defined. Import the engagement scope "
                        "before building a workflow.")

        target_str = self._choose_target(goal, scope)
        if target_str is None:
            return WorkflowPlan(
                goal=goal, source="bugbounty",
                summary="Could not determine a target from the goal or scope.")

        # Hard scope gate.
        decision = ScopeValidator(scope).classify(target_str)
        if not decision.in_scope:
            _LOG.warning("Refused out-of-scope target %r: %s", target_str, decision.reason)
            return WorkflowPlan(
                goal=goal, source="bugbounty", refused=True,
                summary="Target is not authorized under the imported scope.",
                refusal_reason=decision.reason)

        target_obj = extract_target(target_str)
        tool_keys = tool_chain_for(scope.target_type)
        plan = self._rules._assemble(goal, target_obj, tool_keys, source="bugbounty")

        program = scope.program or "Engagement"
        plan.summary = (f"[{program} · {scope.target_type.value}] "
                        f"Authorized target {target_str} ({decision.matched}). " + plan.summary)
        return plan

    # ------------------------------------------------------------------ #
    def recommend_next(self, scope: Scope, completed_tool_keys: list[str]) -> str:
        """Recommend the next methodology step given what has already run."""
        done = set(completed_tool_keys)
        installed = {d.spec.key for d in self._tools.installed()}
        for phase in methodology_for(scope.target_type):
            remaining = [k for k in phase.tool_keys if k not in done and k in installed]
            if remaining:
                names = ", ".join(remaining)
                return (f"Next phase: {phase.name} — {phase.goal} "
                        f"Suggested tool(s): {names}.")
        return ("All methodology phases for this target type have tools that have run. "
                "Review the findings, verify manually, and document reproduction steps.")

    def _choose_target(self, goal: str, scope: Scope) -> str | None:
        """Prefer a target named in the goal; otherwise the first in-scope asset."""
        found = extract_target(goal)
        if found is not None:
            return found.raw
        return scope.in_scope[0] if scope.in_scope else None
