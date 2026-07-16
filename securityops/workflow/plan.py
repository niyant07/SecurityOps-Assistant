"""Workflow plan data model.

A :class:`WorkflowPlan` is an ordered list of :class:`WorkflowStep` objects. The
planner produces it, the GUI displays it for approval, and the engine walks it.
Everything is plain data with no execution logic, so plans are trivial to test
and to serialize into the project database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class StepStatus(str, Enum):
    """Lifecycle of a single workflow step."""

    PENDING = "Pending"          # proposed, awaiting approval
    APPROVED = "Approved"        # operator approved, queued to run
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    SKIPPED = "Skipped"          # operator declined this step
    CANCELLED = "Cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (StepStatus.COMPLETED, StepStatus.FAILED,
                        StepStatus.SKIPPED, StepStatus.CANCELLED)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class WorkflowStep:
    """One proposed tool invocation within a plan."""

    tool_key: str                       # catalog key, e.g. "nmap"
    title: str                          # short human label
    rationale: str                      # why this step, in plain English
    command: str                        # the exact command to be run (review-only until approved)
    target: str = ""
    interactive: bool = False           # launches in a terminal rather than captured
    #: Set when a step could be disruptive (aggressive scan, brute force, etc.).
    warning: str = ""

    # -- runtime state (filled by the engine) --------------------------- #
    status: StepStatus = StepStatus.PENDING
    output: str = ""
    exit_code: int | None = None
    findings: list[str] = field(default_factory=list)   # highlighted lines
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def is_disruptive(self) -> bool:
        return bool(self.warning)


@dataclass
class WorkflowPlan:
    """An ordered, reviewable plan generated from a natural-language goal."""

    goal: str
    summary: str
    steps: list[WorkflowStep] = field(default_factory=list)
    #: True when the planner refused the goal (e.g. it requested a harmful action).
    refused: bool = False
    refusal_reason: str = ""
    #: Which planner produced this: "llm" or "rules".
    source: str = "rules"
    created_at: datetime = field(default_factory=_utcnow)

    def approved_steps(self) -> list[WorkflowStep]:
        return [s for s in self.steps if s.status == StepStatus.APPROVED]

    def pending_steps(self) -> list[WorkflowStep]:
        return [s for s in self.steps if s.status == StepStatus.PENDING]

    def is_complete(self) -> bool:
        return all(s.status.is_terminal for s in self.steps)

    def all_findings(self) -> list[str]:
        out: list[str] = []
        for step in self.steps:
            out.extend(step.findings)
        return out
