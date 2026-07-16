"""AI workflow engine.

Turns a natural-language objective into an explicit, reviewable plan of Kali
tool invocations, executes approved steps in the background, extracts findings
from their output, and explains the results in plain language.

Design principles:

* **Nothing runs without approval.** The planner only proposes; the engine only
  executes steps the operator has explicitly approved.
* **Offline-first.** Planning and explanation use a local LLM when one is
  available and fall back to deterministic rules otherwise.
* **Auditable.** Every executed command and its output is persisted.
"""

from __future__ import annotations

from .plan import StepStatus, WorkflowPlan, WorkflowStep

__all__ = ["StepStatus", "WorkflowPlan", "WorkflowStep"]
