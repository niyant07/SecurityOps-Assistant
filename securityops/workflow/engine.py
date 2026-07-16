"""Workflow execution engine.

Given an approved :class:`WorkflowPlan`, the engine runs each approved step in
order, in the background, using the project's :class:`CommandRunner`. It streams
output to listeners, extracts findings after each step, persists every run to the
scan history (audit trail), and advances to the next step automatically.

The engine executes **only** steps the operator marked ``APPROVED``. It never
starts on its own — :meth:`run` must be called explicitly.
"""

from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtCore import QObject, Signal

from ..core.context import AppContext
from ..core.logging_config import get_logger
from ..core.tasks import CommandRunner
from ..models import Scan, ScanStatus
from . import parsers
from .plan import StepStatus, WorkflowPlan, WorkflowStep

_LOG = get_logger("workflow.engine")
_AUDIT = get_logger("audit")


class WorkflowEngine(QObject):
    """Sequentially executes the approved steps of a plan in the background."""

    step_started = Signal(int)          # step index
    step_output = Signal(int, str)      # step index, output chunk
    step_finished = Signal(int)         # step index (status now terminal)
    plan_finished = Signal()
    audit = Signal(str)                 # human-readable audit line

    def __init__(self, context: AppContext, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._ctx = context
        self._plan: WorkflowPlan | None = None
        self._project_id: int | None = None
        self._index = -1
        self._runner: CommandRunner | None = None
        self._buffer: list[str] = []
        self._cancelled = False

    # ------------------------------------------------------------------ #
    # Control
    # ------------------------------------------------------------------ #
    def is_running(self) -> bool:
        return self._plan is not None and not self._plan.is_complete() and not self._cancelled

    def run(self, plan: WorkflowPlan, project_id: int) -> None:
        """Begin executing *plan*'s approved steps for the given project."""
        if self.is_running():
            _LOG.warning("Engine already running; ignoring run() call.")
            return
        self._plan = plan
        self._project_id = project_id
        self._index = -1
        self._cancelled = False
        # Steps not explicitly approved are treated as skipped.
        for step in plan.steps:
            if step.status == StepStatus.PENDING:
                step.status = StepStatus.SKIPPED
        _AUDIT.info("Workflow started (project=%s, goal=%r)", project_id, plan.goal)
        self._advance()

    def cancel(self) -> None:
        """Stop after the current step; terminate any running process."""
        self._cancelled = True
        if self._runner and self._runner.is_running():
            self._runner.cancel()
        _AUDIT.info("Workflow cancelled by operator")

    # ------------------------------------------------------------------ #
    # Step iteration
    # ------------------------------------------------------------------ #
    def _advance(self) -> None:
        assert self._plan is not None
        if self._cancelled:
            self._finish_plan()
            return
        # Find the next approved step.
        self._index += 1
        while self._index < len(self._plan.steps):
            step = self._plan.steps[self._index]
            if step.status == StepStatus.APPROVED:
                self._start_step(self._index, step)
                return
            self._index += 1
        self._finish_plan()

    def _start_step(self, index: int, step: WorkflowStep) -> None:
        step.status = StepStatus.RUNNING
        step.started_at = datetime.now(timezone.utc)
        self._buffer = []
        argv = self._ctx.tools.split_command(step.command)
        if not argv:
            self._fail_step(step, "Empty command")
            return

        _AUDIT.info("EXEC step=%d tool=%s cmd=%r", index, step.tool_key, step.command)
        self.audit.emit(f"$ {step.command}")
        self.step_started.emit(index)

        runner = self._ctx.tasks.run_command(argv[0], argv[1:])
        self._runner = runner
        runner.output.connect(lambda chunk, i=index: self._on_output(i, chunk))
        runner.finished.connect(lambda code, i=index: self._on_finished(i, code))
        runner.failed.connect(lambda msg, i=index: self._on_failed(i, msg))

    # ------------------------------------------------------------------ #
    # Runner callbacks
    # ------------------------------------------------------------------ #
    def _on_output(self, index: int, chunk: str) -> None:
        self._buffer.append(chunk)
        self.step_output.emit(index, chunk)

    def _on_finished(self, index: int, code: int) -> None:
        assert self._plan is not None
        step = self._plan.steps[index]
        step.output = "".join(self._buffer)[:500_000]
        step.exit_code = code
        step.status = StepStatus.COMPLETED if code == 0 else StepStatus.FAILED
        step.finished_at = datetime.now(timezone.utc)
        step.findings = parsers.extract_findings(step.tool_key, step.output)
        self._persist(step)
        _AUDIT.info("DONE step=%d exit=%d findings=%d", index, code, len(step.findings))
        self.step_finished.emit(index)
        self._advance()

    def _on_failed(self, index: int, message: str) -> None:
        assert self._plan is not None
        step = self._plan.steps[index]
        self._fail_step(step, message)
        self.step_finished.emit(index)
        self._advance()

    def _fail_step(self, step: WorkflowStep, message: str) -> None:
        step.status = StepStatus.FAILED
        step.output = (step.output + f"\n[failed: {message}]").strip()
        step.finished_at = datetime.now(timezone.utc)
        self._persist(step)
        _AUDIT.warning("FAIL step tool=%s: %s", step.tool_key, message)

    # ------------------------------------------------------------------ #
    # Persistence / completion
    # ------------------------------------------------------------------ #
    def _persist(self, step: WorkflowStep) -> None:
        if self._project_id is None:
            return
        status = (ScanStatus.COMPLETED if step.status == StepStatus.COMPLETED
                  else ScanStatus.FAILED)
        scan = Scan(
            project_id=self._project_id,
            tool=step.tool_key,
            command=step.command,
            target=step.target,
            status=status,
            output=step.output,
            exit_code=step.exit_code,
            started_at=step.started_at,
            finished_at=step.finished_at,
        )
        try:
            self._ctx.database.scans.create(scan)
        except Exception:  # noqa: BLE001 - persistence must not crash a run
            _LOG.exception("Failed to persist scan for step %s", step.tool_key)

    def _finish_plan(self) -> None:
        _AUDIT.info("Workflow finished (cancelled=%s)", self._cancelled)
        self.plan_finished.emit()
