"""AI Workflow plugin: natural-language goal -> approve -> execute -> explain.

This is the interactive front-end for :mod:`securityops.workflow`. The operator
types a goal in plain English; the planner proposes a reviewable, checkbox-gated
plan; on approval the engine runs the approved steps in the background, streaming
output and surfacing highlighted findings; the explainer then summarizes results.

Planning and explanation run off the UI thread so a local-LLM call never blocks
the interface. Execution is gated behind an explicit approval dialog.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..core.plugins import PluginBase, PluginMeta
from ..gui import widgets
from ..workflow.engine import WorkflowEngine
from ..workflow.explain import Explainer
from ..workflow.plan import StepStatus, WorkflowPlan, WorkflowStep
from ..workflow.planner import make_planner


# --------------------------------------------------------------------------- #
# Per-step row widget
# --------------------------------------------------------------------------- #
class StepRow(QFrame):
    """A single plan step: approval checkbox, title/status, command, warning."""

    def __init__(self, index: int, step: WorkflowStep) -> None:
        super().__init__()
        self.index = index
        self.step = step
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("QFrame { border: 1px solid #30363d; border-radius: 6px; }")

        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.checkbox = QCheckBox()
        self.checkbox.setChecked(True)
        self._title = QLabel(f"<b>{index + 1}. {step.title}</b>")
        self._status = QLabel(step.status.value)
        self._status.setStyleSheet("color: #8b949e;")
        top.addWidget(self.checkbox)
        top.addWidget(self._title, stretch=1)
        top.addWidget(self._status)
        layout.addLayout(top)

        rationale = QLabel(step.rationale)
        rationale.setWordWrap(True)
        rationale.setStyleSheet("color: #8b949e; border: none;")
        layout.addWidget(rationale)

        cmd = QLabel(step.command)
        cmd.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        cmd.setStyleSheet("font-family: monospace; color: #e6edf3; border: none;")
        cmd.setWordWrap(True)
        layout.addWidget(cmd)

        if step.warning:
            warn = QLabel(f"⚠ {step.warning}")
            warn.setWordWrap(True)
            warn.setStyleSheet("color: #d29922; border: none;")
            layout.addWidget(warn)

    @property
    def approved(self) -> bool:
        return self.checkbox.isChecked()

    def set_status(self, status: StepStatus) -> None:
        colors = {
            StepStatus.RUNNING: "#2f81f7",
            StepStatus.COMPLETED: "#3fb950",
            StepStatus.FAILED: "#f85149",
            StepStatus.SKIPPED: "#8b949e",
            StepStatus.CANCELLED: "#8b949e",
        }
        self._status.setText(status.value)
        self._status.setStyleSheet(f"color: {colors.get(status, '#8b949e')}; border: none;")

    def lock(self) -> None:
        self.checkbox.setEnabled(False)


# --------------------------------------------------------------------------- #
# Main widget
# --------------------------------------------------------------------------- #
class WorkflowChatWidget(QWidget):
    def __init__(self, plugin: "WorkflowChatPlugin") -> None:
        super().__init__()
        self._ctx = plugin.context
        self._planner = make_planner(self._ctx.tools, llm=self._ctx.llm)
        self._explainer = Explainer(llm=self._ctx.llm)
        self._engine = WorkflowEngine(self._ctx)
        self._plan: WorkflowPlan | None = None
        self._rows: list[StepRow] = []

        self._wire_engine()
        self._build_ui()
        self._probe_llm()

    # -- UI --------------------------------------------------------------- #
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        header = QHBoxLayout()
        header.addWidget(widgets.section_label("AI Security Workflow"))
        header.addStretch()
        self._llm_status = QLabel("Local LLM: checking…")
        self._llm_status.setStyleSheet("color: #8b949e;")
        header.addWidget(self._llm_status)
        root.addLayout(header)

        disclaimer = QLabel(
            "Describe a goal in plain English. I'll propose a plan of tools; "
            "nothing runs until you approve it. Authorized targets only.")
        disclaimer.setWordWrap(True)
        disclaimer.setStyleSheet("color: #8b949e;")
        root.addWidget(disclaimer)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left column: conversation + plan steps + controls
        left = QWidget()
        lcol = QVBoxLayout(left)

        self._conversation = QTextBrowser()
        self._conversation.setMinimumHeight(120)
        lcol.addWidget(self._conversation, stretch=1)

        # Scrollable steps area
        self._steps_container = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_container)
        self._steps_layout.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._steps_container)
        lcol.addWidget(scroll, stretch=2)

        controls = QHBoxLayout()
        self._run_btn = QPushButton("Approve & Run")
        self._run_btn.setObjectName("primary")
        self._run_btn.clicked.connect(self._approve_and_run)
        self._run_btn.setEnabled(False)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.clicked.connect(self._cancel)
        self._cancel_btn.setEnabled(False)
        controls.addWidget(self._run_btn)
        controls.addWidget(self._cancel_btn)
        controls.addStretch()
        lcol.addLayout(controls)

        input_row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setPlaceholderText(
            "e.g. Identify the IP address and open ports of my website example.com")
        self._input.returnPressed.connect(self._on_plan)
        plan_btn = QPushButton("Plan")
        plan_btn.clicked.connect(self._on_plan)
        input_row.addWidget(self._input, stretch=1)
        input_row.addWidget(plan_btn)
        lcol.addLayout(input_row)

        splitter.addWidget(left)

        # Right column: live output + findings dashboard
        right = QWidget()
        rcol = QVBoxLayout(right)
        rcol.addWidget(QLabel("Live output"))
        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setStyleSheet("font-family: monospace;")
        rcol.addWidget(self._output, stretch=2)
        rcol.addWidget(QLabel("Findings dashboard"))
        self._findings = QListWidget()
        rcol.addWidget(self._findings, stretch=1)
        splitter.addWidget(right)

        splitter.setSizes([620, 520])
        root.addWidget(splitter, stretch=1)

    # -- engine wiring ---------------------------------------------------- #
    def _wire_engine(self) -> None:
        self._engine.step_started.connect(self._on_step_started)
        self._engine.step_output.connect(self._on_step_output)
        self._engine.step_finished.connect(self._on_step_finished)
        self._engine.plan_finished.connect(self._on_plan_finished)
        self._engine.audit.connect(lambda line: self._output.appendPlainText(line))

    # -- LLM status ------------------------------------------------------- #
    def _probe_llm(self) -> None:
        llm = self._ctx.llm
        if llm is None:
            self._llm_status.setText("Local LLM: disabled (using rules)")
            return

        def probe() -> bool:
            return bool(llm.available(refresh=True))

        worker = self._ctx.tasks.submit(probe)
        worker.signals.result.connect(self._set_llm_status)

    def _set_llm_status(self, available: bool) -> None:
        if available:
            model = getattr(self._ctx.llm, "model", "local")
            self._llm_status.setText(f"Local LLM: connected ({model})")
            self._llm_status.setStyleSheet("color: #3fb950;")
        else:
            self._llm_status.setText("Local LLM: offline (using rules)")
            self._llm_status.setStyleSheet("color: #8b949e;")

    # -- planning --------------------------------------------------------- #
    def _on_plan(self) -> None:
        goal = self._input.text().strip()
        if not goal:
            return
        if self._engine.is_running():
            widgets.warn(self, "Busy", "A workflow is already running.")
            return
        self._say("You", goal)
        self._input.clear()
        self._clear_steps()
        self._say("Assistant", "Analyzing your goal and building a plan…")

        worker = self._ctx.tasks.submit(self._planner.plan, goal)
        worker.signals.result.connect(self._on_plan_ready)
        worker.signals.error.connect(
            lambda msg: self._say("Assistant", f"Planning failed: {msg.splitlines()[0]}"))

    def _on_plan_ready(self, plan: WorkflowPlan) -> None:
        self._plan = plan
        if plan.refused:
            self._say("Assistant", f"⛔ {plan.refusal_reason}")
            return
        self._say("Assistant", plan.summary)
        if not plan.steps:
            return
        for i, step in enumerate(plan.steps):
            row = StepRow(i, step)
            self._rows.append(row)
            self._steps_layout.insertWidget(self._steps_layout.count() - 1, row)
        self._run_btn.setEnabled(True)

    # -- execution -------------------------------------------------------- #
    def _approve_and_run(self) -> None:
        if self._plan is None:
            return
        project_id = self._ctx.active_project_id
        if project_id is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return

        approved: list[str] = []
        for row in self._rows:
            if row.approved:
                row.step.status = StepStatus.APPROVED
                approved.append(row.step.command)
            else:
                row.step.status = StepStatus.SKIPPED
                row.set_status(StepStatus.SKIPPED)

        if not approved:
            widgets.warn(self, "Nothing to run", "Approve at least one step.")
            return

        listing = "\n".join(f"• {c}" for c in approved)
        if not widgets.confirm(
            self, "Confirm execution",
            f"Run the following {len(approved)} approved command(s)?\n\n{listing}\n\n"
            "Only proceed against targets you are authorized to assess.",
        ):
            return

        for row in self._rows:
            row.lock()
        self._run_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._output.clear()
        self._say("Assistant", f"Running {len(approved)} approved step(s)…")
        self._engine.run(self._plan, project_id)

    def _cancel(self) -> None:
        self._engine.cancel()
        self._say("Assistant", "Cancelling after the current step…")

    # -- engine callbacks ------------------------------------------------- #
    def _on_step_started(self, index: int) -> None:
        self._rows[index].set_status(StepStatus.RUNNING)
        self._output.appendPlainText(f"\n=== Step {index + 1}: {self._rows[index].step.title} ===")

    def _on_step_output(self, index: int, chunk: str) -> None:
        self._output.moveCursor(QTextCursor.MoveOperation.End)
        self._output.insertPlainText(chunk)

    def _on_step_finished(self, index: int) -> None:
        step = self._rows[index].step
        self._rows[index].set_status(step.status)
        for finding in step.findings:
            self._findings.addItem(f"[{step.tool_key}] {finding}")
        # Explain this step off-thread.
        worker = self._ctx.tasks.submit(self._explainer.explain_step, step)
        worker.signals.result.connect(
            lambda text, t=step.tool_key: self._say("Assistant", f"({t}) {text}"))

    def _on_plan_finished(self) -> None:
        self._cancel_btn.setEnabled(False)
        if self._plan is None:
            return
        worker = self._ctx.tasks.submit(self._explainer.explain_plan, self._plan)
        worker.signals.result.connect(
            lambda text: self._say("Assistant", f"Summary: {text}"))

    # -- helpers ---------------------------------------------------------- #
    def _clear_steps(self) -> None:
        for row in self._rows:
            row.setParent(None)
            row.deleteLater()
        self._rows.clear()
        self._findings.clear()
        self._run_btn.setEnabled(False)

    def _say(self, who: str, message: str) -> None:
        color = "#2f81f7" if who == "You" else "#3fb950"
        safe = (message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        self._conversation.append(
            f'<p><b style="color:{color}">{who}:</b> {safe}</p>')
        self._conversation.moveCursor(QTextCursor.MoveOperation.End)


class WorkflowChatPlugin(PluginBase):
    meta = PluginMeta(
        identifier="workflow_chat",
        title="AI Workflow",
        description="Natural-language security workflows with approval-gated execution.",
        priority=5,
    )

    def create_widget(self) -> QWidget:
        return WorkflowChatWidget(self)


def get_plugin(context) -> WorkflowChatPlugin:  # noqa: ANN001
    return WorkflowChatPlugin(context)
