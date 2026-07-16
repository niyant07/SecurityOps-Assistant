"""AI Bug Bounty Assistant plugin.

An integrated tab that:

* imports and validates an engagement scope (stored in the shared assets table),
* builds a target-type methodology workflow from a plain-English objective,
* runs approved, scope-validated steps on the shared workflow engine,
* surfaces findings, recommends the next step, and
* generates a bug bounty report (HTML / PDF / Markdown).

It reuses the platform's database, workflow engine, explainer, and reporting.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGroupBox,
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

from ..bugbounty.planner import BugBountyPlanner
from ..bugbounty.report import BugBountyReportBundle, BugBountyReportGenerator
from ..bugbounty.scope import Scope, TargetType, parse_scope_text
from ..core import paths
from ..core.plugins import PluginBase, PluginMeta
from ..gui import widgets
from ..models import Asset, AssetType, ScopeState
from ..workflow.engine import WorkflowEngine
from ..workflow.explain import Explainer
from ..workflow.plan import StepStatus, WorkflowPlan
from ..reporting import ReportFormat
from .workflow_chat import StepRow

_NOTES_HEADER = "# Bug Bounty Engagement"


class BugBountyWidget(QWidget):
    def __init__(self, plugin: "BugBountyPlugin") -> None:
        super().__init__()
        self._ctx = plugin.context
        self._planner = BugBountyPlanner(self._ctx.tools)
        self._explainer = Explainer(llm=self._ctx.llm)
        self._engine = WorkflowEngine(self._ctx)
        self._report_gen = BugBountyReportGenerator(self._ctx.config.section("reporting"))
        self._scope = Scope()
        self._plan: WorkflowPlan | None = None
        self._rows: list[StepRow] = []
        self._completed_tools: list[str] = []

        self._wire_engine()
        self._build_ui()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        header = QHBoxLayout()
        header.addWidget(widgets.section_label("AI Bug Bounty Assistant"))
        header.addStretch()
        note = QLabel("Authorized, in-scope targets only")
        note.setStyleSheet("color: #d29922;")
        header.addWidget(note)
        root.addLayout(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---- left column ---- #
        left = QWidget()
        lcol = QVBoxLayout(left)

        eng = QGroupBox("Engagement & scope")
        eng_l = QVBoxLayout(eng)
        meta_row = QHBoxLayout()
        self._program = QLineEdit(); self._program.setPlaceholderText("Program name")
        self._platform = QLineEdit(); self._platform.setPlaceholderText("Platform (HackerOne, self-owned…)")
        self._ttype = QComboBox()
        for t in TargetType:
            self._ttype.addItem(t.value, t)
        meta_row.addWidget(self._program)
        meta_row.addWidget(self._platform)
        meta_row.addWidget(self._ttype)
        eng_l.addLayout(meta_row)

        self._scope_text = QPlainTextEdit()
        self._scope_text.setPlaceholderText(
            "Paste scope. Optional headers:\nIn scope:\n- *.example.com\nOut of scope:\n- admin.example.com\nRules:\n- ...")
        self._scope_text.setMaximumHeight(120)
        eng_l.addWidget(self._scope_text)

        import_row = QHBoxLayout()
        import_btn = QPushButton("Import & validate scope")
        import_btn.setObjectName("primary")
        import_btn.clicked.connect(self._import_scope)
        import_row.addWidget(import_btn)
        import_row.addStretch()
        eng_l.addLayout(import_row)
        self._scope_status = QLabel("No scope imported.")
        self._scope_status.setWordWrap(True)
        self._scope_status.setStyleSheet("color: #8b949e;")
        eng_l.addWidget(self._scope_status)
        lcol.addWidget(eng)

        # objective + conversation
        self._conversation = QTextBrowser()
        self._conversation.setMaximumHeight(130)
        lcol.addWidget(self._conversation)

        obj_row = QHBoxLayout()
        self._objective = QLineEdit()
        self._objective.setPlaceholderText(
            "Objective, e.g. Assess this web application for common security issues")
        self._objective.returnPressed.connect(self._build_workflow)
        build_btn = QPushButton("Build Workflow")
        build_btn.clicked.connect(self._build_workflow)
        obj_row.addWidget(self._objective, stretch=1)
        obj_row.addWidget(build_btn)
        lcol.addLayout(obj_row)

        self._steps_container = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_container)
        self._steps_layout.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._steps_container)
        lcol.addWidget(scroll, stretch=1)

        ctrl = QHBoxLayout()
        self._run_btn = QPushButton("Approve & Run"); self._run_btn.setObjectName("primary")
        self._run_btn.clicked.connect(self._approve_and_run); self._run_btn.setEnabled(False)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.clicked.connect(lambda: self._engine.cancel()); self._cancel_btn.setEnabled(False)
        self._next_btn = QPushButton("Recommend next")
        self._next_btn.clicked.connect(self._recommend_next)
        self._report_btn = QPushButton("Generate report")
        self._report_btn.clicked.connect(self._generate_report)
        for b in (self._run_btn, self._cancel_btn, self._next_btn, self._report_btn):
            ctrl.addWidget(b)
        lcol.addLayout(ctrl)
        splitter.addWidget(left)

        # ---- right column ---- #
        right = QWidget()
        rcol = QVBoxLayout(right)
        rcol.addWidget(QLabel("Live output"))
        self._output = QPlainTextEdit(); self._output.setReadOnly(True)
        self._output.setStyleSheet("font-family: monospace;")
        rcol.addWidget(self._output, stretch=2)
        rcol.addWidget(QLabel("Findings dashboard"))
        self._findings = QListWidget()
        rcol.addWidget(self._findings, stretch=1)
        splitter.addWidget(right)

        splitter.setSizes([680, 460])
        root.addWidget(splitter, stretch=1)

    def _wire_engine(self) -> None:
        self._engine.step_started.connect(self._on_step_started)
        self._engine.step_output.connect(self._on_step_output)
        self._engine.step_finished.connect(self._on_step_finished)
        self._engine.plan_finished.connect(self._on_plan_finished)
        self._engine.audit.connect(lambda line: self._output.appendPlainText(line))

    # ------------------------------------------------------------------ #
    # Scope import / persistence
    # ------------------------------------------------------------------ #
    def _import_scope(self) -> None:
        project_id = self._ctx.active_project_id
        if project_id is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return
        scope = parse_scope_text(self._scope_text.toPlainText())
        scope.program = self._program.text().strip()
        scope.platform = self._platform.text().strip()
        scope.target_type = self._ttype.currentData()
        if scope.is_empty():
            widgets.warn(self, "Empty scope", "Add at least one in-scope asset.")
            return
        self._scope = scope
        self._persist_scope(project_id, scope)
        self._scope_status.setText(
            f"Imported: {len(scope.in_scope)} in-scope, {len(scope.out_of_scope)} out-of-scope. "
            f"Assets saved to the project.")
        self._scope_status.setStyleSheet("color: #3fb950;")
        self._say("Assistant",
                  f"Scope imported for {scope.program or 'engagement'} "
                  f"({scope.target_type.value}). Enter an objective to build a workflow.")

    def _persist_scope(self, project_id: int, scope: Scope) -> None:
        """Save scope assets to the shared assets table and metadata to scope_notes."""
        db = self._ctx.database
        existing = {a.identifier for a in db.assets.list_for_project(project_id)}
        for ident in scope.in_scope:
            if ident not in existing:
                db.assets.create(Asset(project_id=project_id, identifier=ident,
                                       asset_type=self._asset_type(scope.target_type),
                                       scope=ScopeState.IN_SCOPE, label="bug-bounty"))
        for ident in scope.out_of_scope:
            if ident not in existing:
                db.assets.create(Asset(project_id=project_id, identifier=ident,
                                       asset_type=self._asset_type(scope.target_type),
                                       scope=ScopeState.OUT_OF_SCOPE, label="bug-bounty"))
        project = db.projects.get(project_id)
        if project is not None:
            project.scope_notes = self._scope_to_notes(scope)
            db.projects.update(project)

    @staticmethod
    def _asset_type(t: TargetType) -> AssetType:
        return {
            TargetType.WEB: AssetType.WEB_APP,
            TargetType.API: AssetType.URL,
            TargetType.MOBILE_BACKEND: AssetType.URL,
            TargetType.DESKTOP: AssetType.HOST,
            TargetType.NETWORK: AssetType.NETWORK,
        }.get(t, AssetType.OTHER)

    @staticmethod
    def _scope_to_notes(scope: Scope) -> str:
        return (f"{_NOTES_HEADER}\nProgram: {scope.program}\nPlatform: {scope.platform}\n"
                f"Target-Type: {scope.target_type.value}\n\n{scope.rules}").strip()

    def _load_scope_from_project(self, project_id: int) -> None:
        """Rebuild the in-memory scope from the project's assets + notes header."""
        db = self._ctx.database
        assets = db.assets.list_for_project(project_id)
        project = db.projects.get(project_id)
        scope = Scope()
        scope.in_scope = [a.identifier for a in assets if a.scope == ScopeState.IN_SCOPE]
        scope.out_of_scope = [a.identifier for a in assets if a.scope == ScopeState.OUT_OF_SCOPE]
        if project and project.scope_notes.startswith(_NOTES_HEADER):
            for line in project.scope_notes.splitlines():
                if line.startswith("Program:"):
                    scope.program = line.split(":", 1)[1].strip()
                elif line.startswith("Platform:"):
                    scope.platform = line.split(":", 1)[1].strip()
                elif line.startswith("Target-Type:"):
                    val = line.split(":", 1)[1].strip()
                    for t in TargetType:
                        if t.value == val:
                            scope.target_type = t
            body = project.scope_notes.split("\n\n", 1)
            scope.rules = body[1].strip() if len(body) > 1 else ""
        self._scope = scope
        if scope.in_scope:
            self._program.setText(scope.program)
            self._platform.setText(scope.platform)
            idx = self._ttype.findData(scope.target_type)
            if idx >= 0:
                self._ttype.setCurrentIndex(idx)
            self._scope_status.setText(
                f"Loaded scope: {len(scope.in_scope)} in-scope, "
                f"{len(scope.out_of_scope)} out-of-scope.")
            self._scope_status.setStyleSheet("color: #3fb950;")

    # ------------------------------------------------------------------ #
    # Workflow build / run
    # ------------------------------------------------------------------ #
    def _build_workflow(self) -> None:
        goal = self._objective.text().strip()
        if not goal:
            return
        if self._scope.is_empty():
            widgets.warn(self, "No scope", "Import an engagement scope first.")
            return
        if self._engine.is_running():
            widgets.warn(self, "Busy", "A workflow is already running.")
            return
        self._say("You", goal)
        self._clear_steps()
        worker = self._ctx.tasks.submit(self._planner.plan, goal, self._scope)
        worker.signals.result.connect(self._on_plan_ready)
        worker.signals.error.connect(
            lambda m: self._say("Assistant", f"Planning failed: {m.splitlines()[0]}"))

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

    def _approve_and_run(self) -> None:
        if self._plan is None:
            return
        project_id = self._ctx.active_project_id
        if project_id is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return
        approved = []
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
        if not widgets.confirm(self, "Confirm execution",
                               f"Run {len(approved)} approved, in-scope command(s)?\n\n{listing}"):
            return
        for row in self._rows:
            row.lock()
        self._run_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._output.clear()
        self._engine.run(self._plan, project_id)

    # ------------------------------------------------------------------ #
    # Engine callbacks
    # ------------------------------------------------------------------ #
    def _on_step_started(self, index: int) -> None:
        self._rows[index].set_status(StepStatus.RUNNING)
        self._output.appendPlainText(f"\n=== Step {index + 1}: {self._rows[index].step.title} ===")

    def _on_step_output(self, index: int, chunk: str) -> None:
        self._output.moveCursor(QTextCursor.MoveOperation.End)
        self._output.insertPlainText(chunk)

    def _on_step_finished(self, index: int) -> None:
        step = self._rows[index].step
        self._rows[index].set_status(step.status)
        if step.status == StepStatus.COMPLETED:
            self._completed_tools.append(step.tool_key)
        for f in step.findings:
            self._findings.addItem(f"[{step.tool_key}] {f}")
        worker = self._ctx.tasks.submit(self._explainer.explain_step, step)
        worker.signals.result.connect(
            lambda t, k=step.tool_key: self._say("Assistant", f"({k}) {t}"))

    def _on_plan_finished(self) -> None:
        self._cancel_btn.setEnabled(False)
        if self._plan is not None:
            worker = self._ctx.tasks.submit(self._explainer.explain_plan, self._plan)
            worker.signals.result.connect(lambda t: self._say("Assistant", f"Summary: {t}"))
        self._recommend_next()

    # ------------------------------------------------------------------ #
    # Recommend next / report
    # ------------------------------------------------------------------ #
    def _recommend_next(self) -> None:
        if self._scope.is_empty():
            return
        rec = self._planner.recommend_next(self._scope, self._completed_tools)
        self._say("Assistant", f"Next step: {rec}")

    def _generate_report(self) -> None:
        project_id = self._ctx.active_project_id
        if project_id is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return
        db = self._ctx.database
        project = db.projects.get(project_id)
        if project is None:
            return
        findings = db.findings.list_for_project(project_id)
        summary = ""
        if self._ctx.assistant is not None:
            summary = self._ctx.assistant.summarize_findings(findings)
        bundle = BugBountyReportBundle(
            project=project, scope=self._scope, findings=findings,
            assets=db.assets.list_for_project(project_id),
            scans=db.scans.list_for_project(project_id),
            evidence=db.evidence.list_for_project(project_id),
            executive_summary=summary,
        )
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        safe = "".join(c if c.isalnum() else "_" for c in (self._scope.program or project.name))
        default = str(paths.reports_dir() / f"bugbounty_{safe}_{stamp}.html")
        path, _ = QFileDialog.getSaveFileName(self, "Export bug bounty report", default)
        if not path:
            return
        fmt = {".pdf": ReportFormat.PDF, ".md": ReportFormat.MARKDOWN}.get(
            Path(path).suffix.lower(), ReportFormat.HTML)
        try:
            written = self._report_gen.export(bundle, Path(path), fmt,
                                              evidence_root=paths.evidence_dir())
        except RuntimeError as exc:
            widgets.warn(self, "Export failed", str(exc))
            return
        widgets.info(self, "Report exported", f"Saved to:\n{written}")

    # ------------------------------------------------------------------ #
    def reload(self) -> None:
        self._clear_steps()
        self._completed_tools.clear()
        self._scope = Scope()
        self._program.clear(); self._platform.clear()
        self._scope_status.setText("No scope imported.")
        self._scope_status.setStyleSheet("color: #8b949e;")
        pid = self._ctx.active_project_id
        if pid is not None:
            self._load_scope_from_project(pid)

    def _clear_steps(self) -> None:
        for row in self._rows:
            row.setParent(None)
            row.deleteLater()
        self._rows.clear()
        self._findings.clear()
        self._run_btn.setEnabled(False)

    def _say(self, who: str, message: str) -> None:
        color = "#2f81f7" if who == "You" else "#3fb950"
        safe = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self._conversation.append(f'<p><b style="color:{color}">{who}:</b> {safe}</p>')
        self._conversation.moveCursor(QTextCursor.MoveOperation.End)


class BugBountyPlugin(PluginBase):
    meta = PluginMeta(
        identifier="bugbounty",
        title="Bug Bounty",
        description="Scope-validated, methodology-driven bug bounty assessments.",
        priority=8,
    )

    def create_widget(self) -> QWidget:
        self._widget = BugBountyWidget(self)
        return self._widget

    def on_project_changed(self, project_id: int | None) -> None:
        if getattr(self, "_widget", None) is not None:
            self._widget.reload()


def get_plugin(context) -> BugBountyPlugin:  # noqa: ANN001
    return BugBountyPlugin(context)
