"""Quick Scan plugin — the friendliest entry point into the platform.

Paste a link → confirm you're authorized → one click → get a vulnerability
report. This tab hides the underlying project/plan/approve machinery behind a
single linear flow, while reusing exactly the same safety-tested components as
every other tab:

* the shared planner builds a conservative recon+enumeration+vuln-scan plan
  (never sqlmap/gobuster/ffuf brute-force, since the goal never asks for them),
* the operator still sees the exact commands and must explicitly confirm
  before anything executes,
* the shared background engine runs approved steps and streams output,
* the shared bug-bounty triage engine correlates raw output into findings,
* the shared report generator produces the deliverable, saved straight to the
  user's Downloads folder.

If no project is active, one is created automatically (named after the target)
so a first-time user never has to understand "projects" to get a report.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtGui import QColor, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..bugbounty.triage import triage_findings
from ..core import paths
from ..core.plugins import PluginBase, PluginMeta
from ..gui import widgets
from ..models import Project
from ..reporting import ReportBundle, ReportFormat, ReportGenerator
from ..workflow.engine import WorkflowEngine
from ..workflow.explain import Explainer
from ..workflow.plan import StepStatus, WorkflowPlan
from ..workflow.planner import extract_target, make_planner

_SEVERITY_COLORS = {
    "Critical": "#f85149", "High": "#db6d28", "Medium": "#d29922",
    "Low": "#3fb950", "Informational": "#6c8ebf",
}


class QuickScanWidget(QWidget):
    def __init__(self, plugin: "QuickScanPlugin") -> None:
        super().__init__()
        self._ctx = plugin.context
        self._planner = make_planner(self._ctx.tools, llm=self._ctx.llm)
        self._explainer = Explainer(llm=self._ctx.llm)
        self._engine = WorkflowEngine(self._ctx)
        self._report_gen = ReportGenerator(self._ctx.config.section("reporting"))
        self._plan: WorkflowPlan | None = None
        self._project_id: int | None = None
        self._scanning = False

        self._wire_engine()
        self._build_ui()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(10)

        title = QLabel("Quick Scan")
        title.setStyleSheet("font-size: 18pt; font-weight: 700;")
        root.addWidget(title)
        subtitle = QLabel(
            "Paste a website or host, confirm you're authorized to test it, "
            "and get a vulnerability report — automatically saved to Downloads.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #8b949e;")
        root.addWidget(subtitle)

        # -- input row -- #
        self._url = QLineEdit()
        self._url.setPlaceholderText("https://example.com  or  example.com  or  10.0.0.5")
        self._url.setMinimumHeight(38)
        self._url.textChanged.connect(self._update_scan_enabled)
        self._url.returnPressed.connect(self._scan_now)
        root.addWidget(self._url)

        self._authorized = QCheckBox(
            "I own this website/system, or I have explicit written permission to test it.")
        self._authorized.toggled.connect(self._update_scan_enabled)
        root.addWidget(self._authorized)

        btn_row = QHBoxLayout()
        self._scan_btn = QPushButton("🔍  Scan Now")
        self._scan_btn.setObjectName("primary")
        self._scan_btn.setMinimumHeight(38)
        self._scan_btn.setEnabled(False)
        self._scan_btn.clicked.connect(self._scan_now)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel_scan)
        btn_row.addWidget(self._scan_btn, stretch=1)
        btn_row.addWidget(self._cancel_btn)
        root.addLayout(btn_row)

        # -- status / progress -- #
        self._status = QLabel("")
        self._status.setStyleSheet("color: #8b949e;")
        root.addWidget(self._status)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.setVisible(False)
        self._progress.setTextVisible(False)
        self._progress.setMaximumHeight(6)
        root.addWidget(self._progress)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setStyleSheet("font-family: monospace;")
        self._log.setVisible(False)
        self._log.setMaximumHeight(160)
        root.addWidget(self._log)

        # -- results -- #
        self._results_label = QLabel("")
        self._results_label.setStyleSheet("font-size: 12pt; font-weight: 600;")
        self._results_label.setVisible(False)
        root.addWidget(self._results_label)

        self._summary_text = QLabel("")
        self._summary_text.setWordWrap(True)
        self._summary_text.setVisible(False)
        root.addWidget(self._summary_text)

        self._findings_list = QListWidget()
        self._findings_list.setVisible(False)
        root.addWidget(self._findings_list, stretch=1)

        self._download_btn = QPushButton("⬇  Download Report")
        self._download_btn.setObjectName("primary")
        self._download_btn.setMinimumHeight(38)
        self._download_btn.setVisible(False)
        self._download_btn.clicked.connect(self._download_report)
        root.addWidget(self._download_btn)

        root.addStretch()

    def _wire_engine(self) -> None:
        self._engine.step_started.connect(self._on_step_started)
        self._engine.step_output.connect(self._on_step_output)
        self._engine.step_finished.connect(self._on_step_finished)
        self._engine.plan_finished.connect(self._on_plan_finished)
        self._engine.audit.connect(lambda line: self._append_log(line))

    def _update_scan_enabled(self) -> None:
        self._scan_btn.setEnabled(
            bool(self._url.text().strip()) and self._authorized.isChecked()
            and not self._scanning)

    # ------------------------------------------------------------------ #
    # Scan flow
    # ------------------------------------------------------------------ #
    def _scan_now(self) -> None:
        if self._scanning:
            return
        raw = self._url.text().strip()
        target = extract_target(raw)
        if target is None:
            widgets.warn(self, "Enter a valid target",
                        "Enter a URL or hostname, e.g. https://example.com or example.com.")
            return
        if not self._authorized.isChecked():
            widgets.warn(self, "Authorization required",
                        "Confirm you own this system or have written permission to test it.")
            return

        project_id = self._ensure_project(target.raw)
        if project_id is None:
            return
        self._project_id = project_id

        self._reset_results()
        self._status.setText(f"Building a scan plan for {target.display}…")
        goal = f"assess {raw} for common security issues"
        worker = self._ctx.tasks.submit(self._planner.plan, goal)
        worker.signals.result.connect(self._on_plan_ready)
        worker.signals.error.connect(
            lambda m: self._status.setText(f"Could not build a plan: {m.splitlines()[0]}"))

    def _ensure_project(self, target_raw: str) -> int | None:
        """Reuse the active project, or silently create one for this target."""
        if self._ctx.active_project_id is not None:
            return self._ctx.active_project_id
        project = self._ctx.database.projects.create(
            Project(name=f"Quick Scan: {target_raw}", authorized=True))
        self._ctx.set_active_project(project.id)
        window = self.window()
        if hasattr(window, "refresh_projects"):
            window.refresh_projects(project.id)  # keep the toolbar in sync
        return project.id

    def _on_plan_ready(self, plan: WorkflowPlan) -> None:
        if plan.refused:
            self._status.setText(f"⛔ {plan.refusal_reason}")
            return
        if not plan.steps:
            self._status.setText(plan.summary)
            return

        listing = "\n".join(f"• {s.command}" for s in plan.steps)
        warnings = "\n".join(f"⚠ {s.warning}" for s in plan.steps if s.warning)
        text = f"Run the following {len(plan.steps)} command(s) against your target?\n\n{listing}"
        if warnings:
            text += f"\n\n{warnings}"
        if not widgets.confirm(self, "Confirm scan", text):
            self._status.setText("Scan cancelled.")
            return

        for step in plan.steps:
            step.status = StepStatus.APPROVED
        self._plan = plan

        self._scanning = True
        self._update_scan_enabled()
        self._cancel_btn.setEnabled(True)
        self._progress.setVisible(True)
        self._log.setVisible(True)
        self._log.clear()
        self._status.setText(f"Scanning… (0/{len(plan.steps)} steps)")
        self._engine.run(plan, self._project_id)

    def _cancel_scan(self) -> None:
        self._engine.cancel()
        self._status.setText("Cancelling after the current step…")
        self._cancel_btn.setEnabled(False)

    # ------------------------------------------------------------------ #
    # Engine callbacks
    # ------------------------------------------------------------------ #
    def _on_step_started(self, index: int) -> None:
        if self._plan is None:
            return
        total = len(self._plan.steps)
        step = self._plan.steps[index]
        self._status.setText(f"Scanning… ({index + 1}/{total}) running {step.tool_key}")
        self._append_log(f"\n=== {step.title} ===")

    def _on_step_output(self, _index: int, chunk: str) -> None:
        self._log.moveCursor(QTextCursor.MoveOperation.End)
        self._log.insertPlainText(chunk)

    def _on_step_finished(self, _index: int) -> None:
        pass  # progress text is driven by _on_step_started / _on_plan_finished

    def _on_plan_finished(self) -> None:
        self._scanning = False
        self._cancel_btn.setEnabled(False)
        self._progress.setVisible(False)
        self._update_scan_enabled()
        if self._plan is None or self._project_id is None:
            return

        candidates = triage_findings(self._plan.steps)
        for cand in candidates:
            self._ctx.database.findings.create(cand.to_finding(self._project_id))

        self._status.setText("Scan complete.")
        self._show_results(candidates)

        worker = self._ctx.tasks.submit(self._explainer.explain_plan, self._plan)
        worker.signals.result.connect(
            lambda text: self._summary_text.setText(text))

    def _show_results(self, candidates: list) -> None:  # noqa: ANN401 - list[Candidate]
        counts: dict[str, int] = {}
        for c in candidates:
            counts[c.severity.value] = counts.get(c.severity.value, 0) + 1
        order = ["Critical", "High", "Medium", "Low", "Informational"]
        summary_parts = [f"{counts[s]} {s}" for s in order if s in counts]

        if candidates:
            self._results_label.setText(
                f"Found {len(candidates)} item(s) to review: " + ", ".join(summary_parts))
        else:
            self._results_label.setText("Scan finished — nothing notable was flagged.")
        self._results_label.setVisible(True)
        self._summary_text.setVisible(True)

        self._findings_list.clear()
        for c in candidates:
            color = _SEVERITY_COLORS.get(c.severity.value, "#8b949e")
            item_text = f"[{c.severity.value}] {c.title}"
            self._findings_list.addItem(item_text)
            last = self._findings_list.item(self._findings_list.count() - 1)
            last.setForeground(QColor(color))
            last.setToolTip(c.description)
        self._findings_list.setVisible(bool(candidates))
        self._download_btn.setVisible(True)

    # ------------------------------------------------------------------ #
    # Report download
    # ------------------------------------------------------------------ #
    def _download_report(self) -> None:
        if self._project_id is None:
            return
        db = self._ctx.database
        project = db.projects.get(self._project_id)
        if project is None:
            return
        findings = db.findings.list_for_project(self._project_id)
        summary = ""
        if self._ctx.assistant is not None:
            summary = self._ctx.assistant.summarize_findings(findings)
        bundle = ReportBundle(
            project=project, findings=findings,
            assets=db.assets.list_for_project(self._project_id),
            scans=db.scans.list_for_project(self._project_id),
            evidence=db.evidence.list_for_project(self._project_id),
            executive_summary=summary,
        )
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        safe = "".join(c if c.isalnum() else "_" for c in project.name)
        target = paths.downloads_dir() / f"{safe}_{stamp}.html"
        try:
            written = self._report_gen.export(
                bundle, target, ReportFormat.HTML, evidence_root=paths.evidence_dir())
        except RuntimeError as exc:
            widgets.warn(self, "Download failed", str(exc))
            return
        widgets.info(self, "Report downloaded", f"Saved to your Downloads folder:\n{written}")

    # ------------------------------------------------------------------ #
    def _append_log(self, line: str) -> None:
        self._log.appendPlainText(line)

    def _reset_results(self) -> None:
        self._results_label.setVisible(False)
        self._summary_text.setVisible(False)
        self._summary_text.setText("")
        self._findings_list.clear()
        self._findings_list.setVisible(False)
        self._download_btn.setVisible(False)


class QuickScanPlugin(PluginBase):
    meta = PluginMeta(
        identifier="quick_scan",
        title="Quick Scan",
        description="Paste a link, confirm authorization, and get a vulnerability report.",
        priority=1,
    )

    def create_widget(self) -> QWidget:
        return QuickScanWidget(self)


def get_plugin(context) -> QuickScanPlugin:  # noqa: ANN001
    return QuickScanPlugin(context)
