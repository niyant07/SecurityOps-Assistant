"""Reporting plugin: assemble project data and export HTML/PDF/Markdown reports."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core import paths
from ..core.plugins import PluginBase, PluginMeta
from ..gui import widgets
from ..reporting import ReportBundle, ReportFormat, ReportGenerator


class ReportingWidget(QWidget):
    def __init__(self, plugin: "ReportingPlugin") -> None:
        super().__init__()
        self._ctx = plugin.context
        self._generator = ReportGenerator(self._ctx.config.section("reporting"))
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(widgets.section_label("Report Generation"))

        layout.addWidget(QLabel("Executive summary (leave blank to auto-generate):"))
        self._summary = QPlainTextEdit()
        self._summary.setPlaceholderText("Optional executive summary…")
        self._summary.setMaximumHeight(140)
        layout.addWidget(self._summary)

        row = QHBoxLayout()
        self._format = QComboBox()
        self._format.addItem("HTML", ReportFormat.HTML)
        self._format.addItem("Markdown", ReportFormat.MARKDOWN)
        self._format.addItem("PDF (requires WeasyPrint)", ReportFormat.PDF)
        preview_btn = QPushButton("Preview (HTML)")
        preview_btn.clicked.connect(self._preview)
        export_btn = QPushButton("Export…")
        export_btn.setObjectName("primary")
        export_btn.clicked.connect(self._export)
        row.addWidget(QLabel("Format:"))
        row.addWidget(self._format)
        row.addStretch()
        row.addWidget(preview_btn)
        row.addWidget(export_btn)
        layout.addLayout(row)

        self._preview_area = QPlainTextEdit()
        self._preview_area.setReadOnly(True)
        self._preview_area.setStyleSheet("font-family: monospace;")
        layout.addWidget(self._preview_area, stretch=1)

    # -- helpers ---------------------------------------------------------- #
    def _bundle(self) -> ReportBundle | None:
        project_id = self._ctx.active_project_id
        if project_id is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return None
        db = self._ctx.database
        project = db.projects.get(project_id)
        if project is None:
            return None
        summary = self._summary.toPlainText().strip()
        if not summary and self._ctx.assistant is not None:
            summary = self._ctx.assistant.summarize_findings(
                db.findings.list_for_project(project_id))
        return ReportBundle(
            project=project,
            findings=db.findings.list_for_project(project_id),
            assets=db.assets.list_for_project(project_id),
            scans=db.scans.list_for_project(project_id),
            evidence=db.evidence.list_for_project(project_id),
            executive_summary=summary,
        )

    def _preview(self) -> None:
        bundle = self._bundle()
        if bundle is None:
            return
        html = self._generator.render_html(bundle, evidence_root=paths.evidence_dir())
        self._preview_area.setPlainText(html)

    def _export(self) -> None:
        bundle = self._bundle()
        if bundle is None:
            return
        fmt: ReportFormat = self._format.currentData()
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        safe_name = "".join(c if c.isalnum() else "_" for c in bundle.project.name)
        default = str(paths.reports_dir() / f"{safe_name}_{stamp}.{fmt.value}")
        path, _ = QFileDialog.getSaveFileName(self, "Export report", default)
        if not path:
            return
        try:
            written = self._generator.export(
                bundle, __import__("pathlib").Path(path), fmt,
                evidence_root=paths.evidence_dir(),
            )
        except RuntimeError as exc:  # e.g. WeasyPrint missing
            widgets.warn(self, "Export failed", str(exc))
            return
        widgets.info(self, "Report exported", f"Saved to:\n{written}")


class ReportingPlugin(PluginBase):
    meta = PluginMeta(
        identifier="reporting",
        title="Reporting",
        description="Generate HTML/PDF/Markdown assessment reports.",
        priority=60,
    )

    def create_widget(self) -> QWidget:
        return ReportingWidget(self)


def get_plugin(context) -> ReportingPlugin:  # noqa: ANN001
    return ReportingPlugin(context)
