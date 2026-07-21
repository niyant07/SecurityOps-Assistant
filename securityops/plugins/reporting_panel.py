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
        download_btn = QPushButton("⬇ Download to Downloads")
        download_btn.setObjectName("primary")
        download_btn.setToolTip("Save the report straight to your Downloads folder")
        download_btn.clicked.connect(self._download)
        export_btn = QPushButton("Save as…")
        export_btn.setToolTip("Choose where to save the report")
        export_btn.clicked.connect(self._export)
        row.addWidget(QLabel("Format:"))
        row.addWidget(self._format)
        row.addStretch()
        row.addWidget(preview_btn)
        row.addWidget(export_btn)
        row.addWidget(download_btn)
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

    def _filename(self, bundle: ReportBundle, fmt: ReportFormat) -> str:
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        safe_name = "".join(c if c.isalnum() else "_" for c in bundle.project.name)
        return f"{safe_name}_{stamp}.{fmt.value}"

    def _download(self) -> None:
        """One-click export straight into the user's Downloads folder."""
        bundle = self._bundle()
        if bundle is None:
            return
        fmt: ReportFormat = self._format.currentData()
        target = paths.downloads_dir() / self._filename(bundle, fmt)
        try:
            written = self._generator.export(
                bundle, target, fmt, evidence_root=paths.evidence_dir())
        except RuntimeError as exc:  # e.g. WeasyPrint missing
            widgets.warn(self, "Download failed", str(exc))
            return
        widgets.info(self, "Report downloaded", f"Saved to your Downloads folder:\n{written}")

    def _export(self) -> None:
        from pathlib import Path

        bundle = self._bundle()
        if bundle is None:
            return
        fmt: ReportFormat = self._format.currentData()
        default = str(paths.downloads_dir() / self._filename(bundle, fmt))
        path, _ = QFileDialog.getSaveFileName(self, "Save report", default)
        if not path:
            return
        try:
            written = self._generator.export(
                bundle, Path(path), fmt, evidence_root=paths.evidence_dir())
        except RuntimeError as exc:  # e.g. WeasyPrint missing
            widgets.warn(self, "Export failed", str(exc))
            return
        widgets.info(self, "Report saved", f"Saved to:\n{written}")


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
