"""Findings, severity/CVSS, remediation, and evidence collection plugin."""

from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..core import paths
from ..core.plugins import PluginBase, PluginMeta
from ..gui import widgets
from ..models import Confidence, Evidence, Finding, Severity


class FindingsWidget(QWidget):
    def __init__(self, plugin: "FindingsPlugin") -> None:
        super().__init__()
        self._plugin = plugin
        self._ctx = plugin.context
        self._current: Finding | None = None
        self._build_ui()

    # -- UI --------------------------------------------------------------- #
    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter)

        # Left: list + new/delete
        left = QWidget()
        llayout = QVBoxLayout(left)
        llayout.addWidget(widgets.section_label("Findings"))
        self._list = QListWidget()
        self._list.currentItemChanged.connect(self._on_selected)
        llayout.addWidget(self._list, stretch=1)
        lbtns = QHBoxLayout()
        new_btn = QPushButton("New")
        new_btn.setObjectName("primary")
        new_btn.clicked.connect(self._new_finding)
        del_btn = QPushButton("Delete")
        del_btn.clicked.connect(self._delete_finding)
        lbtns.addWidget(new_btn)
        lbtns.addWidget(del_btn)
        llayout.addLayout(lbtns)
        splitter.addWidget(left)

        # Right: editor
        right = QWidget()
        form = QFormLayout(right)
        self._title = QLineEdit()
        self._severity = QComboBox()
        for s in Severity:
            self._severity.addItem(s.value, s)
        self._cvss = QDoubleSpinBox()
        self._cvss.setRange(0.0, 10.0)
        self._cvss.setSingleStep(0.1)
        self._cvss.valueChanged.connect(self._sync_severity_from_cvss)
        self._cvss_vector = QLineEdit()
        self._confidence = QComboBox()
        for cf in Confidence:
            self._confidence.addItem(cf.value, cf)
        self._affected = QLineEdit()
        self._description = QPlainTextEdit()
        self._business = QPlainTextEdit()
        self._business.setPlaceholderText("Business impact (used in disclosure reports)")
        self._reproduction = QPlainTextEdit()
        self._reproduction.setPlaceholderText("Numbered steps to reproduce (for bug bounty reports)")
        self._remediation = QPlainTextEdit()
        self._references = QPlainTextEdit()
        self._references.setPlaceholderText("One reference per line (URLs, CWE, CVE)")

        form.addRow("Title:", self._title)
        form.addRow("Severity:", self._severity)
        form.addRow("Confidence:", self._confidence)
        form.addRow("CVSS score:", self._cvss)
        form.addRow("CVSS vector:", self._cvss_vector)
        form.addRow("Affected asset:", self._affected)
        form.addRow("Description:", self._description)
        form.addRow("Business impact:", self._business)
        form.addRow("Reproduction:", self._reproduction)

        remediation_row = QHBoxLayout()
        remediation_row.addWidget(self._remediation)
        suggest_btn = QPushButton("Suggest")
        suggest_btn.setToolTip("Draft remediation using the offline assistant")
        suggest_btn.clicked.connect(self._suggest_remediation)
        remediation_row.addWidget(suggest_btn)
        form.addRow("Remediation:", remediation_row)
        form.addRow("References:", self._references)

        # Evidence
        self._evidence_list = QListWidget()
        form.addRow("Evidence:", self._evidence_list)
        ev_btns = QHBoxLayout()
        add_shot = QPushButton("Attach screenshot")
        add_shot.clicked.connect(lambda: self._attach_evidence("screenshot"))
        add_file = QPushButton("Attach file")
        add_file.clicked.connect(lambda: self._attach_evidence("file"))
        ev_btns.addWidget(add_shot)
        ev_btns.addWidget(add_file)
        form.addRow("", self._container(ev_btns))

        save_btn = QPushButton("Save finding")
        save_btn.setObjectName("primary")
        save_btn.clicked.connect(self._save)
        form.addRow("", save_btn)

        splitter.addWidget(right)
        splitter.setSizes([300, 700])
        self._set_editing_enabled(False)

    @staticmethod
    def _container(layout) -> QWidget:
        w = QWidget()
        w.setLayout(layout)
        return w

    # -- data ------------------------------------------------------------- #
    def reload(self) -> None:
        self._list.clear()
        self._current = None
        self._set_editing_enabled(False)
        project_id = self._ctx.active_project_id
        if project_id is None:
            return
        for finding in self._ctx.database.findings.list_for_project(project_id):
            item = QListWidgetItem(f"[{finding.severity.value[:4]}] {finding.title}")
            item.setData(Qt.ItemDataRole.UserRole, finding.id)
            item.setForeground(Qt.GlobalColor.white)
            self._list.addItem(item)

    def _on_selected(self, current: QListWidgetItem | None, _prev=None) -> None:
        if current is None or self._ctx.active_project_id is None:
            return
        finding_id = current.data(Qt.ItemDataRole.UserRole)
        findings = {f.id: f for f in self._ctx.database.findings.list_for_project(
            self._ctx.active_project_id)}
        finding = findings.get(finding_id)
        if not finding:
            return
        self._current = finding
        self._title.setText(finding.title)
        self._severity.setCurrentText(finding.severity.value)
        self._cvss.blockSignals(True)
        self._cvss.setValue(finding.cvss_score or 0.0)
        self._cvss.blockSignals(False)
        self._cvss_vector.setText(finding.cvss_vector)
        self._affected.setText(finding.affected_asset)
        self._confidence.setCurrentText(finding.confidence.value)
        self._description.setPlainText(finding.description)
        self._business.setPlainText(finding.business_impact)
        self._reproduction.setPlainText(finding.reproduction)
        self._remediation.setPlainText(finding.remediation)
        self._references.setPlainText(finding.references)
        self._set_editing_enabled(True)
        self._reload_evidence()

    def _reload_evidence(self) -> None:
        self._evidence_list.clear()
        if not self._current or self._current.id is None:
            return
        for ev in self._ctx.database.evidence.list_for_finding(self._current.id):
            label = f"{ev.kind}: {ev.caption or ev.path}"
            self._evidence_list.addItem(label)

    # -- actions ---------------------------------------------------------- #
    def _new_finding(self) -> None:
        project_id = self._ctx.active_project_id
        if project_id is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return
        finding = Finding(project_id=project_id, title="Untitled finding")
        self._ctx.database.findings.create(finding)
        self.reload()
        # select the newly created (first) item
        if self._list.count():
            self._list.setCurrentRow(0)

    def _save(self) -> None:
        if not self._current:
            return
        self._current.title = self._title.text().strip() or "Untitled finding"
        self._current.severity = self._severity.currentData()
        self._current.cvss_score = self._cvss.value() or None
        self._current.cvss_vector = self._cvss_vector.text().strip()
        self._current.affected_asset = self._affected.text().strip()
        self._current.confidence = self._confidence.currentData()
        self._current.description = self._description.toPlainText()
        self._current.business_impact = self._business.toPlainText()
        self._current.reproduction = self._reproduction.toPlainText()
        self._current.remediation = self._remediation.toPlainText()
        self._current.references = self._references.toPlainText()
        self._ctx.database.findings.update(self._current)
        self.reload()
        widgets.info(self, "Saved", "Finding saved.")

    def _delete_finding(self) -> None:
        if not self._current or self._current.id is None:
            return
        if widgets.confirm(self, "Delete finding", f"Delete '{self._current.title}'?"):
            self._ctx.database.findings.delete(self._current.id)
            self.reload()

    def _sync_severity_from_cvss(self, value: float) -> None:
        if value > 0:
            self._severity.setCurrentText(Severity.from_cvss(value).value)

    def _suggest_remediation(self) -> None:
        assistant = self._ctx.assistant
        if assistant is None:
            widgets.warn(self, "Assistant unavailable", "The assistant is disabled.")
            return
        probe = Finding(
            project_id=self._ctx.active_project_id or 0,
            title=self._title.text(),
            description=self._description.toPlainText(),
        )
        self._remediation.setPlainText(assistant.suggest_remediation(probe))

    def _attach_evidence(self, kind: str) -> None:
        if not self._current or self._current.id is None:
            widgets.warn(self, "Save first", "Create/select a finding before attaching evidence.")
            return
        caption = "Screenshot" if kind == "screenshot" else "File"
        filter_ = "Images (*.png *.jpg *.jpeg)" if kind == "screenshot" else "All files (*.*)"
        source, _ = QFileDialog.getOpenFileName(self, f"Select {caption}", "", filter_)
        if not source:
            return
        src = Path(source)
        dest_dir = paths.evidence_dir() / str(self._current.project_id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        try:
            shutil.copy2(src, dest)
        except OSError as exc:
            widgets.warn(self, "Copy failed", str(exc))
            return
        rel = dest.relative_to(paths.evidence_dir())
        evidence = Evidence(
            project_id=self._current.project_id,
            finding_id=self._current.id,
            kind=kind,
            path=str(rel).replace("\\", "/"),
            caption=src.name,
        )
        self._ctx.database.evidence.create(evidence)
        self._reload_evidence()

    def _set_editing_enabled(self, enabled: bool) -> None:
        for w in (self._title, self._severity, self._confidence, self._cvss,
                  self._cvss_vector, self._affected, self._description, self._business,
                  self._reproduction, self._remediation, self._references,
                  self._evidence_list):
            w.setEnabled(enabled)


class FindingsPlugin(PluginBase):
    meta = PluginMeta(
        identifier="findings",
        title="Findings",
        description="Record findings, severity, CVSS, remediation, and evidence.",
        priority=40,
    )

    def create_widget(self) -> QWidget:
        self._widget = FindingsWidget(self)
        return self._widget

    def on_project_changed(self, project_id: int | None) -> None:
        if getattr(self, "_widget", None) is not None:
            self._widget.reload()


def get_plugin(context) -> FindingsPlugin:  # noqa: ANN001
    return FindingsPlugin(context)
