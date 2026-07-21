"""Scan history plugin: browse recorded tool executions and their output."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.plugins import PluginBase, PluginMeta
from ..gui import widgets


class ScansWidget(QWidget):
    def __init__(self, plugin: "ScansPlugin") -> None:
        super().__init__()
        self._ctx = plugin.context
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        header.addWidget(widgets.section_label("Scan History"))
        header.addStretch()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.reload)
        header.addWidget(refresh)
        layout.addLayout(header)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Tool", "Target", "Status", "Exit", "When"])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.itemSelectionChanged.connect(self._show_output)
        splitter.addWidget(self._table)

        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setStyleSheet("font-family: monospace;")
        splitter.addWidget(self._output)
        splitter.setSizes([400, 300])
        layout.addWidget(splitter, stretch=1)

    def reload(self) -> None:
        self._table.setRowCount(0)
        self._output.clear()
        project_id = self._ctx.active_project_id
        if project_id is None:
            return
        self._scans = self._ctx.database.scans.list_for_project(project_id)
        for scan in self._scans:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(scan.tool))
            self._table.setItem(row, 1, QTableWidgetItem(scan.target))
            self._table.setItem(row, 2, QTableWidgetItem(scan.status.value))
            self._table.setItem(row, 3, QTableWidgetItem(
                "" if scan.exit_code is None else str(scan.exit_code)))
            when = scan.created_at.strftime("%Y-%m-%d %H:%M") if scan.created_at else ""
            self._table.setItem(row, 4, QTableWidgetItem(when))

    def _show_output(self) -> None:
        row = self._table.currentRow()
        if row < 0 or row >= len(getattr(self, "_scans", [])):
            return
        scan = self._scans[row]
        self._output.setPlainText(f"$ {scan.command}\n\n{scan.output}")


class ScansPlugin(PluginBase):
    meta = PluginMeta(
        identifier="scans",
        title="Scan History",
        description="Browse recorded tool runs and output.",
        priority=30,
    )

    def create_widget(self) -> QWidget:
        self._widget = ScansWidget(self)
        return self._widget

    def on_project_changed(self, project_id: int | None) -> None:
        if getattr(self, "_widget", None) is not None:
            self._widget.reload()


def get_plugin(context) -> ScansPlugin:  # noqa: ANN001
    return ScansPlugin(context)
