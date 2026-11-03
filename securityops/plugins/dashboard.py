"""Dashboard plugin: live overview of persisted projects and assessment activity."""

from __future__ import annotations

import sqlite3

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..core.context import AppContext
from ..core.plugins import PluginBase, PluginMeta
from ..dashboard import DashboardService, DashboardSnapshot
from ..models import Scan


class DashboardWidget(QWidget):
    """Display actual database metrics and shortcuts to related feature tabs."""

    def __init__(self, plugin: DashboardPlugin) -> None:
        super().__init__()
        self._ctx = plugin.context
        self._service = DashboardService(
            self._ctx.database,
            installed_tool_count=len(self._ctx.tools.installed()),
            catalog_tool_count=len(self._ctx.tools.all()),
        )
        self._metric_values: dict[str, QLabel] = {}
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.setInterval(5000)
        self._timer.timeout.connect(self.reload)
        self._timer.start()
        self.reload()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        header = QHBoxLayout()
        title = QLabel("Security Operations Dashboard")
        title.setStyleSheet("font-size: 20pt; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.reload)
        header.addWidget(refresh)
        root.addLayout(header)

        subtitle = QLabel("A live summary of records saved on this machine.")
        subtitle.setStyleSheet("color: #8b949e;")
        root.addWidget(subtitle)

        metrics = (
            ("Projects", "projects"),
            ("Assets", "assets"),
            ("Findings", "findings"),
            ("Critical / high", "critical_high"),
            ("Awaiting verification", "verification"),
            ("Active assessments", "active"),
            ("Failed scans", "failed"),
            ("Tools detected", "tools"),
        )
        grid = QGridLayout()
        grid.setSpacing(12)
        for index, (caption, key) in enumerate(metrics):
            card = QWidget()
            card.setObjectName("dashboardCard")
            card.setStyleSheet(
                "QWidget#dashboardCard { background: #161b22; border: 1px solid #30363d; "
                "border-radius: 8px; }"
            )
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 12, 14, 12)
            label = QLabel("---")
            label.setStyleSheet("font-size: 20pt; font-weight: 700; border: none;")
            caption_label = QLabel(caption)
            caption_label.setStyleSheet("color: #8b949e; border: none;")
            card_layout.addWidget(label)
            card_layout.addWidget(caption_label)
            grid.addWidget(card, index // 4, index % 4)
            self._metric_values[key] = label
        root.addLayout(grid)

        shortcuts = QHBoxLayout()
        shortcuts.addWidget(QLabel("Open:"))
        for title, tab_name in (
            ("Quick Scan", "Quick Scan"),
            ("Assets", "Assets"),
            ("Findings", "Findings"),
            ("Scan History", "Scan History"),
            ("Reports", "Reports"),
        ):
            button = QPushButton(title)
            button.clicked.connect(
                lambda _checked=False, name=tab_name: self._open_tab(name)
            )
            shortcuts.addWidget(button)
        shortcuts.addStretch()
        root.addLayout(shortcuts)

        root.addWidget(QLabel("Recent scans"))
        self._error = QLabel("")
        self._error.setStyleSheet("color: #f85149;")
        self._error.setWordWrap(True)
        root.addWidget(self._error)
        self._scans = QTableWidget(0, 4)
        self._scans.setHorizontalHeaderLabels(["Tool", "Target", "Status", "Created"])
        self._scans.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._scans.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._scans.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._scans.setAlternatingRowColors(True)
        root.addWidget(self._scans, stretch=1)

    def reload(self) -> None:
        """Refresh metrics and scans, showing retrieval errors rather than hiding them."""
        try:
            snapshot = self._service.snapshot()
        except (sqlite3.Error, ValueError) as exc:
            self._error.setText(f"Could not load dashboard data: {exc}")
            self._error.setStyleSheet("color: #f85149;")
            return
        self._error.clear()
        self._render_metrics(snapshot)
        self._render_scans(snapshot.recent_scans)

    def _render_metrics(self, snapshot: DashboardSnapshot) -> None:
        values = {
            "projects": snapshot.project_count,
            "assets": snapshot.asset_count,
            "findings": snapshot.finding_count,
            "critical_high": snapshot.critical_high_count,
            "verification": snapshot.awaiting_verification_count,
            "active": snapshot.active_assessment_count,
            "failed": snapshot.failed_scan_count,
            "tools": f"{snapshot.installed_tool_count}/{snapshot.catalog_tool_count}",
        }
        for key, value in values.items():
            self._metric_values[key].setText(str(value))

    def _render_scans(self, scans: tuple[Scan, ...]) -> None:
        self._scans.setRowCount(0)
        for scan in scans:
            row = self._scans.rowCount()
            self._scans.insertRow(row)
            created = scan.created_at.strftime("%Y-%m-%d %H:%M") if scan.created_at else ""
            for column, value in enumerate(
                (scan.tool, scan.target, scan.status.value, created)
            ):
                self._scans.setItem(row, column, QTableWidgetItem(value))
        if not scans:
            self._error.setText("No scans have been recorded yet.")
            self._error.setStyleSheet("color: #8b949e;")
        else:
            self._error.setStyleSheet("color: #f85149;")

    def _open_tab(self, title: str) -> None:
        tabs = self.window().findChild(QTabWidget, "mainTabs")
        if tabs is None:
            return
        for index in range(tabs.count()):
            if tabs.tabText(index) == title:
                tabs.setCurrentIndex(index)
                return


class DashboardPlugin(PluginBase):
    meta = PluginMeta(
        identifier="dashboard",
        title="Dashboard",
        description="Overview of saved projects, findings, scans, and tool availability.",
        priority=0,
    )

    def create_widget(self) -> QWidget:
        return DashboardWidget(self)


def get_plugin(context: AppContext) -> DashboardPlugin:
    return DashboardPlugin(context)
