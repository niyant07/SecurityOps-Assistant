"""Main application window.

Hosts a project selector and a tab per discovered plugin. Owns the
:class:`PluginManager`, wires project-change events, and provides the File/Help
menus. Business logic lives in the core/plugins; this class only orchestrates.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QComboBox,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QTabWidget,
    QToolBar,
    QWidget,
)

from ..core.context import AppContext
from ..core.logging_config import get_logger
from ..core.plugins import PluginManager
from ..models import Project

_LOG = get_logger("gui.main")


class MainWindow(QMainWindow):
    """Top-level window tying core services, plugins, and the project selector."""

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self._ctx = context
        self._plugins = PluginManager(context)

        self.setWindowTitle("SecurityOps Assistant")
        self.resize(1200, 800)

        self._project_combo = QComboBox()
        self._project_combo.setMinimumWidth(260)
        self._project_combo.currentIndexChanged.connect(self._on_project_selected)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        self.setCentralWidget(self._tabs)

        self._build_toolbar()
        self._build_menu()
        self._build_statusbar()

        self._load_plugins()
        self._reload_projects()

    # ------------------------------------------------------------------ #
    # UI construction
    # ------------------------------------------------------------------ #
    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        toolbar.addWidget(QLabel("  Project: "))
        toolbar.addWidget(self._project_combo)

        new_project = QAction("New Project", self)
        new_project.triggered.connect(self._create_project)
        toolbar.addAction(new_project)

    def _build_menu(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("&File")
        act_new = QAction("New Project…", self)
        act_new.triggered.connect(self._create_project)
        file_menu.addAction(act_new)
        file_menu.addSeparator()
        act_quit = QAction("Quit", self)
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        help_menu = menu.addMenu("&Help")
        act_about = QAction("About", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    def _build_statusbar(self) -> None:
        self._status_label = QLabel("No project selected")
        self.statusBar().addPermanentWidget(self._status_label)
        self.statusBar().showMessage("Ready — authorized use only")

    def _load_plugins(self) -> None:
        for plugin in self._plugins.discover():
            try:
                widget: QWidget = plugin.create_widget()
            except Exception as exc:  # noqa: BLE001 - isolate faulty plugins
                _LOG.exception("Plugin %s failed to build widget", plugin.meta.identifier)
                placeholder = QLabel(f"Plugin '{plugin.meta.title}' failed to load:\n{exc}")
                placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
                widget = placeholder
            self._tabs.addTab(widget, plugin.meta.title)

    # ------------------------------------------------------------------ #
    # Project handling
    # ------------------------------------------------------------------ #
    def _reload_projects(self) -> None:
        self._project_combo.blockSignals(True)
        self._project_combo.clear()
        projects = self._ctx.database.projects.list()
        if not projects:
            self._project_combo.addItem("— No projects —", None)
        for project in projects:
            self._project_combo.addItem(project.name, project.id)
        self._project_combo.blockSignals(False)
        self._on_project_selected(self._project_combo.currentIndex())

    def _on_project_selected(self, _index: int) -> None:
        project_id = self._project_combo.currentData()
        self._ctx.set_active_project(project_id)
        self._plugins.notify_project_changed(project_id)
        if project_id is None:
            self._status_label.setText("No project selected")
        else:
            name = self._project_combo.currentText()
            self._status_label.setText(f"Active project: {name} (#{project_id})")
        _LOG.debug("Active project set to %s", project_id)

    def _create_project(self) -> None:
        name, ok = QInputDialog.getText(self, "New Project", "Project name:")
        if not ok or not name.strip():
            return
        confirm = QMessageBox.question(
            self,
            "Authorization Confirmation",
            "Confirm you are authorized to assess the systems in this project's "
            "scope (you own them or have written permission).",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        project = Project(name=name.strip(), authorized=confirm == QMessageBox.StandardButton.Yes)
        self._ctx.database.projects.create(project)
        self._reload_projects()
        index = self._project_combo.findData(project.id)
        if index >= 0:
            self._project_combo.setCurrentIndex(index)

    # ------------------------------------------------------------------ #
    # Misc
    # ------------------------------------------------------------------ #
    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About SecurityOps Assistant",
            "<b>SecurityOps Assistant</b><br/>"
            "Offline, local-only assistant for <i>authorized</i> security "
            "assessments.<br/><br/>No cloud services. No telemetry.<br/>"
            "Use only against systems you own or are permitted to test.",
        )

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        _LOG.info("Shutting down")
        self._plugins.shutdown_all()
        self._ctx.tasks.cancel_all()
        self._ctx.database.close()
        super().closeEvent(event)
