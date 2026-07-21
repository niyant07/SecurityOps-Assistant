"""Main application window.

Hosts a project selector and a tab per discovered plugin. Owns the
:class:`PluginManager`, wires project-change events, and provides the File/Help
menus. Business logic lives in the core/plugins; this class only orchestrates.

The window is designed to be approachable: clear labels and tooltips, keyboard
shortcuts, a first-run welcome, an at-a-glance authorization badge, and a status
bar that always shows what is active.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QComboBox,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QToolBar,
    QWidget,
)

from ..core.context import AppContext
from ..core.logging_config import get_logger
from ..core.plugins import PluginManager
from ..models import Project

_LOG = get_logger("gui.main")

# A short, plain-language hint shown per tab (falls back to the plugin's own
# description). Keys are plugin identifiers.
_TAB_HINTS = {
    "workflow_chat": "Describe a goal in plain English → review a plan → run it safely.",
    "bugbounty": "Import an engagement scope and run an in-scope-only assessment.",
    "disclosure": "Turn findings into a report and prepare a responsible disclosure.",
    "assets": "List your targets and mark what is in or out of scope.",
    "tool_launcher": "Browse detected Kali tools and launch them with one click.",
    "scans": "Review every command that was run and its output.",
    "findings": "Record findings with severity, CVSS, evidence and remediation.",
    "assistant": "Ask the offline assistant about tools, next steps or remediation.",
    "reporting": "Export a professional report as HTML, PDF or Markdown.",
}


class MainWindow(QMainWindow):
    """Top-level window tying core services, plugins, and the project selector."""

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self._ctx = context
        self._plugins = PluginManager(context)

        self.setWindowTitle("SecurityOps Assistant")
        self.resize(1240, 820)
        self.setMinimumSize(960, 640)

        self._project_combo = QComboBox()
        self._project_combo.setMinimumWidth(260)
        self._project_combo.setToolTip("Switch between your assessment projects")
        self._project_combo.currentIndexChanged.connect(self._on_project_selected)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        self._tabs.setMovable(True)
        self.setCentralWidget(self._tabs)

        self._build_toolbar()
        self._build_menu()
        self._build_statusbar()

        self._load_plugins()
        self._reload_projects()
        self._center_on_screen()
        # Defer the welcome until the event loop is running so the window shows first.
        if not self._ctx.database.projects.list():
            self._show_welcome()

    # ------------------------------------------------------------------ #
    # UI construction
    # ------------------------------------------------------------------ #
    def _build_toolbar(self) -> None:
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        label = QLabel("  Project:  ")
        toolbar.addWidget(label)
        toolbar.addWidget(self._project_combo)

        new_btn = QPushButton("＋ New Project")
        new_btn.setObjectName("primary")
        new_btn.setToolTip("Create a new assessment project (Ctrl+N)")
        new_btn.clicked.connect(self._create_project)
        toolbar.addWidget(new_btn)

        self._delete_btn = QPushButton("Delete")
        self._delete_btn.setObjectName("danger")
        self._delete_btn.setToolTip("Delete the active project and all its data")
        self._delete_btn.clicked.connect(self._delete_project)
        toolbar.addWidget(self._delete_btn)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        help_btn = QPushButton("？ Help")
        help_btn.setToolTip("How to use SecurityOps Assistant (F1)")
        help_btn.clicked.connect(self._show_help)
        toolbar.addWidget(help_btn)

    def _build_menu(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("&File")
        act_new = QAction("New Project…", self)
        act_new.setShortcut(QKeySequence.StandardKey.New)  # Ctrl+N
        act_new.triggered.connect(self._create_project)
        file_menu.addAction(act_new)
        act_del = QAction("Delete Project…", self)
        act_del.triggered.connect(self._delete_project)
        file_menu.addAction(act_del)
        file_menu.addSeparator()
        act_quit = QAction("Quit", self)
        act_quit.setShortcut(QKeySequence.StandardKey.Quit)  # Ctrl+Q
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        help_menu = menu.addMenu("&Help")
        act_guide = QAction("Getting Started", self)
        act_guide.setShortcut(QKeySequence(Qt.Key.Key_F1))
        act_guide.triggered.connect(self._show_help)
        help_menu.addAction(act_guide)
        act_about = QAction("About", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    def _build_statusbar(self) -> None:
        # Left: rotating hints / actions. Right: permanent badges.
        self._auth_badge = QLabel("")
        self._status_label = QLabel("No project selected")
        tools = self._ctx.tools.installed()
        self._tools_label = QLabel(f"🛠 {len(tools)} tools detected")
        self._tools_label.setToolTip("Kali tools auto-detected on this system")
        for w in (self._auth_badge, self._status_label, self._tools_label):
            self.statusBar().addPermanentWidget(w)
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
            index = self._tabs.addTab(widget, plugin.meta.title)
            hint = _TAB_HINTS.get(plugin.meta.identifier, plugin.meta.description)
            self._tabs.setTabToolTip(index, hint)

    def _center_on_screen(self) -> None:
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            return
        geo = self.frameGeometry()
        geo.moveCenter(screen.availableGeometry().center())
        self.move(geo.topLeft())

    # ------------------------------------------------------------------ #
    # Project handling
    # ------------------------------------------------------------------ #
    def _reload_projects(self) -> None:
        self._project_combo.blockSignals(True)
        self._project_combo.clear()
        projects = self._ctx.database.projects.list()
        if not projects:
            self._project_combo.addItem("— No projects yet —", None)
        for project in projects:
            self._project_combo.addItem(project.name, project.id)
        self._project_combo.blockSignals(False)
        self._delete_btn.setEnabled(bool(projects))
        self._on_project_selected(self._project_combo.currentIndex())

    def _on_project_selected(self, _index: int) -> None:
        project_id = self._project_combo.currentData()
        self._ctx.set_active_project(project_id)
        self._plugins.notify_project_changed(project_id)
        if project_id is None:
            self._status_label.setText("No project selected")
            self._auth_badge.setText("")
            self.setWindowTitle("SecurityOps Assistant")
            self.statusBar().showMessage("Create a project to begin — click ＋ New Project")
            return
        project = self._ctx.database.projects.get(project_id)
        name = self._project_combo.currentText()
        self._status_label.setText(f"Active: {name}")
        self.setWindowTitle(f"SecurityOps Assistant — {name}")
        if project is not None and project.authorized:
            self._auth_badge.setText("✔ Authorized")
            self._auth_badge.setStyleSheet("color: #3fb950; font-weight: 600;")
        else:
            self._auth_badge.setText("⚠ Not marked authorized")
            self._auth_badge.setStyleSheet("color: #d29922; font-weight: 600;")
        self.statusBar().showMessage(f"Working in “{name}” — authorized use only", 4000)
        _LOG.debug("Active project set to %s", project_id)

    def _create_project(self) -> None:
        name, ok = QInputDialog.getText(self, "New Project", "Project name:")
        if not ok or not name.strip():
            return
        confirm = QMessageBox.question(
            self,
            "Authorization Confirmation",
            "Do you confirm you are authorized to assess the systems in this "
            "project's scope — i.e. you own them or have written permission?\n\n"
            "Choose “No” to still create the project but mark it as not yet authorized.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        project = Project(name=name.strip(),
                          authorized=confirm == QMessageBox.StandardButton.Yes)
        self._ctx.database.projects.create(project)
        self._reload_projects()
        index = self._project_combo.findData(project.id)
        if index >= 0:
            self._project_combo.setCurrentIndex(index)
        self.statusBar().showMessage(f"Created project “{project.name}”", 4000)

    def _delete_project(self) -> None:
        project_id = self._project_combo.currentData()
        if project_id is None:
            QMessageBox.information(self, "No project", "There is no project to delete.")
            return
        name = self._project_combo.currentText()
        confirm = QMessageBox.warning(
            self, "Delete project",
            f"Delete “{name}” and all of its assets, scans, findings, evidence and "
            f"disclosure records?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        self._ctx.database.projects.delete(project_id)
        self._reload_projects()
        self.statusBar().showMessage(f"Deleted project “{name}”", 4000)

    # ------------------------------------------------------------------ #
    # Onboarding / help
    # ------------------------------------------------------------------ #
    def _show_welcome(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle("Welcome to SecurityOps Assistant")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(
            "<b>Welcome!</b> This is an offline assistant for <i>authorized</i> "
            "security assessments.<br><br>"
            "To get started, create a project. Then open the <b>AI Workflow</b> tab "
            "and describe a goal in plain English — for example:<br>"
            "<i>“Find the open ports of my website example.com.”</i><br><br>"
            "Nothing runs until you review and approve it.")
        create = box.addButton("Create a project", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Later", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is create:
            self._create_project()

    def _show_help(self) -> None:
        QMessageBox.information(
            self, "Getting Started",
            "<b>Quick start</b>"
            "<ol>"
            "<li>Click <b>＋ New Project</b> and confirm you are authorized.</li>"
            "<li>Open <b>AI Workflow</b> and type a goal in plain English.</li>"
            "<li>Review the proposed commands and tick the steps to run.</li>"
            "<li>Click <b>Approve &amp; Run</b> — output and findings appear live.</li>"
            "<li>Use <b>Findings</b> and <b>Reporting</b> to record and export results.</li>"
            "</ol>"
            "<b>Tips</b><br>"
            "• Hover any tab to see what it does.<br>"
            "• The <b>Bug Bounty</b> tab enforces an imported scope.<br>"
            "• The <b>Disclosure</b> tab drafts a report and email but never sends "
            "anything for you.<br>"
            "• Everything runs locally — no data leaves your machine.")

    def _show_about(self) -> None:
        from .. import __version__

        QMessageBox.about(
            self,
            "About SecurityOps Assistant",
            f"<b>SecurityOps Assistant</b> v{__version__}<br/>"
            "Offline, local-only assistant for <i>authorized</i> security "
            "assessments.<br/><br/>No cloud services. No telemetry.<br/>"
            "Use only against systems you own or are permitted to test.")

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if self._ctx.tasks.active_count() > 0:
            reply = QMessageBox.question(
                self, "Quit while tasks are running?",
                "A task is still running. Quit and stop it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        _LOG.info("Shutting down")
        self._plugins.shutdown_all()
        self._ctx.tasks.cancel_all()
        self._ctx.database.close()
        super().closeEvent(event)
