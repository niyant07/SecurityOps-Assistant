"""Tool launcher plugin.

Lists auto-detected Kali tools grouped by category, lets the operator select a
target and parameters, builds a *review-only* command, and — on an explicit
Launch click — runs it. Non-interactive tools stream output into the panel and
are recorded in scan history; interactive tools (Burp, msfconsole, Wireshark,
crackers) are opened in a terminal emulator.
"""

from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.plugins import PluginBase, PluginMeta
from ..core.tasks import CommandRunner
from ..core.tools import DetectedTool, MissingParameterError, ToolRegistry
from ..gui import widgets
from ..models import Scan, ScanStatus


class ToolLauncherWidget(QWidget):
    """The tool-launcher tab UI."""

    def __init__(self, plugin: "ToolLauncherPlugin") -> None:
        super().__init__()
        self._plugin = plugin
        self._ctx = plugin.context
        self._registry: ToolRegistry = self._ctx.tools
        self._current: DetectedTool | None = None
        self._runner: CommandRunner | None = None

        self._build_ui()
        self._populate_tree()

    # -- UI --------------------------------------------------------------- #
    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter)

        # Left: tool tree
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Tool", "Status"])
        self._tree.setColumnWidth(0, 180)
        self._tree.itemSelectionChanged.connect(self._on_tool_selected)
        splitter.addWidget(self._tree)

        # Right: details + command + output
        right = QWidget()
        rlayout = QVBoxLayout(right)

        self._name_label = QLabel("Select a tool")
        self._name_label.setStyleSheet("font-size: 14pt; font-weight: 600;")
        self._desc_label = QLabel("")
        self._desc_label.setWordWrap(True)
        self._desc_label.setStyleSheet("color: #8b949e;")
        rlayout.addWidget(self._name_label)
        rlayout.addWidget(self._desc_label)

        form_box = QGroupBox("Command builder")
        form = QFormLayout(form_box)
        self._target_edit = QLineEdit()
        self._target_edit.setPlaceholderText("target (host / URL / CIDR)")
        self._target_edit.textChanged.connect(self._rebuild_command)
        self._params_edit = QLineEdit()
        self._params_edit.setPlaceholderText("key=value key2=value2 (wordlist, mode, ...)")
        self._params_edit.textChanged.connect(self._rebuild_command)
        self._asset_combo = QComboBox()
        self._asset_combo.currentIndexChanged.connect(self._on_asset_picked)
        form.addRow("In-scope asset:", self._asset_combo)
        form.addRow("Target:", self._target_edit)
        form.addRow("Params:", self._params_edit)
        rlayout.addWidget(form_box)

        self._command_edit = QLineEdit()
        self._command_edit.setReadOnly(True)
        self._command_edit.setPlaceholderText("Generated command appears here for review")
        rlayout.addWidget(QLabel("Command (review before launching):"))
        rlayout.addWidget(self._command_edit)

        btn_row = QHBoxLayout()
        self._launch_btn = QPushButton("Launch")
        self._launch_btn.setObjectName("primary")
        self._launch_btn.clicked.connect(self._launch)
        self._launch_btn.setEnabled(False)
        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.clicked.connect(self._cancel)
        self._cancel_btn.setEnabled(False)
        self._refresh_btn = QPushButton("Re-detect tools")
        self._refresh_btn.clicked.connect(self._redetect)
        btn_row.addWidget(self._launch_btn)
        btn_row.addWidget(self._cancel_btn)
        btn_row.addStretch()
        btn_row.addWidget(self._refresh_btn)
        rlayout.addLayout(btn_row)

        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setPlaceholderText("Tool output will stream here…")
        self._output.setStyleSheet("font-family: monospace;")
        rlayout.addWidget(self._output, stretch=1)

        splitter.addWidget(right)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([260, 720])

    def _populate_tree(self) -> None:
        self._tree.clear()
        for category, tools in self._registry.by_category().items():
            cat_item = QTreeWidgetItem([category.value, ""])
            cat_item.setFirstColumnSpanned(True)
            self._tree.addTopLevelItem(cat_item)
            for detected in sorted(tools, key=lambda d: d.spec.name.lower()):
                status = "installed" if detected.installed else "not found"
                child = QTreeWidgetItem([detected.spec.name, status])
                child.setData(0, Qt.ItemDataRole.UserRole, detected.spec.key)
                if not detected.installed:
                    child.setForeground(0, Qt.GlobalColor.gray)
                cat_item.addChild(child)
            cat_item.setExpanded(True)

    # -- events ----------------------------------------------------------- #
    def refresh_assets(self) -> None:
        """Reload the in-scope asset dropdown for the active project."""
        self._asset_combo.blockSignals(True)
        self._asset_combo.clear()
        self._asset_combo.addItem("— pick an asset —", None)
        project_id = self._ctx.active_project_id
        if project_id is not None:
            for asset in self._ctx.database.assets.list_for_project(project_id):
                self._asset_combo.addItem(f"{asset.identifier} ({asset.scope.value})",
                                          asset.identifier)
        self._asset_combo.blockSignals(False)

    def _on_asset_picked(self, _index: int) -> None:
        identifier = self._asset_combo.currentData()
        if identifier:
            self._target_edit.setText(str(identifier))

    def _on_tool_selected(self) -> None:
        items = self._tree.selectedItems()
        if not items:
            return
        key = items[0].data(0, Qt.ItemDataRole.UserRole)
        if not key:
            return
        self._current = self._registry.get(key)
        if not self._current:
            return
        spec = self._current.spec
        self._name_label.setText(spec.name)
        notes = f"\n\nNotes: {spec.notes}" if spec.notes else ""
        interactive = "\n\n(Interactive — opens in a terminal.)" if spec.interactive else ""
        self._desc_label.setText(spec.description + notes + interactive)
        self._rebuild_command()

    def _parse_params(self) -> dict[str, str]:
        params: dict[str, str] = {}
        for token in self._params_edit.text().split():
            if "=" in token:
                key, _, value = token.partition("=")
                params[key.strip()] = value.strip()
        return params

    def _rebuild_command(self) -> None:
        if not self._current:
            self._command_edit.clear()
            self._launch_btn.setEnabled(False)
            return
        target = self._target_edit.text().strip()
        if not target:
            self._command_edit.setText("(enter a target)")
            self._launch_btn.setEnabled(False)
            return
        try:
            command = self._registry.build_command(
                self._current.spec.key, target, self._parse_params()
            )
        except MissingParameterError as exc:
            self._command_edit.setText(str(exc))
            self._launch_btn.setEnabled(False)
            return
        self._command_edit.setText(command)
        self._launch_btn.setEnabled(self._current.installed and not self._is_running())

    # -- launching -------------------------------------------------------- #
    def _is_running(self) -> bool:
        return bool(self._runner and self._runner.is_running())

    def _launch(self) -> None:
        if not self._current or not self._current.installed:
            return
        project_id = self._ctx.active_project_id
        if project_id is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return

        command = self._command_edit.text().strip()
        target = self._target_edit.text().strip()
        spec = self._current.spec

        if self._ctx.config.get("ui.confirm_tool_launch", True):
            if not widgets.confirm(
                self, "Confirm launch",
                f"Launch the following command?\n\n{command}\n\n"
                "Only proceed against assets you are authorized to test.",
            ):
                return

        argv = self._registry.split_command(command)
        if not argv:
            return

        scan = Scan(
            project_id=project_id, tool=spec.name, command=command, target=target,
            status=ScanStatus.RUNNING, started_at=datetime.now(timezone.utc),
        )
        self._ctx.database.scans.create(scan)

        if spec.interactive:
            self._launch_in_terminal(command)
            scan.status = ScanStatus.COMPLETED
            scan.output = "(launched in external terminal)"
            scan.finished_at = datetime.now(timezone.utc)
            self._ctx.database.scans.update(scan)
            self._output.appendPlainText(f"$ {command}\n[opened in terminal]\n")
            return

        self._output.clear()
        self._output.appendPlainText(f"$ {command}\n")
        self._runner = self._ctx.tasks.run_command(argv[0], argv[1:])
        self._launch_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)

        buffer: list[str] = []
        self._runner.output.connect(lambda chunk: self._on_output(chunk, buffer))
        self._runner.finished.connect(lambda code: self._on_finished(code, scan, buffer))
        self._runner.failed.connect(lambda msg: self._on_failed(msg, scan))

    def _launch_in_terminal(self, command: str) -> None:
        term = self._ctx.config.get("tools.terminal", {}) or {}
        program = str(term.get("program", "x-terminal-emulator"))
        args = [str(a).replace("{cmd}", command) for a in term.get("args", ["-e", command])]
        self._ctx.tasks.run_command(program, args)

    def _on_output(self, chunk: str, buffer: list[str]) -> None:
        buffer.append(chunk)
        self._output.moveCursor(self._output.textCursor().MoveOperation.End)
        self._output.insertPlainText(chunk)

    def _on_finished(self, code: int, scan: Scan, buffer: list[str]) -> None:
        scan.status = ScanStatus.COMPLETED if code == 0 else ScanStatus.FAILED
        scan.exit_code = code
        scan.output = "".join(buffer)[:200_000]
        scan.finished_at = datetime.now(timezone.utc)
        self._ctx.database.scans.update(scan)
        self._output.appendPlainText(f"\n[process exited with code {code}]")
        self._cancel_btn.setEnabled(False)
        self._rebuild_command()

    def _on_failed(self, message: str, scan: Scan) -> None:
        scan.status = ScanStatus.FAILED
        scan.output = message
        scan.finished_at = datetime.now(timezone.utc)
        self._ctx.database.scans.update(scan)
        self._output.appendPlainText(f"\n[failed to start: {message}]")
        self._cancel_btn.setEnabled(False)
        self._rebuild_command()

    def _cancel(self) -> None:
        if self._runner:
            self._runner.cancel()
            self._output.appendPlainText("\n[cancelled by operator]")

    def _redetect(self) -> None:
        self._registry.refresh()
        self._populate_tree()
        widgets.info(self, "Detection complete",
                     f"{len(self._registry.installed())} tools found on this system.")


class ToolLauncherPlugin(PluginBase):
    meta = PluginMeta(
        identifier="tool_launcher",
        title="Tools",
        description="Detect and launch installed Kali tools.",
        priority=20,
    )

    def create_widget(self) -> QWidget:
        self._widget = ToolLauncherWidget(self)
        return self._widget

    def on_project_changed(self, project_id: int | None) -> None:
        if getattr(self, "_widget", None) is not None:
            self._widget.refresh_assets()


def get_plugin(context) -> ToolLauncherPlugin:  # noqa: ANN001 - context type is AppContext
    return ToolLauncherPlugin(context)
