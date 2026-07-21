"""Asset inventory & scope management plugin."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.plugins import PluginBase, PluginMeta
from ..gui import widgets
from ..models import Asset, AssetType, ScopeState


class AssetsWidget(QWidget):
    def __init__(self, plugin: "AssetsPlugin") -> None:
        super().__init__()
        self._ctx = plugin.context
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(widgets.section_label("Asset Inventory & Scope"))

        add_row = QHBoxLayout()
        self._identifier = QLineEdit()
        self._identifier.setPlaceholderText("host / IP / domain / URL / CIDR")
        self._type_combo = QComboBox()
        for t in AssetType:
            self._type_combo.addItem(t.value, t)
        self._scope_combo = QComboBox()
        for s in ScopeState:
            self._scope_combo.addItem(s.value, s)
        add_btn = QPushButton("Add")
        add_btn.setObjectName("primary")
        add_btn.clicked.connect(self._add_asset)
        add_row.addWidget(self._identifier, stretch=2)
        add_row.addWidget(self._type_combo)
        add_row.addWidget(self._scope_combo)
        add_row.addWidget(add_btn)
        layout.addLayout(add_row)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Identifier", "Type", "Scope", "Notes"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        layout.addWidget(self._table, stretch=1)

        btn_row = QHBoxLayout()
        toggle_btn = QPushButton("Toggle scope")
        toggle_btn.clicked.connect(self._toggle_scope)
        del_btn = QPushButton("Delete selected")
        del_btn.clicked.connect(self._delete_selected)
        btn_row.addStretch()
        btn_row.addWidget(toggle_btn)
        btn_row.addWidget(del_btn)
        layout.addLayout(btn_row)

    def reload(self) -> None:
        self._table.setRowCount(0)
        project_id = self._ctx.active_project_id
        if project_id is None:
            return
        for asset in self._ctx.database.assets.list_for_project(project_id):
            row = self._table.rowCount()
            self._table.insertRow(row)
            item = QTableWidgetItem(asset.identifier)
            item.setData(Qt.ItemDataRole.UserRole, asset.id)
            self._table.setItem(row, 0, item)
            self._table.setItem(row, 1, QTableWidgetItem(asset.asset_type.value))
            self._table.setItem(row, 2, QTableWidgetItem(asset.scope.value))
            self._table.setItem(row, 3, QTableWidgetItem(asset.notes))

    def _add_asset(self) -> None:
        project_id = self._ctx.active_project_id
        if project_id is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return
        identifier = self._identifier.text().strip()
        if not identifier:
            return
        asset = Asset(
            project_id=project_id,
            identifier=identifier,
            asset_type=self._type_combo.currentData(),
            scope=self._scope_combo.currentData(),
        )
        self._ctx.database.assets.create(asset)
        self._identifier.clear()
        self.reload()

    def _selected_asset_id(self) -> int | None:
        row = self._table.currentRow()
        if row < 0:
            return None
        item = self._table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _toggle_scope(self) -> None:
        asset_id = self._selected_asset_id()
        if asset_id is None or self._ctx.active_project_id is None:
            return
        assets = {a.id: a for a in self._ctx.database.assets.list_for_project(
            self._ctx.active_project_id)}
        asset = assets.get(asset_id)
        if not asset:
            return
        asset.scope = (ScopeState.OUT_OF_SCOPE if asset.scope == ScopeState.IN_SCOPE
                       else ScopeState.IN_SCOPE)
        self._ctx.database.assets.update(asset)
        self.reload()

    def _delete_selected(self) -> None:
        asset_id = self._selected_asset_id()
        if asset_id is None:
            return
        if widgets.confirm(self, "Delete asset", "Remove the selected asset?"):
            self._ctx.database.assets.delete(asset_id)
            self.reload()


class AssetsPlugin(PluginBase):
    meta = PluginMeta(
        identifier="assets",
        title="Assets",
        description="Inventory targets and manage scope.",
        priority=10,
    )

    def create_widget(self) -> QWidget:
        self._widget = AssetsWidget(self)
        return self._widget

    def on_project_changed(self, project_id: int | None) -> None:
        if getattr(self, "_widget", None) is not None:
            self._widget.reload()


def get_plugin(context) -> AssetsPlugin:  # noqa: ANN001
    return AssetsPlugin(context)
