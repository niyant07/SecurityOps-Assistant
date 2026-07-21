"""Small reusable GUI helpers shared by plugins."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)


def no_project_placeholder(message: str = "Select or create a project to begin.") -> QWidget:
    """Return a centered placeholder widget shown when no project is active."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    label = QLabel(message)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #8b949e; font-size: 12pt;")
    layout.addStretch()
    layout.addWidget(label)
    layout.addStretch()
    return widget


def confirm(parent: QWidget, title: str, text: str) -> bool:
    """Show a Yes/No confirmation dialog; return True if the user chose Yes."""
    reply = QMessageBox.question(
        parent, title, text,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
    )
    return reply == QMessageBox.StandardButton.Yes


def info(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.information(parent, title, text)


def warn(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.warning(parent, title, text)


def section_label(text: str) -> QLabel:
    """A styled section header label."""
    label = QLabel(text)
    label.setStyleSheet("font-size: 13pt; font-weight: 600; margin: 6px 0;")
    return label
