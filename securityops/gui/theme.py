"""Dark (and light) theme as a Qt Style Sheet.

Kept as Python strings to avoid resource-packaging complexity. Apply with
:func:`apply_theme(app, name)`.
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

# Palette constants (GitHub-dark inspired).
_DARK = {
    "bg": "#0d1117",
    "surface": "#161b22",
    "surface2": "#1c2128",
    "border": "#30363d",
    "text": "#e6edf3",
    "muted": "#8b949e",
    "accent": "#2f81f7",
    "accent_hover": "#4c94ff",
}

_DARK_QSS = f"""
* {{ outline: none; }}
QWidget {{
    background-color: {_DARK['bg']};
    color: {_DARK['text']};
    font-size: 10pt;
}}
QMainWindow, QDialog {{ background-color: {_DARK['bg']}; }}

QToolBar, QMenuBar {{
    background-color: {_DARK['surface']};
    border-bottom: 1px solid {_DARK['border']};
    spacing: 6px;
    padding: 4px;
}}
QMenuBar::item:selected, QMenu::item:selected {{ background: {_DARK['surface2']}; }}
QMenu {{ background: {_DARK['surface']}; border: 1px solid {_DARK['border']}; }}

QStatusBar {{
    background-color: {_DARK['surface']};
    border-top: 1px solid {_DARK['border']};
    color: {_DARK['muted']};
}}

QTabWidget::pane {{ border: 1px solid {_DARK['border']}; top: -1px; }}
QTabBar::tab {{
    background: {_DARK['surface']};
    color: {_DARK['muted']};
    padding: 8px 16px;
    border: 1px solid {_DARK['border']};
    border-bottom: none;
}}
QTabBar::tab:selected {{ background: {_DARK['bg']}; color: {_DARK['text']}; }}
QTabBar::tab:hover {{ color: {_DARK['text']}; }}

QPushButton {{
    background-color: {_DARK['surface2']};
    border: 1px solid {_DARK['border']};
    border-radius: 6px;
    padding: 6px 14px;
}}
QPushButton:hover {{ border-color: {_DARK['accent']}; }}
QPushButton:pressed {{ background-color: {_DARK['surface']}; }}
QPushButton#primary {{
    background-color: {_DARK['accent']};
    border: none;
    color: white;
    font-weight: 600;
}}
QPushButton#primary:hover {{ background-color: {_DARK['accent_hover']}; }}
QPushButton:disabled {{ color: {_DARK['muted']}; border-color: {_DARK['surface2']}; }}

QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background-color: {_DARK['surface']};
    border: 1px solid {_DARK['border']};
    border-radius: 6px;
    padding: 5px 8px;
    selection-background-color: {_DARK['accent']};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
    border-color: {_DARK['accent']};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}

QTableView, QTableWidget, QTreeWidget, QListWidget {{
    background-color: {_DARK['surface']};
    border: 1px solid {_DARK['border']};
    gridline-color: {_DARK['border']};
    selection-background-color: {_DARK['accent']};
    selection-color: white;
    alternate-background-color: {_DARK['surface2']};
}}
QHeaderView::section {{
    background-color: {_DARK['surface2']};
    color: {_DARK['muted']};
    border: none;
    border-right: 1px solid {_DARK['border']};
    border-bottom: 1px solid {_DARK['border']};
    padding: 6px 8px;
}}

QGroupBox {{
    border: 1px solid {_DARK['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 8px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 4px; color: {_DARK['muted']}; }}

QProgressBar {{
    border: 1px solid {_DARK['border']};
    border-radius: 6px;
    text-align: center;
    background: {_DARK['surface']};
}}
QProgressBar::chunk {{ background-color: {_DARK['accent']}; border-radius: 5px; }}

QScrollBar:vertical {{ background: {_DARK['bg']}; width: 12px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {_DARK['border']}; border-radius: 6px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {_DARK['muted']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QSplitter::handle {{ background: {_DARK['border']}; }}
"""


def apply_theme(app: QApplication, name: str = "dark") -> None:
    """Apply the named theme to *app*. Currently only 'dark' is styled fully."""
    if name == "dark":
        _apply_dark_palette(app)
        app.setStyleSheet(_DARK_QSS)
    else:
        app.setStyleSheet("")  # fall back to native/light


def _apply_dark_palette(app: QApplication) -> None:
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(_DARK["bg"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(_DARK["text"]))
    palette.setColor(QPalette.ColorRole.Base, QColor(_DARK["surface"]))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(_DARK["surface2"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(_DARK["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(_DARK["surface2"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(_DARK["text"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(_DARK["accent"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(_DARK["surface"]))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(_DARK["text"]))
    app.setPalette(palette)


SEVERITY_ROW_COLORS = {
    "Critical": "#f85149",
    "High": "#db6d28",
    "Medium": "#d29922",
    "Low": "#3fb950",
    "Informational": "#6c8ebf",
}
