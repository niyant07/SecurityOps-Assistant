"""Assistant panel plugin: converse with the offline advisory assistant."""

from __future__ import annotations

from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..core.plugins import PluginBase, PluginMeta
from ..gui import widgets


class AssistantWidget(QWidget):
    _SUGGESTIONS = (
        "Explain nmap",
        "What tool should I use next for recon?",
        "Generate a gobuster command for http://example.com",
        "How do I remediate SQL injection?",
        "Show the assessment workflow",
    )

    def __init__(self, plugin: "AssistantPlugin") -> None:
        super().__init__()
        self._ctx = plugin.context
        self._build_ui()
        self._greet()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(widgets.section_label("Offline Assistant"))

        self._history = QTextBrowser()
        self._history.setOpenExternalLinks(False)
        layout.addWidget(self._history, stretch=1)

        chips = QHBoxLayout()
        for text in self._SUGGESTIONS[:3]:
            btn = QPushButton(text)
            btn.clicked.connect(lambda _=False, t=text: self._ask(t))
            chips.addWidget(btn)
        layout.addLayout(chips)

        input_row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setPlaceholderText("Ask about tools, next steps, commands, remediation…")
        self._input.returnPressed.connect(self._on_send)
        send = QPushButton("Send")
        send.setObjectName("primary")
        send.clicked.connect(self._on_send)
        input_row.addWidget(self._input, stretch=1)
        input_row.addWidget(send)
        layout.addLayout(input_row)

    def _greet(self) -> None:
        self._append("Assistant",
                     "I'm an offline advisor. I can explain tools, recommend the next "
                     "phase, generate review-only commands, map CVSS to severity, and "
                     "draft remediation. I never run tools or exploit anything myself.")

    def _on_send(self) -> None:
        text = self._input.text().strip()
        if text:
            self._ask(text)
            self._input.clear()

    def _ask(self, text: str) -> None:
        self._append("You", text)
        assistant = self._ctx.assistant
        if assistant is None:
            self._append("Assistant", "The assistant is disabled in configuration.")
            return
        reply = assistant.ask(text)
        body = reply.text
        if reply.suggested_command:
            body += f"\n\n<pre>{reply.suggested_command}</pre>"
        self._append("Assistant", body, html=bool(reply.suggested_command))

    def _append(self, who: str, message: str, html: bool = False) -> None:
        color = "#2f81f7" if who == "You" else "#3fb950"
        safe = message if html else self._escape(message)
        self._history.append(
            f'<p><b style="color:{color}">{who}:</b><br/>{safe.replace(chr(10), "<br/>")}</p>'
        )
        self._history.moveCursor(QTextCursor.MoveOperation.End)

    @staticmethod
    def _escape(text: str) -> str:
        return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


class AssistantPlugin(PluginBase):
    meta = PluginMeta(
        identifier="assistant",
        title="Assistant",
        description="Offline advisory assistant.",
        priority=50,
    )

    def create_widget(self) -> QWidget:
        return AssistantWidget(self)


def get_plugin(context) -> AssistantPlugin:  # noqa: ANN001
    return AssistantPlugin(context)
