"""AI Responsible Disclosure & Reporting plugin.

Turns a project's verified findings into a professional disclosure package:
curate (dedup + rank + flag), draft an editable report and email, detect the
target's published security contact (RFC 9116 security.txt), and — only after
explicit user approval — *prepare* the submission (save report + .eml, open the
mail client) and record it locally.

Safety: this module never transmits anything itself. The analyst performs the
actual send. It refuses to proceed for unauthorized or out-of-scope targets and
never fabricates findings — each carries a confidence level.
"""

from __future__ import annotations

import email.message
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..bugbounty.scope import Scope, ScopeValidator
from ..core import paths
from ..core.plugins import PluginBase, PluginMeta
from ..disclosure import (
    build_disclosure_email,
    curate_findings,
    parse_security_txt,
)
from ..disclosure.report import DisclosureReportBundle, DisclosureReportGenerator
from ..disclosure.security_txt import fetch_security_txt
from ..gui import widgets
from ..models import Disclosure, DisclosureStatus, ScopeState
from ..reporting import ReportFormat


class DisclosureWidget(QWidget):
    def __init__(self, plugin: "DisclosurePlugin") -> None:
        super().__init__()
        self._ctx = plugin.context
        self._gen = DisclosureReportGenerator(self._ctx.config.section("reporting"))
        self._curated = None
        self._contact = None
        self._email = None
        self._build_ui()

    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        header = QHBoxLayout()
        header.addWidget(widgets.section_label("Responsible Disclosure & Reporting"))
        header.addStretch()
        note = QLabel("Prepares submissions — never sends automatically")
        note.setStyleSheet("color: #d29922;")
        header.addWidget(note)
        root.addLayout(header)

        # target + contact row
        top = QHBoxLayout()
        self._target = QLineEdit()
        self._target.setPlaceholderText("Target (host / domain) for this disclosure")
        self._recipient = QLineEdit()
        self._recipient.setPlaceholderText("Security contact (auto-filled from security.txt)")
        fetch_btn = QPushButton("Fetch security.txt")
        fetch_btn.setToolTip("Look up the target's published security contact (network request to the target)")
        fetch_btn.clicked.connect(self._fetch_contact)
        top.addWidget(self._target, stretch=2)
        top.addWidget(self._recipient, stretch=2)
        top.addWidget(fetch_btn)
        root.addLayout(top)
        self._auth_status = QLabel("")
        self._auth_status.setWordWrap(True)
        root.addWidget(self._auth_status)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # left: curated findings
        left = QWidget()
        lcol = QVBoxLayout(left)
        lrow = QHBoxLayout()
        lrow.addWidget(QLabel("Verified findings"))
        lrow.addStretch()
        curate_btn = QPushButton("Curate findings")
        curate_btn.clicked.connect(self._curate)
        lrow.addWidget(curate_btn)
        lcol.addLayout(lrow)
        self._findings_list = QListWidget()
        lcol.addWidget(self._findings_list, stretch=1)
        self._summary = QLabel("Curate to summarize, deduplicate, and rank findings.")
        self._summary.setWordWrap(True)
        self._summary.setStyleSheet("color: #8b949e;")
        lcol.addWidget(self._summary)
        splitter.addWidget(left)

        # right: tabs (Report / Email / security.txt / History)
        tabs = QTabWidget()

        rep = QWidget(); rl = QVBoxLayout(rep)
        rbtns = QHBoxLayout()
        draft = QPushButton("Draft report"); draft.setObjectName("primary")
        draft.clicked.connect(self._draft_report)
        save = QPushButton("Save report…"); save.clicked.connect(self._save_report)
        rbtns.addWidget(draft); rbtns.addWidget(save); rbtns.addStretch()
        rl.addLayout(rbtns)
        self._report_edit = QPlainTextEdit()
        self._report_edit.setPlaceholderText("The drafted report (Markdown) appears here — editable before submission.")
        rl.addWidget(self._report_edit, stretch=1)
        tabs.addTab(rep, "Report")

        em = QWidget(); el = QVBoxLayout(em)
        gen_email = QPushButton("Generate disclosure email")
        gen_email.clicked.connect(self._generate_email)
        el.addWidget(gen_email)
        el.addWidget(QLabel("Subject"))
        self._subject = QLineEdit()
        el.addWidget(self._subject)
        el.addWidget(QLabel("Body (editable)"))
        self._body = QPlainTextEdit()
        el.addWidget(self._body, stretch=1)
        approve = QPushButton("Approve & prepare submission")
        approve.setObjectName("primary")
        approve.clicked.connect(self._prepare_submission)
        el.addWidget(approve)
        tabs.addTab(em, "Email & Submit")

        stx = QWidget(); sl = QVBoxLayout(stx)
        sl.addWidget(QLabel("Paste a security.txt (or use 'Fetch security.txt' above):"))
        self._stx_edit = QPlainTextEdit()
        sl.addWidget(self._stx_edit, stretch=1)
        parse_btn = QPushButton("Parse pasted security.txt")
        parse_btn.clicked.connect(self._parse_contact)
        sl.addWidget(parse_btn)
        tabs.addTab(stx, "security.txt")

        hist = QWidget(); hl = QVBoxLayout(hist)
        hl.addWidget(QLabel("Disclosure history (local record)"))
        self._history = QListWidget()
        hl.addWidget(self._history, stretch=1)
        tabs.addTab(hist, "History")

        splitter.addWidget(tabs)
        splitter.setSizes([460, 700])
        root.addWidget(splitter, stretch=1)

    # ------------------------------------------------------------------ #
    # Authorization gate
    # ------------------------------------------------------------------ #
    def _authorization(self, target: str) -> tuple[bool, str]:
        project = self._current_project()
        if project is None:
            return False, "Select or create a project first."
        if not project.authorized:
            return False, ("This project is not marked as authorized. Disclosure is "
                           "only available for assets you own or are permitted to test.")
        if not target:
            return False, "Enter the target this disclosure concerns."
        scope = self._scope_from_assets()
        if scope.in_scope:
            decision = ScopeValidator(scope).classify(target)
            if not decision.in_scope:
                return False, f"Refused: {decision.reason}"
        return True, "Authorization confirmed for this target."

    def _scope_from_assets(self) -> Scope:
        scope = Scope()
        pid = self._ctx.active_project_id
        if pid is not None:
            for a in self._ctx.database.assets.list_for_project(pid):
                (scope.in_scope if a.scope == ScopeState.IN_SCOPE
                 else scope.out_of_scope if a.scope == ScopeState.OUT_OF_SCOPE
                 else []).append(a.identifier)
        return scope

    def _refresh_auth(self) -> None:
        ok, msg = self._authorization(self._target.text().strip())
        self._auth_status.setText(("✔ " if ok else "⛔ ") + msg)
        self._auth_status.setStyleSheet(f"color: {'#3fb950' if ok else '#f85149'};")

    # ------------------------------------------------------------------ #
    # Findings curation
    # ------------------------------------------------------------------ #
    def _curate(self) -> None:
        pid = self._ctx.active_project_id
        if pid is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return
        findings = self._ctx.database.findings.list_for_project(pid)
        if not findings:
            widgets.info(self, "No findings", "Record verified findings first (Findings tab).")
            return
        self._curated = curate_findings(findings)
        self._findings_list.clear()
        for f in self._curated.ranked:
            flag = "  ⚑ verify" if f.confidence.needs_verification else ""
            self._findings_list.addItem(
                f"[{f.severity.value}] {f.title}  ·  {f.confidence.value}{flag}")
        c = self._curated
        self._summary.setText(
            f"{len(c.ranked)} finding(s) after removing {c.duplicates_removed} duplicate(s); "
            f"{len(c.needs_verification)} flagged for manual verification.")
        self._refresh_auth()

    # ------------------------------------------------------------------ #
    # Security contact
    # ------------------------------------------------------------------ #
    def _parse_contact(self) -> None:
        text = self._stx_edit.toPlainText().strip()
        if not text:
            return
        self._contact = parse_security_txt(text, source="pasted")
        self._apply_contact()

    def _fetch_contact(self) -> None:
        host = self._target.text().strip()
        if not host:
            widgets.warn(self, "No target", "Enter the target host first.")
            return
        if not widgets.confirm(self, "Fetch security.txt",
                               f"Make a network request to {host} to look up its published "
                               f"security.txt? This contacts the target directly."):
            return
        worker = self._ctx.tasks.submit(fetch_security_txt, host)
        worker.signals.result.connect(self._on_contact_fetched)

    def _on_contact_fetched(self, contact) -> None:
        if contact is None:
            widgets.info(self, "Not found",
                         "No security.txt was found. Enter the security contact manually "
                         "or check the organization's bug bounty program page.")
            return
        self._contact = contact
        if contact.raw:
            self._stx_edit.setPlainText(contact.raw)
        self._apply_contact()

    def _apply_contact(self) -> None:
        if self._contact and self._contact.has_contact:
            self._recipient.setText(self._contact.primary_email or self._contact.primary_url)
            widgets.info(self, "Security contact found",
                         f"Contact(s): {', '.join(self._contact.contacts)}")

    # ------------------------------------------------------------------ #
    # Report & email drafting
    # ------------------------------------------------------------------ #
    def _bundle(self) -> DisclosureReportBundle | None:
        pid = self._ctx.active_project_id
        if pid is None:
            return None
        project = self._current_project()
        if project is None:
            return None
        db = self._ctx.database
        findings = db.findings.list_for_project(pid)
        summary = ""
        if self._ctx.assistant is not None:
            summary = self._ctx.assistant.summarize_findings(findings)
        return DisclosureReportBundle(
            project=project, target=self._target.text().strip() or project.name,
            findings=findings, assets=db.assets.list_for_project(pid),
            scans=db.scans.list_for_project(pid), evidence=db.evidence.list_for_project(pid),
            organization=self._recipient.text().strip(),
            executive_summary=summary,
            report_version=db.disclosures.next_version(pid),
        )

    def _draft_report(self) -> None:
        bundle = self._bundle()
        if bundle is None:
            widgets.warn(self, "No project", "Select or create a project first.")
            return
        self._report_edit.setPlainText(self._gen.render_markdown(bundle))

    def _save_report(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        bundle = self._bundle()
        if bundle is None:
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        safe = "".join(c if c.isalnum() else "_" for c in bundle.target)
        default = str(paths.downloads_dir() / f"disclosure_{safe}_{bundle.report_version}_{stamp}.html")
        path, _ = QFileDialog.getSaveFileName(self, "Save disclosure report", default)
        if not path:
            return
        fmt = {".pdf": ReportFormat.PDF, ".md": ReportFormat.MARKDOWN}.get(
            Path(path).suffix.lower(), ReportFormat.HTML)
        try:
            written = self._gen.export(bundle, Path(path), fmt, evidence_root=paths.evidence_dir())
        except RuntimeError as exc:
            widgets.warn(self, "Export failed", str(exc))
            return
        self._last_report_path = str(written)
        widgets.info(self, "Report saved", f"Saved to:\n{written}")

    def _generate_email(self) -> None:
        if self._curated is None:
            self._curate()
        if self._curated is None:
            return
        bundle = self._bundle()
        version = bundle.report_version if bundle else "v1"
        self._email = build_disclosure_email(
            organization=self._recipient.text().strip() or "Security Team",
            target=self._target.text().strip() or "the target",
            curated=self._curated,
            recipient=self._recipient.text().strip(),
            report_version=version,
            llm=self._ctx.llm,
        )
        self._subject.setText(self._email.subject)
        self._body.setPlainText(self._email.body)

    # ------------------------------------------------------------------ #
    # Prepare submission (never auto-sends)
    # ------------------------------------------------------------------ #
    def _prepare_submission(self) -> None:
        pid = self._ctx.active_project_id
        target = self._target.text().strip()
        ok, msg = self._authorization(target)
        self._refresh_auth()
        if not ok:
            widgets.warn(self, "Not authorized", msg)
            return
        recipient = self._recipient.text().strip()
        subject = self._subject.text().strip()
        body = self._body.toPlainText().strip()
        if not (recipient and subject and body):
            widgets.warn(self, "Incomplete",
                         "Fill in the recipient, subject, and email body first "
                         "(Generate disclosure email).")
            return

        confirmed = widgets.confirm(
            self, "Approve disclosure",
            f"Prepare this responsible-disclosure submission?\n\n"
            f"To: {recipient}\nSubject: {subject}\n\n"
            f"This will save an .eml draft and open your mail client. "
            f"The application will NOT send anything — you review and send it yourself.")
        if not confirmed:
            return

        db = self._ctx.database
        version = db.disclosures.next_version(pid)

        # Save the report alongside the submission.
        report_path = getattr(self, "_last_report_path", "")
        if not report_path:
            bundle = self._bundle()
            if bundle is not None:
                stamp = datetime.now().strftime("%Y%m%d_%H%M")
                safe = "".join(c if c.isalnum() else "_" for c in bundle.target)
                out = paths.reports_dir() / f"disclosure_{safe}_{version}_{stamp}.html"
                try:
                    self._gen.export(bundle, out, ReportFormat.HTML, evidence_root=paths.evidence_dir())
                    report_path = str(out)
                except RuntimeError:
                    report_path = ""

        # Write an .eml draft (not sent).
        eml_path = self._write_eml(recipient, subject, body, report_path)

        # Offer to open the mail client (mailto) — user still sends manually.
        QDesktopServices.openUrl(QUrl(
            f"mailto:{recipient}?subject={quote(subject)}&body={quote(body)}"))

        # Record the submission locally.
        db.disclosures.create(Disclosure(
            project_id=pid, report_version=version, recipient=recipient,
            method="email (manual)", status=DisclosureStatus.PREPARED,
            subject=subject, report_path=report_path,
            notes=f"Draft saved to {eml_path}. Sent manually by the analyst."))
        self._reload_history()
        widgets.info(
            self, "Submission prepared",
            f"Prepared and recorded (version {version}).\n\n"
            f"- Report: {report_path or '(not saved)'}\n- Email draft: {eml_path}\n\n"
            f"Review and send it through the organization's responsible-disclosure "
            f"process. Update the record's status once sent.")

    def _write_eml(self, recipient: str, subject: str, body: str, report_path: str) -> str:
        msg = email.message.EmailMessage()
        msg["To"] = recipient
        msg["Subject"] = subject
        body_note = body
        if report_path:
            body_note += f"\n\n[Attach the report before sending: {report_path}]"
        msg.set_content(body_note)
        stamp = datetime.now().strftime("%Y%m%d_%H%M")
        out = paths.reports_dir() / f"disclosure_draft_{stamp}.eml"
        out.write_bytes(bytes(msg))
        return str(out)

    # ------------------------------------------------------------------ #
    def _reload_history(self) -> None:
        self._history.clear()
        pid = self._ctx.active_project_id
        if pid is None:
            return
        for d in self._ctx.database.disclosures.list_for_project(pid):
            when = d.created_at.strftime("%Y-%m-%d %H:%M") if d.created_at else ""
            self._history.addItem(
                f"{when}  ·  {d.report_version}  ·  {d.status.value}  ·  {d.recipient}")

    def _current_project(self):
        pid = self._ctx.active_project_id
        return self._ctx.database.projects.get(pid) if pid is not None else None

    def reload(self) -> None:
        self._curated = None
        self._contact = None
        self._findings_list.clear()
        self._report_edit.clear()
        self._subject.clear()
        self._body.clear()
        self._summary.setText("Curate to summarize, deduplicate, and rank findings.")
        self._reload_history()
        self._refresh_auth()


class DisclosurePlugin(PluginBase):
    meta = PluginMeta(
        identifier="disclosure",
        title="Disclosure",
        description="Draft, review, and record responsible vulnerability disclosures.",
        priority=65,
    )

    def create_widget(self) -> QWidget:
        self._widget = DisclosureWidget(self)
        return self._widget

    def on_project_changed(self, project_id: int | None) -> None:
        if getattr(self, "_widget", None) is not None:
            self._widget.reload()


def get_plugin(context) -> DisclosurePlugin:  # noqa: ANN001
    return DisclosurePlugin(context)
