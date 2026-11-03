"""JSON endpoints for the single assessment screen.

GET  /api/status            current progress, scan results and analysis
POST /api/assess            {target, authorized: true} — start information gathering
POST /api/analyze           run the AI security analysis on the results
POST /api/reset             clear the screen for a new target
GET  /api/report?format=    download the report (html or pdf)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..assessment.analysis import LLMProvider, analyze
from ..assessment.gather import TargetError
from ..assessment.report import PdfUnavailableError, render_html, render_pdf, report_filename
from .state import AssessmentSession, ScopeError


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Download:
    filename: str
    content_type: str
    body: bytes
    inline: bool = False


def status(session: AssessmentSession, _query: dict[str, str]) -> dict[str, Any]:
    return session.snapshot()


def assess(session: AssessmentSession, data: dict[str, Any]) -> dict[str, Any]:
    if data.get("authorized") is not True:
        raise ApiError("Confirm that you own this target or are authorized to assess it.")
    target = data.get("target")
    if not isinstance(target, str):
        raise ApiError("Enter a domain, IP address, or URL.")
    try:
        session.start(target)
    except (TargetError, ScopeError) as exc:
        raise ApiError(str(exc)) from exc
    except RuntimeError as exc:
        raise ApiError(str(exc), status=409) from exc
    return {"ok": True}


def run_analysis(session: AssessmentSession, _data: dict[str, Any]) -> dict[str, Any]:
    try:
        session.start_analysis()
    except RuntimeError as exc:
        raise ApiError(str(exc), status=409) from exc
    return {"ok": True}


def reset(session: AssessmentSession, _data: dict[str, Any]) -> dict[str, Any]:
    try:
        session.reset()
    except RuntimeError as exc:
        raise ApiError(str(exc), status=409) from exc
    return {"ok": True}


def report(session: AssessmentSession, query: dict[str, str]) -> Download:
    with session.lock:
        scan, analysis = session.scan, session.analysis
    if scan is None:
        raise ApiError("Run an assessment first.")
    if analysis is None:  # report without the AI step: rule-based findings only
        analysis = analyze(scan, LLMProvider())
        analysis.error = "AI analysis was not run for this report; findings are rule-based."
    html = render_html(scan, analysis, session.config)
    if query.get("format", "html") == "pdf":
        try:
            return Download(report_filename(scan, "pdf"), "application/pdf", render_pdf(html))
        except PdfUnavailableError as exc:
            raise ApiError(str(exc)) from exc
    return Download(report_filename(scan, "html"), "text/html; charset=utf-8",
                    html.encode("utf-8"), inline=query.get("inline") == "1")


GET_ROUTES = {"/api/status": status, "/api/report": report}
POST_ROUTES = {"/api/assess": assess, "/api/analyze": run_analysis, "/api/reset": reset}
