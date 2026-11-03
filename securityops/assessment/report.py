"""Component 3 — Report Generation (HTML, and PDF when WeasyPrint is installed)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .analysis import SEVERITIES, Analysis
from .gather import ScanResult

_TEMPLATES = Path(__file__).resolve().parent.parent / "reporting" / "templates"

LIMITATIONS = [
    "Only passive, non-destructive checks were performed: DNS lookups, standard HTTP/HTTPS "
    "requests to the home page, and one TLS handshake.",
    "No authentication, crawling, port scanning, vulnerability exploitation or source-code "
    "review was performed, so application-level flaws (e.g. SQL injection, broken access "
    "control) are out of scope.",
    "Technology detection is based on public hints (headers, cookies, markup) and may be "
    "incomplete or wrong.",
    "Results reflect a single point in time and the network location of the tester; CDNs, "
    "load balancers and firewalls can change what is observed.",
    "AI-generated explanations are assistive. Findings marked 'Potential risk' require "
    "manual verification before being reported to anyone.",
]


class PdfUnavailableError(RuntimeError):
    """WeasyPrint (and its system libraries) is not installed."""


def render_html(scan: ScanResult, analysis: Analysis, config: Any = None) -> str:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                      autoescape=select_autoescape(["html"]))
    counts = {s: sum(f.severity == s for f in analysis.findings) for s in SEVERITIES}
    return env.get_template("assessment_report.html").render(
        scan=scan, analysis=analysis, counts=counts, limitations=LIMITATIONS,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        author=(config.get("reporting.author", "Security Analyst") if config else
                "Security Analyst"),
        organization=(config.get("reporting.company", "") if config else ""),
        classification=(config.get("reporting.classification", "CONFIDENTIAL") if config
                        else "CONFIDENTIAL"),
    )


def render_pdf(html: str) -> bytes:
    try:
        from weasyprint import HTML  # optional, Linux-oriented dependency
    except Exception as exc:  # noqa: BLE001 - ImportError or missing system libraries
        raise PdfUnavailableError(
            "PDF export needs WeasyPrint ('pip install weasyprint', plus its system "
            "libraries on Windows/macOS). Download the HTML report and use your browser's "
            "Print → Save as PDF instead.") from exc
    return HTML(string=html).write_pdf()


def report_filename(scan: ScanResult, extension: str) -> str:
    safe = "".join(c if c.isalnum() else "_" for c in scan.host)
    return f"security_assessment_{safe}_{datetime.now():%Y%m%d_%H%M}.{extension}"
