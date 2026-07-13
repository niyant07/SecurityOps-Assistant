"""Report generation package (HTML / PDF / Markdown).

Uses Jinja2 for HTML, an optional WeasyPrint backend for PDF, and a hand-rolled
Markdown serializer. All rendering is local; no network access.
"""

from __future__ import annotations

from .generator import ReportBundle, ReportGenerator, ReportFormat

__all__ = ["ReportBundle", "ReportGenerator", "ReportFormat"]
