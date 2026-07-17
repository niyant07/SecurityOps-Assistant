"""Responsible disclosure & reporting module.

Takes verified findings from an authorized assessment and helps the analyst
produce and deliver a professional vulnerability disclosure — always with the
human in control:

* curate findings (deduplicate, rank by severity and confidence, flag items that
  still need manual verification),
* draft a disclosure report (with business impact and an assessment timeline),
* detect the target's published security contact (RFC 9116 ``security.txt``),
* generate a professional, vendor-friendly disclosure email,
* and record every submission locally.

Safety: the module never transmits anything on its own. It prepares the report
and email and hands off to the analyst's mail client; the analyst performs the
actual send and confirms it. Nothing proceeds for out-of-scope or unauthorized
targets, and no finding is ever fabricated — each carries a confidence level.
"""

from __future__ import annotations

from .curate import CuratedFindings, curate_findings
from .email_gen import DisclosureEmail, build_disclosure_email
from .security_txt import SecurityContact, fetch_security_txt, parse_security_txt

__all__ = [
    "CuratedFindings",
    "curate_findings",
    "DisclosureEmail",
    "build_disclosure_email",
    "SecurityContact",
    "fetch_security_txt",
    "parse_security_txt",
]
