"""Generate a professional responsible-disclosure email.

Produces a courteous, vendor-friendly email that accompanies the detailed
report. The email is a draft for the analyst to review and edit; the module
never sends it. A local LLM may be used to refine the tone, but the factual
content (counts, severities) always comes from the curated findings.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.logging_config import get_logger
from ..models import Severity
from .curate import CuratedFindings

_LOG = get_logger("disclosure.email")


@dataclass
class DisclosureEmail:
    """A draft disclosure email."""

    recipient: str
    subject: str
    body: str


def build_disclosure_email(
    organization: str,
    target: str,
    curated: CuratedFindings,
    recipient: str = "",
    researcher: str = "[Your Name]",
    report_version: str = "v1",
    llm=None,  # noqa: ANN001 - optional securityops.ai.llm.LocalLLM
) -> DisclosureEmail:
    """Build a disclosure email draft for *organization* about *target*."""
    org = organization or "Security Team"
    subject = f"Responsible Disclosure — Security findings for {target} ({report_version})"

    counts = curated.severity_counts
    highest = max((s for s in counts), key=lambda s: s.rank, default=None)
    n = len(curated.ranked)
    breakdown = ", ".join(f"{counts[s]} {s.value}"
                          for s in sorted(counts, key=lambda s: s.rank, reverse=True))
    verify_note = ""
    if curated.needs_verification:
        verify_note = (f" {len(curated.needs_verification)} item(s) are marked as "
                       f"requiring further verification and are noted as such in the report.")

    body = _template(org, target, n, highest, breakdown, verify_note, researcher, report_version)

    if llm is not None and getattr(llm, "available", lambda: False)():
        refined = _llm_refine(llm, body)
        if refined:
            body = refined

    return DisclosureEmail(recipient=recipient, subject=subject, body=body)


def _template(org: str, target: str, n: int, highest: Severity | None,
              breakdown: str, verify_note: str, researcher: str, version: str) -> str:
    sev_phrase = f"up to {highest.value.lower()} severity" if highest else "various severities"
    count_phrase = (f"{n} security finding{'s' if n != 1 else ''} ({breakdown})"
                    if breakdown else "a number of security findings")
    return (
        f"Dear {org},\n\n"
        f"I am writing to responsibly disclose {count_phrase} of {sev_phrase} that I "
        f"identified during an authorized security assessment of {target}.\n\n"
        f"I am reporting these in good faith under your responsible disclosure "
        f"process, with the goal of helping you remediate them before they can be "
        f"misused. I have not accessed, modified, or exfiltrated any data beyond what "
        f"was necessary to demonstrate each issue, and I have not disclosed these "
        f"findings to any third party.{verify_note}\n\n"
        f"A detailed report ({version}) is attached. For each finding it includes a "
        f"description, severity (CVSS), business impact, evidence, step-by-step "
        f"reproduction, and suggested remediation.\n\n"
        f"I would appreciate an acknowledgment of receipt, and I am happy to provide "
        f"any additional information or clarification. I am glad to coordinate on "
        f"disclosure timelines that work for your team.\n\n"
        f"Kind regards,\n{researcher}\n"
    )


def _llm_refine(llm, body: str) -> str | None:  # noqa: ANN001
    system = ("You improve the professionalism and courtesy of a security "
              "disclosure email without changing any facts, numbers, or claims. "
              "Keep it concise and vendor-friendly. Return only the email body.")
    prompt = f"Refine the tone of this disclosure email:\n\n{body}"
    try:
        return llm.generate(prompt, system=system)
    except Exception:  # noqa: BLE001
        return None
