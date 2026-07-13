"""Offline assistant engine.

The :class:`Assistant` answers operator questions using the tool catalog and the
curated knowledge base. It is intent-routed: a lightweight keyword classifier
picks a handler. It is *advisory only* — it never launches tools or mutates
data. Anything that would run a command is returned as a suggestion string for
the operator to review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from ..core.tools import CATALOG_BY_KEY, ToolRegistry
from ..models import Finding, Severity
from . import knowledge


@dataclass
class AssistantReply:
    """A structured reply from the assistant."""

    text: str
    #: Optional suggested command for the operator to review (never auto-run).
    suggested_command: str | None = None
    #: Optional list of follow-up suggestions.
    suggestions: list[str] = field(default_factory=list)


class Assistant:
    """Deterministic, offline advisory assistant."""

    #: Actions the assistant will always refuse to perform automatically.
    REFUSAL = (
        "I can only advise, not act. I won't launch tools, exploit targets, or "
        "modify systems automatically — review and run anything sensitive yourself, "
        "and only against assets you're authorized to test."
    )

    def __init__(self, tools: ToolRegistry | None = None) -> None:
        self._tools = tools
        # Intent handlers are tried in order; first matching pattern wins.
        self._routes: list[tuple[re.Pattern[str], Callable[[str], AssistantReply]]] = [
            (re.compile(r"\b(explain|what is|what does|describe|tell me about)\b", re.I),
             self._explain_tool),
            (re.compile(r"\b(next|recommend|which tool|what should|suggest)\b", re.I),
             self._recommend_next),
            (re.compile(r"\b(command|how do i run|generate|scan for|build)\b", re.I),
             self._generate_command),
            (re.compile(r"\b(remediat\w*|fix|mitigat\w*|resolve)\b", re.I),
             self._remediation),
            (re.compile(r"\b(cvss|severity|score)\b", re.I),
             self._severity_help),
            (re.compile(r"\b(workflow|phase|methodology|process|steps)\b", re.I),
             self._workflow),
            (re.compile(r"\b(exploit\w*|hack\w*|attack\w*|ddos|malware|ransom\w*)\b", re.I),
             self._safety_gate),
        ]

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def ask(self, question: str) -> AssistantReply:
        """Route *question* to a handler and return a reply."""
        text = question.strip()
        if not text:
            return AssistantReply("Ask me to explain a tool, recommend a next step, "
                                  "generate a command, or draft remediation.")
        for pattern, handler in self._routes:
            if pattern.search(text):
                return handler(text)
        return self._fallback(text)

    def explain_tool(self, key: str) -> str:
        """Return a plain-language explanation of a catalog tool."""
        spec = CATALOG_BY_KEY.get(key)
        if spec is None:
            return f"I don't have '{key}' in my catalog."
        lines = [f"{spec.name} — {spec.category.value}", "", spec.description]
        if spec.notes:
            lines += ["", f"Notes: {spec.notes}"]
        if spec.interactive:
            lines += ["", "This tool is launched interactively (in a terminal)."]
        return "\n".join(lines)

    def summarize_findings(self, findings: list[Finding]) -> str:
        """Produce an executive-style summary of a list of findings."""
        if not findings:
            return "No findings recorded yet."
        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = [
            f"{counts[s]} {s.value}"
            for s in sorted(counts, key=lambda s: s.rank, reverse=True)
        ]
        top = max(findings, key=lambda f: (f.severity.rank, f.cvss_score or 0))
        summary = (
            f"{len(findings)} finding(s): " + ", ".join(parts) + ". "
            f"Highest-risk item: '{top.title}' ({top.severity.value})."
        )
        highest = top.severity
        if highest in (Severity.CRITICAL, Severity.HIGH):
            summary += " Prioritize remediation of the high/critical items immediately."
        return summary

    def suggest_remediation(self, finding: Finding) -> str:
        """Return remediation guidance for a finding based on its title/description."""
        return self._remediation_for(f"{finding.title} {finding.description}").text

    # ------------------------------------------------------------------ #
    # Intent handlers
    # ------------------------------------------------------------------ #
    def _explain_tool(self, text: str) -> AssistantReply:
        spec = self._match_tool(text)
        if spec is None:
            return AssistantReply(
                "Which tool? I can explain: "
                + ", ".join(s.name for s in CATALOG_BY_KEY.values())
            )
        return AssistantReply(self.explain_tool(spec.key))

    def _recommend_next(self, text: str) -> AssistantReply:
        # Recommend based on the phase mentioned, else default to the first phase.
        phase = self._match_phase(text) or knowledge.PHASES[0]
        available = [
            CATALOG_BY_KEY[k].name
            for k in phase.tool_keys
            if k in CATALOG_BY_KEY and self._is_installed(k)
        ]
        tool_line = (
            "Available tools: " + ", ".join(available)
            if available else
            "None of the typical tools for this phase appear installed."
        )
        return AssistantReply(
            f"Phase: {phase.name}\nGoal: {phase.goal}\n{tool_line}\n\n{phase.guidance}",
            suggestions=[CATALOG_BY_KEY[k].name for k in phase.tool_keys if k in CATALOG_BY_KEY],
        )

    def _generate_command(self, text: str) -> AssistantReply:
        spec = self._match_tool(text)
        if spec is None:
            return AssistantReply(
                "Tell me which tool and a target, e.g. "
                "'generate an nmap command for 10.0.0.5'."
            )
        target = self._extract_target(text) or "<TARGET>"
        command = spec.template.format(
            binary=spec.binary,
            target=target,
            outfile="scan.txt",
            wordlist="<WORDLIST>",
            mode="<MODE>",
            hashfile="<HASHFILE>",
            userlist="<USERS>",
            passlist="<PASSWORDS>",
            capturefile="<CAPTURE>",
        )
        note = f"\n\nNote: {spec.notes}" if spec.notes else ""
        return AssistantReply(
            f"Suggested {spec.name} command (review before running):{note}",
            suggested_command=command,
        )

    def _remediation(self, text: str) -> AssistantReply:
        return self._remediation_for(text)

    def _remediation_for(self, text: str) -> AssistantReply:
        low = text.lower()
        for topic, advice in knowledge.REMEDIATION.items():
            if topic in low:
                refs = knowledge.REFERENCES.get(topic, ())
                ref_line = ("\n\nReferences: " + "; ".join(refs)) if refs else ""
                return AssistantReply(f"Remediation for {topic}:\n{advice}{ref_line}")
        return AssistantReply(
            "General remediation: apply least privilege, keep software patched, "
            "validate all input, encrypt data in transit and at rest, and monitor "
            "for anomalies. Tell me the specific issue (e.g. 'SQL injection') for "
            "targeted guidance."
        )

    def _severity_help(self, _text: str) -> AssistantReply:
        bands = "\n".join(
            f"  {b.low:>3.1f}-{b.high:<4.1f}  {b.label}" for b in knowledge.CVSS_BANDS
        )
        return AssistantReply(
            "CVSS v3.1 qualitative severity bands:\n" + bands +
            "\n\nEnter a base score on a finding and the app maps it to a band "
            "automatically."
        )

    def _workflow(self, _text: str) -> AssistantReply:
        lines = ["Recommended assessment workflow:"]
        for i, phase in enumerate(knowledge.PHASES, 1):
            lines.append(f"  {i}. {phase.name} — {phase.goal}")
        return AssistantReply("\n".join(lines))

    def _safety_gate(self, _text: str) -> AssistantReply:
        return AssistantReply(self.REFUSAL)

    def _fallback(self, _text: str) -> AssistantReply:
        return AssistantReply(
            "I can: explain a tool, recommend the next phase/tool, generate a "
            "command to review, map CVSS to severity, draft remediation, and "
            "summarize findings. What would you like?"
        )

    # ------------------------------------------------------------------ #
    # Matching helpers
    # ------------------------------------------------------------------ #
    def _match_tool(self, text: str):
        low = text.lower()
        for spec in CATALOG_BY_KEY.values():
            names = (spec.key, spec.name.lower(), spec.binary.lower(), *spec.aliases)
            if any(re.search(rf"\b{re.escape(n)}\b", low) for n in names):
                return spec
        return None

    def _match_phase(self, text: str) -> knowledge.Phase | None:
        low = text.lower()
        for phase in knowledge.PHASES:
            if phase.name.lower() in low:
                return phase
        keyword_map = {
            "recon": knowledge.PHASES[0],
            "enum": knowledge.PHASES[1],
            "web": knowledge.PHASES[2],
            "vuln": knowledge.PHASES[3],
            "exploit": knowledge.PHASES[4],
            "report": knowledge.PHASES[5],
        }
        for kw, phase in keyword_map.items():
            if kw in low:
                return phase
        return None

    @staticmethod
    def _extract_target(text: str) -> str | None:
        # IPv4, CIDR, URL, or bare hostname/domain.
        patterns = (
            r"https?://[^\s]+",
            r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b",
            r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
        )
        for pat in patterns:
            match = re.search(pat, text, re.I)
            if match:
                return match.group(0)
        return None

    def _is_installed(self, key: str) -> bool:
        if self._tools is None:
            return True
        detected = self._tools.get(key)
        return bool(detected and detected.installed)
