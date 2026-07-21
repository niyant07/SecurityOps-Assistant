"""Target-type assessment methodologies.

Maps a :class:`TargetType` to an ordered, phased set of catalog tool keys. The
planner turns these into concrete, scope-validated workflow steps. Chains are
recon → enumeration → assessment and deliberately conservative: only
non-destructive, widely-accepted assessment tools, all approval-gated downstream.
"""

from __future__ import annotations

from dataclasses import dataclass

from .scope import TargetType


@dataclass(frozen=True)
class MethodologyPhase:
    name: str
    goal: str
    tool_keys: tuple[str, ...]


# Ordered phases per target type. Tool keys reference securityops.core.tools.CATALOG.
_METHODOLOGIES: dict[TargetType, tuple[MethodologyPhase, ...]] = {
    TargetType.WEB: (
        MethodologyPhase("Reconnaissance", "Map subdomains and the attack surface.",
                         ("subfinder", "amass", "dnsrecon")),
        MethodologyPhase("Enumeration", "Find live services and fingerprint the stack.",
                         ("nmap", "httpx", "whatweb")),
        MethodologyPhase("Content Discovery", "Enumerate paths, endpoints and files.",
                         ("gobuster", "ffuf", "dirsearch")),
        MethodologyPhase("Vulnerability Assessment", "Check for common web issues.",
                         ("nikto", "sqlmap")),
    ),
    TargetType.API: (
        MethodologyPhase("Reconnaissance", "Discover API hosts and subdomains.",
                         ("subfinder", "dnsrecon")),
        MethodologyPhase("Enumeration", "Probe endpoints and detect technologies.",
                         ("httpx", "nmap")),
        MethodologyPhase("Endpoint Discovery", "Enumerate API routes and parameters.",
                         ("ffuf", "gobuster")),
        MethodologyPhase("Vulnerability Assessment", "Check for injection and misconfig.",
                         ("nikto", "sqlmap")),
    ),
    TargetType.MOBILE_BACKEND: (
        MethodologyPhase("Reconnaissance", "Identify backend hosts and APIs.",
                         ("subfinder", "dnsrecon")),
        MethodologyPhase("Enumeration", "Probe backend services.",
                         ("nmap", "httpx", "whatweb")),
        MethodologyPhase("Endpoint Discovery", "Enumerate backend API routes.",
                         ("ffuf",)),
        MethodologyPhase("Vulnerability Assessment", "Check backend web issues.",
                         ("nikto", "sqlmap")),
    ),
    TargetType.DESKTOP: (
        # Desktop apps are assessed mostly manually / for their network backends.
        MethodologyPhase("Network Enumeration", "Scan the app's hosts/services.",
                         ("nmap",)),
        MethodologyPhase("Service Assessment", "Fingerprint any exposed web services.",
                         ("httpx", "whatweb", "nikto")),
    ),
    TargetType.NETWORK: (
        MethodologyPhase("Host Discovery", "Enumerate live hosts and open ports.",
                         ("nmap", "naabu")),
        MethodologyPhase("Service Assessment", "Fingerprint services; check web hosts.",
                         ("httpx", "whatweb", "nikto")),
    ),
    TargetType.OTHER: (
        MethodologyPhase("Reconnaissance", "Basic discovery.",
                         ("nmap", "httpx")),
    ),
}


def methodology_for(target_type: TargetType) -> tuple[MethodologyPhase, ...]:
    """Return the ordered phases for *target_type* (falls back to OTHER)."""
    return _METHODOLOGIES.get(target_type, _METHODOLOGIES[TargetType.OTHER])


def tool_chain_for(target_type: TargetType) -> list[str]:
    """Flatten the methodology into an ordered, de-duplicated list of tool keys."""
    ordered: list[str] = []
    for phase in methodology_for(target_type):
        for key in phase.tool_keys:
            if key not in ordered:
                ordered.append(key)
    return ordered


def methodology_summary(target_type: TargetType) -> str:
    """A short, human-readable description of the methodology for reports."""
    phases = methodology_for(target_type)
    lines = [f"Methodology for {target_type.value} assessment:"]
    for i, phase in enumerate(phases, 1):
        lines.append(f"  {i}. {phase.name} — {phase.goal}")
    return "\n".join(lines)
