"""Curated, offline knowledge used by the assistant.

Everything here is static data: assessment-phase workflows, remediation
templates keyed by topic, and reference links. No network access.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Phase:
    """One phase of an assessment with recommended tools (by catalog key)."""

    name: str
    goal: str
    tool_keys: tuple[str, ...]
    guidance: str


# Ordered assessment phases; the assistant walks these to recommend "next steps".
PHASES: tuple[Phase, ...] = (
    Phase(
        "Reconnaissance",
        "Map the external attack surface without touching in-scope hosts aggressively.",
        ("theharvester", "amass", "subfinder", "dnsrecon"),
        "Start passively. Confirm each discovered asset is in scope before probing.",
    ),
    Phase(
        "Enumeration",
        "Identify live hosts, open ports, and running services.",
        ("nmap", "naabu", "httpx", "whatweb"),
        "Fingerprint services and versions to guide targeted testing.",
    ),
    Phase(
        "Web Application Assessment",
        "Discover content and test web-specific weaknesses.",
        ("gobuster", "ffuf", "dirsearch", "nikto", "sqlmap"),
        "Only fuzz/injection-test parameters explicitly in scope.",
    ),
    Phase(
        "Vulnerability Analysis",
        "Correlate findings with known vulnerabilities.",
        ("nikto", "searchsploit", "sqlmap"),
        "Validate findings manually before reporting to reduce false positives.",
    ),
    Phase(
        "Exploitation (manual, authorized)",
        "Confirm impact of validated vulnerabilities.",
        ("metasploit", "hydra", "hashcat", "john"),
        "Launch consoles for manual use. Never run automated exploitation blindly.",
    ),
    Phase(
        "Reporting",
        "Document findings, evidence, and remediation.",
        (),
        "Capture evidence as you go; write remediation that is specific and testable.",
    ),
)


# Remediation templates keyed by lowercase topic keyword. Matched by substring.
REMEDIATION: dict[str, str] = {
    "sql injection": (
        "Use parameterized queries / prepared statements for all database access. "
        "Validate and whitelist input, apply least-privilege database accounts, and "
        "deploy a WAF as defense in depth. Review ORM usage for raw-query bypasses."
    ),
    "xss": (
        "Context-aware output encoding for all user-controlled data. Adopt a strict "
        "Content-Security-Policy, set HttpOnly/Secure cookies, and validate input on "
        "the server. Prefer framework auto-escaping over manual sanitization."
    ),
    "default credential": (
        "Change all default/vendor credentials, enforce a strong password policy and "
        "MFA, and disable or rename default administrative accounts."
    ),
    "weak password": (
        "Enforce length- and entropy-based password policies, enable MFA, rate-limit "
        "authentication, and monitor for credential-stuffing patterns."
    ),
    "outdated": (
        "Patch to a supported, current version. Establish a recurring patch-management "
        "cycle and subscribe to vendor security advisories."
    ),
    "tls": (
        "Disable legacy protocols (SSLv3/TLS 1.0/1.1) and weak ciphers. Deploy TLS 1.2+ "
        "with strong ciphersuites, HSTS, and valid certificates."
    ),
    "directory listing": (
        "Disable directory indexing on the web server, remove sensitive files from web "
        "roots, and return 404 for non-public paths."
    ),
    "information disclosure": (
        "Suppress verbose error messages and version banners, remove debug endpoints, "
        "and ensure stack traces are never returned to clients."
    ),
    "open port": (
        "Restrict exposed services with host/network firewalls, close unused ports, and "
        "place management interfaces behind a VPN or bastion."
    ),
}


# Reference links appended where relevant (offline reference identifiers).
REFERENCES: dict[str, tuple[str, ...]] = {
    "sql injection": ("OWASP: SQL Injection Prevention Cheat Sheet", "CWE-89"),
    "xss": ("OWASP: XSS Prevention Cheat Sheet", "CWE-79"),
    "tls": ("Mozilla Server Side TLS", "NIST SP 800-52r2"),
    "default credential": ("CWE-1392", "CIS Benchmarks"),
    "outdated": ("CWE-1104", "NIST SP 800-40"),
}


@dataclass(frozen=True)
class CvssBand:
    low: float
    high: float
    label: str


# CVSS v3.1 qualitative bands for quick severity guidance.
CVSS_BANDS: tuple[CvssBand, ...] = (
    CvssBand(0.0, 0.0, "None / Informational"),
    CvssBand(0.1, 3.9, "Low"),
    CvssBand(4.0, 6.9, "Medium"),
    CvssBand(7.0, 8.9, "High"),
    CvssBand(9.0, 10.0, "Critical"),
)
