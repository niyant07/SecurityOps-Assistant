"""Kali tool catalog, detection, and safe command building.

The catalog is data-driven: each :class:`ToolSpec` describes a tool, how to
detect it, its category, a short description, and a *template* used to build a
suggested command line. Templates never run automatically — they are shown to
the operator for review and only executed on an explicit action.

Detection uses :func:`shutil.which` plus any ``extra_paths`` from config.
Built-in checks (``securityops/checks.py``) need no install: they run with the
current Python interpreter and are always available.
"""

from __future__ import annotations

import shlex
import shutil
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .logging_config import get_logger

_LOG = get_logger("tools")

# Standalone, stdlib-only script that implements the built-in checks.
CHECKS_SCRIPT = str(Path(__file__).resolve().parent.parent / "checks.py")


class ToolCategory(str, Enum):
    RECON = "Reconnaissance"
    ENUM = "Enumeration"
    WEB = "Web Application"
    VULN = "Vulnerability"
    EXPLOIT = "Exploitation (launch only)"
    PASSWORD = "Password / Hash"
    WIRELESS = "Wireless"
    TRAFFIC = "Traffic Analysis"


@dataclass(frozen=True)
class ToolSpec:
    """Static description of an external security tool."""

    key: str
    name: str
    binary: str
    category: ToolCategory
    description: str
    # {target} is substituted with the chosen target. Extra {placeholders} are
    # filled from the params dict passed to build_command().
    template: str = "{binary} {target}"
    # Interactive/console tools should be launched inside a terminal emulator.
    interactive: bool = False
    # Free-form usage / safety notes surfaced by the assistant.
    notes: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)
    # Built-in checks run with the current Python interpreter; no install needed.
    builtin: bool = False


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
CATALOG: tuple[ToolSpec, ...] = (
    ToolSpec(
        "nmap", "Nmap", "nmap", ToolCategory.RECON,
        "Network mapper: host discovery, port scanning, service/version and OS detection.",
        template="{binary} -sV -sC {target}",
        notes="Use -Pn if hosts block ping. -T4 speeds scans on reliable networks.",
    ),
    ToolSpec(
        "amass", "Amass", "amass", ToolCategory.RECON,
        "In-depth DNS enumeration and attack-surface mapping.",
        template="{binary} enum -d {target}",
    ),
    ToolSpec(
        "subfinder", "Subfinder", "subfinder", ToolCategory.RECON,
        "Passive subdomain discovery using public sources.",
        template="{binary} -d {target}",
    ),
    ToolSpec(
        "theharvester", "theHarvester", "theHarvester", ToolCategory.RECON,
        "Gather emails, subdomains, hosts and names from public sources (OSINT).",
        template="{binary} -d {target} -b all",
        aliases=("theharvester",),
    ),
    ToolSpec(
        "dnsrecon", "DNSRecon", "dnsrecon", ToolCategory.RECON,
        "DNS enumeration: records, zone transfers, brute force.",
        template="{binary} -d {target}",
    ),
    ToolSpec(
        "naabu", "Naabu", "naabu", ToolCategory.ENUM,
        "Fast SYN/CONNECT port scanner.",
        template="{binary} -host {target}",
    ),
    ToolSpec(
        "httpx", "httpx", "httpx", ToolCategory.ENUM,
        "Fast multi-purpose HTTP toolkit; probes live web servers.",
        template="{binary} -u {target} -sc -title -tech-detect",
    ),
    ToolSpec(
        "whatweb", "WhatWeb", "whatweb", ToolCategory.ENUM,
        "Website fingerprinting: CMS, frameworks, servers, versions.",
        template="{binary} {target}",
    ),
    ToolSpec(
        "gobuster", "Gobuster", "gobuster", ToolCategory.WEB,
        "Directory/file, DNS and vhost brute forcing.",
        template="{binary} dir -u {target} -w {wordlist}",
        notes="Requires a wordlist, e.g. /usr/share/wordlists/dirb/common.txt.",
    ),
    ToolSpec(
        "ffuf", "ffuf", "ffuf", ToolCategory.WEB,
        "Fast web fuzzer for content and parameter discovery.",
        template="{binary} -u {target}/FUZZ -w {wordlist}",
    ),
    ToolSpec(
        "dirsearch", "Dirsearch", "dirsearch", ToolCategory.WEB,
        "Web path scanner for hidden files and directories.",
        template="{binary} -u {target}",
    ),
    ToolSpec(
        "nikto", "Nikto", "nikto", ToolCategory.VULN,
        "Web server scanner for known vulnerabilities and misconfigurations.",
        template="{binary} -h {target}",
    ),
    ToolSpec(
        "sqlmap", "sqlmap", "sqlmap", ToolCategory.VULN,
        "Automated SQL injection detection and exploitation.",
        template="{binary} -u {target} --batch",
        notes="Only test parameters you are authorized to. --batch uses defaults.",
    ),
    ToolSpec(
        "searchsploit", "Searchsploit", "searchsploit", ToolCategory.VULN,
        "Offline search of the Exploit-DB archive.",
        template="{binary} {target}",
    ),
    ToolSpec(
        "burpsuite", "Burp Suite", "burpsuite", ToolCategory.WEB,
        "Web proxy / application security testing suite (launch only).",
        template="{binary}", interactive=True,
        notes="Launched only; configure your browser proxy to intercept traffic.",
        aliases=("burp",),
    ),
    ToolSpec(
        "wireshark", "Wireshark", "wireshark", ToolCategory.TRAFFIC,
        "Network protocol analyzer (launch only).",
        template="{binary}", interactive=True,
    ),
    ToolSpec(
        "metasploit", "Metasploit Console", "msfconsole", ToolCategory.EXPLOIT,
        "Exploitation framework — launches the interactive console only.",
        template="{binary}", interactive=True,
        notes="Console is launched for manual, authorized use. No auto-exploitation.",
        aliases=("msfconsole", "msf"),
    ),
    ToolSpec(
        "hashcat", "Hashcat", "hashcat", ToolCategory.PASSWORD,
        "GPU-accelerated password hash cracking.",
        template="{binary} -m {mode} {hashfile} {wordlist}", interactive=True,
    ),
    ToolSpec(
        "hydra", "Hydra", "hydra", ToolCategory.PASSWORD,
        "Online login brute-forcer for many protocols.",
        template="{binary} -L {userlist} -P {passlist} {target}", interactive=True,
    ),
    ToolSpec(
        "john", "John the Ripper", "john", ToolCategory.PASSWORD,
        "Offline password hash cracker.",
        template="{binary} {hashfile}", interactive=True,
        aliases=("johntheripper",),
    ),
    ToolSpec(
        "aircrack", "Aircrack-ng", "aircrack-ng", ToolCategory.WIRELESS,
        "Cracks a captured WEP/WPA handshake against a wordlist.",
        template="{binary} {capturefile} -w {wordlist}", interactive=True,
        notes="Final step of the aircrack-ng suite. Only use on a handshake you "
              "captured from a network you own or are explicitly authorized to test.",
        aliases=("aircrack-ng",),
    ),
    ToolSpec(
        "airmon", "Airmon-ng", "airmon-ng", ToolCategory.WIRELESS,
        "Enables monitor mode on a wireless interface (step 1 of a WiFi audit).",
        template="{binary} start {target}", interactive=True,
        notes="target = wireless interface, e.g. wlan0. Creates a monitor-mode "
              "interface (e.g. wlan0mon) used by airodump-ng/aireplay-ng.",
        aliases=("airmon-ng",),
    ),
    ToolSpec(
        "airodump", "Airodump-ng", "airodump-ng", ToolCategory.WIRELESS,
        "Captures wireless traffic and WPA handshakes on a channel (step 2).",
        template="{binary} {target}", interactive=True,
        notes="target = monitor-mode interface, e.g. wlan0mon. Add -c <channel> "
              "--bssid <AP MAC> -w <output-prefix> manually to focus on one "
              "authorized access point.",
        aliases=("airodump-ng",),
    ),
    ToolSpec(
        "aireplay", "Aireplay-ng", "aireplay-ng", ToolCategory.WIRELESS,
        "Sends deauthentication frames to force a handshake capture (optional step 3).",
        template="{binary} --deauth {count} -a {bssid} {target}", interactive=True,
        notes="⚠ Deauthenticates ALL clients on the target access point, not just "
              "your own device — only run against an AP you own or have explicit "
              "written authorization to test, and be aware of who else it disrupts.",
        aliases=("aireplay-ng",),
    ),
    # ----------------------------------------------------------------------- #
    # Built-in checks: no install needed (see securityops/checks.py)
    # ----------------------------------------------------------------------- #
    ToolSpec(
        "sops-dns", "Built-in DNS Lookup", "python", ToolCategory.RECON,
        "Resolves the target's IPv4/IPv6 addresses and reverse DNS names.",
        template="{binary} {script} dns {target}", builtin=True,
    ),
    ToolSpec(
        "sops-ports", "Built-in Port Scan", "python", ToolCategory.ENUM,
        "TCP connect scan of 31 common service ports (SSH, web, databases, RDP, ...).",
        template="{binary} {script} ports {target}", builtin=True,
        notes="Connect scan only: no SYN packets, OS detection or service probing.",
    ),
    ToolSpec(
        "sops-http", "Built-in HTTP Probe", "python", ToolCategory.ENUM,
        "Fetches the site and fingerprints the server, frameworks and CMS.",
        template="{binary} {script} http {target}", builtin=True,
    ),
    ToolSpec(
        "sops-headers", "Built-in Header Audit", "python", ToolCategory.VULN,
        "Checks security headers, cookie flags, CORS, version banners and HTTPS redirect.",
        template="{binary} {script} headers {target}", builtin=True,
    ),
    ToolSpec(
        "sops-tls", "Built-in TLS Inspector", "python", ToolCategory.VULN,
        "Validates the certificate (trust, hostname, expiry) and the negotiated protocol.",
        template="{binary} {script} tls {target}", builtin=True,
    ),
    ToolSpec(
        "sops-paths", "Built-in Exposure Check", "python", ToolCategory.WEB,
        "Requests 20 well-known sensitive paths (.git, .env, admin panels, backups).",
        template="{binary} {script} paths {target}", builtin=True,
        notes="About 20 requests with a short delay between them; no wordlist brute force.",
    ),
    ToolSpec(
        "sops-securitytxt", "Built-in security.txt Lookup", "python", ToolCategory.RECON,
        "Finds the published security contact (RFC 9116) for responsible disclosure.",
        template="{binary} {script} securitytxt {target}", builtin=True,
    ),
)

CATALOG_BY_KEY: dict[str, ToolSpec] = {spec.key: spec for spec in CATALOG}

# Official sites for documentation and downloads of the external tools.
HOMEPAGES: dict[str, str] = {
    "nmap": "https://nmap.org",
    "amass": "https://github.com/owasp-amass/amass",
    "subfinder": "https://github.com/projectdiscovery/subfinder",
    "theharvester": "https://github.com/laramies/theHarvester",
    "dnsrecon": "https://github.com/darkoperator/dnsrecon",
    "naabu": "https://github.com/projectdiscovery/naabu",
    "httpx": "https://github.com/projectdiscovery/httpx",
    "whatweb": "https://github.com/urbanadventurer/WhatWeb",
    "gobuster": "https://github.com/OJ/gobuster",
    "ffuf": "https://github.com/ffuf/ffuf",
    "dirsearch": "https://github.com/maurosoria/dirsearch",
    "nikto": "https://github.com/sullo/nikto",
    "sqlmap": "https://sqlmap.org",
    "searchsploit": "https://www.exploit-db.com/searchsploit",
    "burpsuite": "https://portswigger.net/burp",
    "wireshark": "https://www.wireshark.org",
    "metasploit": "https://www.metasploit.com",
    "hashcat": "https://hashcat.net/hashcat/",
    "hydra": "https://github.com/vanhauser-thc/thc-hydra",
    "john": "https://www.openwall.com/john/",
    "aircrack": "https://www.aircrack-ng.org",
    "airmon": "https://www.aircrack-ng.org",
    "airodump": "https://www.aircrack-ng.org",
    "aireplay": "https://www.aircrack-ng.org",
}


@dataclass
class DetectedTool:
    """A catalog entry paired with its detection result."""

    spec: ToolSpec
    path: str | None

    @property
    def installed(self) -> bool:
        return self.path is not None


class MissingParameterError(ValueError):
    """Raised when a command template needs a placeholder that was not supplied."""


class ToolRegistry:
    """Detects installed tools and builds review-only command lines."""

    def __init__(self, extra_paths: list[str] | None = None) -> None:
        self._extra_paths = extra_paths or []
        self._detected: dict[str, DetectedTool] = {}
        self.refresh()

    def refresh(self) -> None:
        """Re-scan the system for each catalog tool."""
        search_path = self._build_search_path()
        for spec in CATALOG:
            if spec.builtin:
                self._detected[spec.key] = DetectedTool(spec=spec, path=sys.executable)
                continue
            path = shutil.which(spec.binary, path=search_path)
            if path is None:
                for alias in spec.aliases:
                    path = shutil.which(alias, path=search_path)
                    if path:
                        break
            self._detected[spec.key] = DetectedTool(spec=spec, path=path)
        installed = sum(1 for d in self._detected.values() if d.installed)
        _LOG.info("Tool detection complete: %d/%d installed", installed, len(CATALOG))

    def _build_search_path(self) -> str | None:
        import os
        import sys

        parts = [p for p in self._extra_paths if p]
        if sys.platform == "win32":
            win_paths = [
                r"C:\Program Files\Nmap",
                r"C:\Program Files (x86)\Nmap",
                r"C:\ProgramData\chocolatey\bin",
                r"C:\Tools",
            ]
            parts.extend([p for p in win_paths if os.path.isdir(p)])
        env_path = os.environ.get("PATH", "")
        if env_path:
            parts.append(env_path)
        return os.pathsep.join(parts) if parts else None

    # -- queries ---------------------------------------------------------- #
    def all(self) -> list[DetectedTool]:
        return list(self._detected.values())

    def installed(self) -> list[DetectedTool]:
        return [d for d in self._detected.values() if d.installed]

    def by_category(self) -> dict[ToolCategory, list[DetectedTool]]:
        grouped: dict[ToolCategory, list[DetectedTool]] = {}
        for detected in self._detected.values():
            grouped.setdefault(detected.spec.category, []).append(detected)
        return grouped

    def get(self, key: str) -> DetectedTool | None:
        return self._detected.get(key)

    # -- command building ------------------------------------------------- #
    def build_command(self, key: str, target: str, params: dict[str, str] | None = None) -> str:
        """Render a tool's command template into a review-only command string.

        Raises
        ------
        KeyError: unknown tool key.
        MissingParameterError: a required ``{placeholder}`` was not provided.
        """
        detected = self._detected.get(key)
        if detected is None:
            raise KeyError(f"Unknown tool: {key}")

        spec = detected.spec
        binary = detected.path or spec.binary
        values: dict[str, str] = {"binary": binary, "target": target}
        if spec.builtin:
            values["script"] = CHECKS_SCRIPT
        values.update(params or {})
        # Quote every value so paths with spaces or backslashes (Windows) and
        # unusual targets survive split_command() as single arguments.
        values = {name: shlex.quote(str(value)) for name, value in values.items()}

        try:
            return spec.template.format(**values).strip()
        except KeyError as exc:
            missing = str(exc).strip("'")
            raise MissingParameterError(
                f"Tool '{spec.name}' needs a value for '{{{missing}}}'."
            ) from exc

    @staticmethod
    def split_command(command: str) -> list[str]:
        """Safely split a command string into argv without invoking a shell."""
        return shlex.split(command)
