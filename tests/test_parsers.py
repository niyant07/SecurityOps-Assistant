"""Tests for tool-output findings extraction."""

from __future__ import annotations

from securityops.workflow import parsers

NMAP_OUTPUT = """Starting Nmap 7.94
Nmap scan report for example.com (93.184.216.34)
Host is up (0.011s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    nginx 1.18.0
443/tcp  open  https   nginx 1.18.0
OS details: Linux 5.4 - 5.15
"""


def test_nmap_ports_and_host() -> None:
    findings = parsers.extract_findings("nmap", NMAP_OUTPUT)
    joined = "\n".join(findings)
    assert "Host up: example.com (93.184.216.34)" in findings
    assert "Open port 22/tcp" in joined
    assert "Open port 443/tcp" in joined
    assert any(f.startswith("OS:") for f in findings)


def test_nikto_prioritizes_issues() -> None:
    output = (
        "+ Server: Apache/2.2.8\n"
        "+ The anti-clickjacking X-Frame-Options header is not present.\n"
        "+ OSVDB-3268: /admin/: Directory indexing found.\n"
    )
    findings = parsers.extract_findings("nikto", output)
    assert any("X-Frame-Options" in f for f in findings)
    assert any("OSVDB-3268" in f for f in findings)


def test_web_paths_parser() -> None:
    output = "Status: 200  /admin\nStatus: 301  /login\nStatus: 403 /private\n"
    findings = parsers.extract_findings("gobuster", output)
    assert any("/admin" in f for f in findings)
    assert any("HTTP 301" in f for f in findings)


def test_generic_fallback_finds_cve() -> None:
    findings = parsers.extract_findings("unknown_tool", "matches CVE-2021-44228 here")
    assert any("CVE-2021-44228" in f for f in findings)


def test_empty_output_returns_empty() -> None:
    assert parsers.extract_findings("nmap", "") == []


def test_parser_never_raises_on_junk() -> None:
    # Binary-ish / malformed content must not crash extraction.
    junk = "\x00\xff not real output )(*&^%$#@!"
    assert isinstance(parsers.extract_findings("nmap", junk), list)
