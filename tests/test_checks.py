"""Tests for the built-in, install-free checks and how plans use them."""

from __future__ import annotations

import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from securityops.bugbounty.triage import triage_step
from securityops.core.tools import CHECKS_SCRIPT, ToolRegistry
from securityops.workflow.parsers import extract_findings
from securityops.workflow.planner import RuleBasedPlanner


class _Site(BaseHTTPRequestHandler):
    """A deliberately weak site: no security headers, leaky files."""

    pages = {
        "/": ("text/html", "<html><head><title>Test Shop</title></head>"
                           "<body><script src=/wp-content/x.js></script></body></html>"),
        "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
        "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin\n"),
    }

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        page = self.pages.get(self.path)
        if page is None:
            self.send_error(404)
            return
        body = page[1].encode()
        self.send_response(200)
        self.send_header("Content-Type", page[0])
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "PHPSESSID=abc; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def site() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def _run(check: str, target: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, CHECKS_SCRIPT, check, target],
                          capture_output=True, text=True, timeout=120)


def test_http_probe_fingerprints_site(site: str) -> None:
    result = _run("http", site)
    assert result.returncode == 0
    assert "[200] [Test Shop]" in result.stdout
    assert "+ Technology: WordPress" in result.stdout
    assert "+ Technology: PHP" in result.stdout


def test_header_audit_reports_missing_headers_and_cookie_flags(site: str) -> None:
    result = _run("headers", site)
    assert result.returncode == 0
    assert "+ The Content-Security-Policy header is not present" in result.stdout
    assert "+ Cookie 'PHPSESSID' is set without HttpOnly, SameSite." in result.stdout
    assert "+ X-Powered-By: PHP/7.4.3" in result.stdout


def test_exposure_check_confirms_sensitive_files(site: str) -> None:
    result = _run("paths", site)
    assert result.returncode == 0
    assert "Status: 200 /.git/HEAD" in result.stdout
    assert "+ Sensitive file exposed: /.git/HEAD (contents confirmed)" in result.stdout
    assert "/.env" not in result.stdout  # 404s are not reported


def test_builtin_output_triages_into_candidates(site: str) -> None:
    output = _run("paths", site).stdout + _run("headers", site).stdout
    findings = extract_findings("sops-paths", output)
    titles = {c.title for c in triage_step("sops-paths", site, findings)}
    assert "Sensitive file exposed: /.git/HEAD" in titles
    assert "Missing or weak security header" in titles
    assert "Cookie missing security flags" in titles


def test_tls_check_reports_plain_http_port(site: str) -> None:
    result = _run("tls", site)
    assert result.returncode == 1
    assert "No TLS service reachable" in result.stdout


def test_invalid_usage_is_rejected() -> None:
    assert _run("exploit", "example.test").returncode == 2


def test_builtin_commands_split_into_exact_argv() -> None:
    registry = ToolRegistry()
    argv = registry.split_command(registry.build_command("sops-ports", "192.0.2.10"))
    assert argv == [sys.executable, CHECKS_SCRIPT, "ports", "192.0.2.10"]


def test_planner_falls_back_to_builtins_without_kali() -> None:
    registry = ToolRegistry()
    for detected in registry.all():
        if not detected.spec.builtin:
            detected.path = None
    plan = RuleBasedPlanner(registry).plan("Assess the website https://example.test")
    keys = [step.tool_key for step in plan.steps]
    assert keys == ["sops-ports", "sops-http", "sops-headers", "sops-tls"]
    assert "Built-in checks stand in" in plan.summary


def test_planner_prefers_installed_kali_tools(all_installed_tools: ToolRegistry) -> None:
    plan = RuleBasedPlanner(all_installed_tools).plan("Find open ports on 192.0.2.10")
    assert [step.tool_key for step in plan.steps][:2] == ["nmap", "naabu"]
