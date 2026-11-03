"""Tests for the three assessment components: gather, analysis, report."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from securityops.assessment import analysis as an
from securityops.assessment.gather import (
    ScanResult,
    TargetError,
    check_security_headers,
    detect_technologies,
    parse_target,
    run_assessment,
)
from securityops.assessment.report import PdfUnavailableError, render_html, render_pdf


class _WeakSite(BaseHTTPRequestHandler):
    """A lab site with typical weaknesses: no security headers, leaky banner."""

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        body = (b"<html><head><title>Lab Shop</title>"
                b"<meta name='generator' content='WordPress 6.1'></head>"
                b"<body><script src='/wp-content/app.js'></script></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def lab() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _WeakSite)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def lab_scan(lab: str) -> ScanResult:
    return run_assessment(lab, timeout=3)


# --------------------------------------------------------------------------- #
# Component 1: information gathering
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text,host,port", [
    ("example.com", "example.com", None),
    ("https://Example.COM/path", "example.com", None),
    ("127.0.0.1:8080", "127.0.0.1", 8080),
    ("localhost", "localhost", None),
])
def test_parse_target_accepts_hosts_ips_and_urls(text: str, host: str, port: int | None) -> None:
    target = parse_target(text)
    assert (target.host, target.port) == (host, port)


@pytest.mark.parametrize("text", ["", "two words.com", "ftp://example.com", "exa_mple..com",
                                  "http://example.com:99999", "a" * 400])
def test_parse_target_rejects_invalid_input(text: str) -> None:
    with pytest.raises(TargetError):
        parse_target(text)


def test_assessment_collects_results_from_lab_site(lab_scan: ScanResult) -> None:
    assert lab_scan.dns["A"] == ["127.0.0.1"]
    assert lab_scan.http["http"]["status"] == 200
    assert lab_scan.http["http"]["title"] == "Lab Shop"
    assert "body" not in lab_scan.http["http"]          # bodies are not kept
    assert lab_scan.tls.get("skipped")                   # http:// target → no TLS check
    missing = {h["name"] for h in lab_scan.headers if h["applicable"] and not h["present"]}
    assert "Content-Security-Policy" in missing
    assert "Strict-Transport-Security" not in missing    # HSTS only applies to HTTPS
    techs = {t["name"] for t in lab_scan.technologies}
    assert {"WordPress", "PHP", "WordPress 6.1"} <= techs
    assert "Lab Shop" not in lab_scan.summary and "127.0.0.1" in lab_scan.summary


def test_progress_callback_reports_every_step(lab: str) -> None:
    events: list[tuple[str, str]] = []
    run_assessment(lab, lambda step, status: events.append((step, status)), timeout=3)
    assert [step for step, status in events if status == "done"] == [
        "DNS records", "HTTP/HTTPS response", "TLS certificate", "Security headers",
        "Technologies", "Summary"]


def test_unreachable_target_is_reported_not_raised() -> None:
    scan = run_assessment("http://127.0.0.1:1", timeout=2)
    assert scan.http == {} and scan.errors


def test_header_check_accepts_csp_frame_ancestors() -> None:
    response = {"headers": {"Content-Security-Policy": "frame-ancestors 'none'"},
                "final_url": "https://example.test/"}
    rows = {r["name"]: r for r in check_security_headers(response)}
    assert rows["X-Frame-Options"]["present"]
    assert rows["Strict-Transport-Security"]["applicable"]


def test_technology_detection_from_headers_and_cookies() -> None:
    response = {"headers": {"Server": "nginx/1.18.0", "CF-RAY": "x"},
                "cookies": ["JSESSIONID=1"], "body": "<script src=/_next/static/a.js>"}
    names = {t["name"] for t in detect_technologies(response)}
    assert names == {"nginx/1.18.0", "Next.js", "Java", "Cloudflare"}


# --------------------------------------------------------------------------- #
# Component 2: AI analysis
# --------------------------------------------------------------------------- #
class _FakeProvider(an.LLMProvider):
    name = "Fake model"

    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.prompts: list[str] = []

    def complete(self, system: str, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.answer


class _DownProvider(an.LLMProvider):
    name = "Ollama (llama3)"

    def complete(self, system: str, prompt: str) -> str:
        raise an.ProviderError("The local Ollama server is not reachable.")


def test_rule_findings_are_evidence_backed(lab_scan: ScanResult) -> None:
    findings = {f.title: f for f in an.rule_based_findings(lab_scan)}
    csp = findings["Content-Security-Policy not set"]
    assert csp.status == an.CONFIRMED and csp.severity == "Medium"
    banner = findings["Software version disclosed in X-Powered-By header"]
    assert banner.status == an.POTENTIAL and "PHP/7.4.3" in banner.evidence
    assert findings["Cookie 'PHPSESSID' missing security flags"].status == an.CONFIRMED
    assert all(f.evidence and f.remediation for f in findings.values())


def test_ai_answer_is_merged_but_cannot_rewrite_evidence(lab_scan: ScanResult) -> None:
    baseline = an.rule_based_findings(lab_scan)
    first = baseline[0]
    answer = json.dumps({
        "executive_summary": "The site needs basic hardening.",
        "findings": [
            {"id": first.id, "severity": "High", "status": "Potential risk",
             "evidence": "made up", "why_it_matters": "Better explanation.",
             "remediation": "Better fix."},
            {"id": None, "title": "Outdated PHP", "severity": "Critical",
             "status": "Confirmed", "evidence": "X-Powered-By: PHP/7.4.3",
             "why_it_matters": "PHP 7.4 is end-of-life.", "remediation": "Upgrade PHP."},
            {"id": None, "title": "No evidence item", "severity": "High"},
            {"id": "F1", "severity": "Catastrophic"},
        ]})
    result = an.analyze(lab_scan, _FakeProvider(f"```json\n{answer}\n```"))
    assert result.source == "ai" and not result.error
    assert result.executive_summary == "The site needs basic hardening."
    merged = {f.id: f for f in result.findings}
    assert merged[first.id].severity == "High"
    assert merged[first.id].evidence == first.evidence        # evidence stays observed
    assert merged[first.id].status == first.status            # status stays observed
    assert merged[first.id].why_it_matters == "Better explanation."
    assert merged["AI1"].status == an.POTENTIAL               # AI cannot confirm
    assert "No evidence item" not in {f.title for f in result.findings}
    assert len(result.findings) == len(baseline) + 1          # nothing dropped


def test_prompt_contains_results_but_not_page_bodies(lab_scan: ScanResult) -> None:
    provider = _FakeProvider("{}")
    an.analyze(lab_scan, provider)
    assert "Content-Security-Policy" in provider.prompts[0]
    assert "wp-content/app.js" not in provider.prompts[0]


def test_unavailable_model_falls_back_with_message(lab_scan: ScanResult) -> None:
    result = an.analyze(lab_scan, _DownProvider())
    assert result.source == "rules"
    assert "not reachable" in result.error
    assert result.findings and result.executive_summary


def test_invalid_model_json_falls_back(lab_scan: ScanResult) -> None:
    result = an.analyze(lab_scan, _FakeProvider("Sorry, I can't help with that."))
    assert result.source == "rules" and "expected JSON format" in result.error


def test_make_provider_reads_config() -> None:
    class Cfg(dict):
        def get(self, key, default=None):  # noqa: ANN001, ANN202
            return super().get(key, default)

    assert isinstance(an.make_provider(Cfg({"llm.provider": "none"})), an.LLMProvider)
    assert isinstance(an.make_provider(Cfg({"llm.provider": "anthropic"})), an.AnthropicProvider)
    assert isinstance(an.make_provider(Cfg({})), an.OllamaProvider)
    assert type(an.make_provider(Cfg({"llm.enabled": False}))) is an.LLMProvider


# --------------------------------------------------------------------------- #
# Component 3: report
# --------------------------------------------------------------------------- #
def test_html_report_has_required_sections(lab_scan: ScanResult) -> None:
    analysis = an.analyze(lab_scan, _DownProvider())
    html = render_html(lab_scan, analysis)
    for section in ("Scope", "Executive summary", "Findings", "Evidence collected",
                    "Limitations", "Remediation", lab_scan.target, lab_scan.started_at):
        assert section in html
    assert "Content-Security-Policy not set" in html


def test_report_escapes_untrusted_values(lab_scan: ScanResult) -> None:
    analysis = an.analyze(lab_scan, _DownProvider())
    analysis.executive_summary = "<script>alert(1)</script>"
    assert "<script>alert(1)</script>" not in render_html(lab_scan, analysis)


def test_pdf_without_weasyprint_gives_clear_error() -> None:
    pytest.importorskip("pytest")
    try:
        import weasyprint  # noqa: F401
    except Exception:  # noqa: BLE001
        with pytest.raises(PdfUnavailableError, match="Print"):
            render_pdf("<p>x</p>")
    else:
        assert render_pdf("<p>x</p>").startswith(b"%PDF")
