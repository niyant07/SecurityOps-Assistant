"""Tests for the loopback web API of the single assessment screen."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from securityops.assessment.analysis import LLMProvider, ProviderError
from securityops.web import AssessmentSession, _make_handler


class _Config(dict):
    def get(self, key, default=None):  # noqa: ANN001, ANN202
        return super().get(key, default)


class _Site(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<title>Lab</title>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class _Offline(LLMProvider):
    name = "Offline model"

    def complete(self, system: str, prompt: str) -> str:
        raise ProviderError("Model is offline.")


@pytest.fixture()
def lab() -> Iterator[str]:
    site = ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{site.server_port}"
    site.shutdown()
    site.server_close()


def _serve(config: dict) -> tuple[ThreadingHTTPServer, AssessmentSession]:
    session = AssessmentSession(_Config({"assessment.timeout_seconds": 2, **config}),
                                provider=_Offline())
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(session))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, session


@pytest.fixture()
def server() -> Iterator[tuple[AssessmentSession, int]]:
    httpd, session = _serve({})
    yield session, httpd.server_port
    httpd.shutdown()
    httpd.server_close()


def _post(port: int, path: str, body: dict[str, object],
          headers: dict[str, str] | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}",
                 **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _get(port: int, path: str) -> tuple[int, dict[str, str], bytes]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _wait(port: int, done: callable) -> dict:  # type: ignore[valid-type]
    deadline = time.time() + 30
    while time.time() < deadline:
        state = json.loads(_get(port, "/api/status")[2])
        if done(state):
            return state
        time.sleep(0.1)
    raise AssertionError("timed out")


def test_full_workflow_gather_analyze_report(server: tuple[AssessmentSession, int],
                                             lab: str) -> None:
    _session, port = server
    assert _post(port, "/api/assess", {"target": lab, "authorized": True})[0] == 200
    state = _wait(port, lambda s: s["status"] == "done")
    assert all(step["status"] == "done" for step in state["steps"])
    assert state["scan"]["http"]["http"]["status"] == 200

    assert _post(port, "/api/analyze", {})[0] == 200
    state = _wait(port, lambda s: s["analysis"] is not None)
    assert state["analysis"]["source"] == "rules"           # model offline → fallback
    assert "Model is offline" in state["analysis"]["error"]
    assert state["analysis"]["findings"]

    status, headers, body = _get(port, "/api/report?format=html")
    assert status == 200
    assert headers["Content-Disposition"].startswith("attachment")
    assert "sandbox" in headers["Content-Security-Policy"]
    assert b"Executive summary" in body and b"Limitations" in body


def test_assessment_requires_authorization(server: tuple[AssessmentSession, int]) -> None:
    session, port = server
    status, body = _post(port, "/api/assess", {"target": "example.com", "authorized": False})
    assert status == 400 and "authorized" in body["error"]
    assert session.status == "idle"


def test_invalid_target_gets_friendly_error(server: tuple[AssessmentSession, int]) -> None:
    _session, port = server
    status, body = _post(port, "/api/assess", {"target": "not a host", "authorized": True})
    assert status == 400 and "domain" in body["error"]


def test_configured_scope_is_enforced() -> None:
    httpd, session = _serve({"assessment.allowed_targets": ["*.lab.test", "127.0.0.1"],
                             "assessment.blocked_targets": ["admin.lab.test"]})
    port = httpd.server_port
    try:
        status, body = _post(port, "/api/assess", {"target": "example.com", "authorized": True})
        assert status == 400 and "allowed_targets" in body["error"]
        status, body = _post(port, "/api/assess",
                             {"target": "admin.lab.test", "authorized": True})
        assert status == 400 and "blocked_targets" in body["error"]
        assert session.status == "idle"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_report_and_analysis_need_a_scan_first(server: tuple[AssessmentSession, int]) -> None:
    _session, port = server
    assert _post(port, "/api/analyze", {})[0] == 409
    assert _get(port, "/api/report?format=html")[0] == 400


@pytest.mark.parametrize("headers", [
    {"Content-Type": "text/plain"},
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_cross_site_posts_are_rejected(server: tuple[AssessmentSession, int],
                                       headers: dict[str, str]) -> None:
    session, port = server
    status, body = _post(port, "/api/assess",
                         {"target": "example.com", "authorized": True}, headers)
    assert status == 403 and "Cross-site" in body["error"]
    assert session.status == "idle"


# --------------------------------------------------------------------------- #
# Public (hosted) mode
# --------------------------------------------------------------------------- #
@pytest.fixture()
def public_server() -> Iterator[tuple[AssessmentSession, int]]:
    session = AssessmentSession(_Config({"assessment.timeout_seconds": 2}),
                                provider=_Offline(), public=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(session, "s3cret-code"))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield session, httpd.server_port
    httpd.shutdown()
    httpd.server_close()


def _public_post(port: int, body: dict, code: str | None) -> tuple[int, dict]:
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    if code is not None:
        headers["X-Access-Code"] = code
    return _post(port, "/api/assess", body, headers)


def test_public_mode_requires_access_code(public_server: tuple[AssessmentSession, int]) -> None:
    session, port = public_server
    assert _get(port, "/healthz")[0] == 200
    assert _get(port, "/")[0] == 200                       # the UI itself loads
    status, _h, body = _get(port, "/api/status")
    assert status == 401 and json.loads(body)["code_required"]
    for code in (None, "wrong"):
        status, _ = _public_post(port, {"target": "example.com", "authorized": True}, code)
        assert status == 401
    assert session.status == "idle"


def test_public_mode_blocks_internal_targets(public_server: tuple[AssessmentSession, int]) -> None:
    session, port = public_server
    for target in ("127.0.0.1", "localhost", "10.0.0.5", "169.254.169.254"):
        status, body = _public_post(port, {"target": target, "authorized": True},
                                    "s3cret-code")
        assert status == 400 and "private or internal" in body["error"]
    assert session.status == "idle"


def test_public_mode_checks_origin_against_host(
        public_server: tuple[AssessmentSession, int]) -> None:
    _session, port = public_server
    status, _ = _post(port, "/api/assess", {"target": "x", "authorized": True},
                      {"Origin": "https://evil.example", "X-Access-Code": "s3cret-code"})
    assert status == 403
