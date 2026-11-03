"""Tests for the loopback web API: CSRF guard, validation, and plan lifecycle."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer

import pytest
from PySide6.QtCore import QCoreApplication

from securityops.core.config import load_config
from securityops.core.context import AppContext
from securityops.core.database import Database
from securityops.core.tasks import TaskManager
from securityops.core.tools import ToolRegistry
from securityops.web import WebState, _make_handler

# A documentation-range IP keeps the planner from doing DNS lookups.
_TARGET = "192.0.2.10"


@pytest.fixture()
def server(db: Database, all_installed_tools: ToolRegistry) -> Iterator[tuple[WebState, int]]:
    QCoreApplication.instance() or QCoreApplication([])
    context = AppContext(load_config(), db, TaskManager(), all_installed_tools)
    state = WebState(context)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield state, httpd.server_port
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)


def _post(port: int, path: str, body: dict[str, object],
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json",
                 "Origin": f"http://127.0.0.1:{port}",
                 **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _create_project(port: int, target: str = _TARGET) -> tuple[int, dict[str, object]]:
    return _post(port, "/api/project",
                 {"name": "Lab", "target": target, "authorized": True})


def test_same_origin_json_post_creates_project(server: tuple[WebState, int]) -> None:
    state, port = server
    status, _ = _create_project(port)
    assert status == 201
    assert state.target == _TARGET


@pytest.mark.parametrize("headers", [
    {"Content-Type": "text/plain"},                       # form / no-cors fetch
    {"Origin": "https://evil.example"},                   # foreign page
    {"Origin": "null"},                                   # sandboxed iframe / file://
    {"Sec-Fetch-Site": "cross-site"},                     # fetch metadata
])
def test_cross_site_posts_are_rejected(server: tuple[WebState, int],
                                       headers: dict[str, str]) -> None:
    state, port = server
    status, body = _post(port, "/api/project",
                         {"name": "x", "target": _TARGET, "authorized": True}, headers)
    assert status == 403
    assert "Cross-site" in str(body["error"])
    assert state.project_id is None


def test_quoted_url_target_is_rejected(server: tuple[WebState, int]) -> None:
    state, port = server
    status, _ = _create_project(port, "http://example.test/a'b")
    assert status == 400
    assert state.project_id is None


def test_plan_can_be_reset_and_project_closed(server: tuple[WebState, int]) -> None:
    state, port = server
    _create_project(port)
    status, _ = _post(port, "/api/plan", {"goal": "Find open ports"})
    assert status == 200
    assert state.plan is not None and state.plan.steps

    status, _ = _post(port, "/api/plan/reset", {})
    assert status == 200
    assert state.plan is None
    assert state.project_id is not None

    status, _ = _post(port, "/api/project/close", {})
    assert status == 200
    assert state.project_id is None
    assert state.target == ""


@pytest.mark.parametrize("path", ["/api/plan/reset", "/api/project/close"])
def test_reset_and_close_refused_while_running(server: tuple[WebState, int], path: str) -> None:
    state, port = server
    _create_project(port)
    _post(port, "/api/plan", {"goal": "Find open ports"})
    state.running = True
    status, _ = _post(port, path, {})
    assert status == 400
    assert state.plan is not None
