"""Loopback-only browser interface for the SecurityOps workflow."""

from __future__ import annotations

import ipaddress
import json
import mimetypes
import sqlite3
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any
from urllib.parse import unquote, urlsplit

from PySide6.QtCore import QCoreApplication, QObject, Signal, Slot

from .app import build_context
from .core.context import AppContext
from .core.logging_config import get_logger
from .models import Asset, AssetType, Project, ScopeState
from .workflow.engine import WorkflowEngine
from .workflow.plan import StepStatus, WorkflowPlan
from .workflow.planner import extract_target, make_planner

_LOG = get_logger("web")
_MAX_BODY_BYTES = 64_000


def _normalized_target(value: str) -> str:
    """Normalize a target for exact matching against the authorized asset."""
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return ""
    if "://" in candidate:
        return f"{parsed.scheme.lower()}://{host}{parsed.path.rstrip('/')}"
    return host


class WebState(QObject):
    """Shared application state and Qt-thread workflow dispatch."""

    start_requested = Signal(object, int)
    cancel_requested = Signal()

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.planner = make_planner(context.tools, llm=context.llm)
        self.engine = WorkflowEngine(context)
        self.lock = threading.RLock()
        self.project_id: int | None = None
        self.target = ""
        self.plan: WorkflowPlan | None = None
        self.running = False
        self.log: list[str] = []
        self.start_requested.connect(self._start_workflow)
        self.cancel_requested.connect(self.engine.cancel)
        self.engine.audit.connect(self._append_log)
        self.engine.step_started.connect(self._step_started)
        self.engine.step_output.connect(self._step_output)
        self.engine.step_finished.connect(self._step_finished)
        self.engine.plan_finished.connect(self._plan_finished)

    @Slot(object, int)
    def _start_workflow(self, plan: WorkflowPlan, project_id: int) -> None:
        self.engine.run(plan, project_id)

    @Slot(str)
    def _append_log(self, line: str) -> None:
        with self.lock:
            self.log.append(line)
            self.log = self.log[-300:]

    @Slot(int)
    def _step_started(self, index: int) -> None:
        with self.lock:
            if self.plan:
                self.plan.steps[index].status = StepStatus.RUNNING

    @Slot(int, str)
    def _step_output(self, index: int, chunk: str) -> None:
        with self.lock:
            if self.plan:
                step = self.plan.steps[index]
                step.output = (step.output + chunk)[-50_000:]
                self.log.append(chunk)
                self.log = self.log[-300:]

    @Slot(int)
    def _step_finished(self, index: int) -> None:
        with self.lock:
            if self.plan:
                step = self.plan.steps[index]
                self.log.append(f"{step.title}: {step.status.value}")
                self.log = self.log[-300:]

    @Slot()
    def _plan_finished(self) -> None:
        with self.lock:
            self.running = False

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            project = (self.context.database.projects.get(self.project_id)
                       if self.project_id is not None else None)
            assets = (self.context.database.assets.list_for_project(self.project_id)
                      if self.project_id is not None else [])
            scans = (self.context.database.scans.list_for_project(self.project_id)
                     if self.project_id is not None else [])
            plan = self.plan
            return {
                "project": ({
                    "id": project.id,
                    "name": project.name,
                    "authorized": project.authorized,
                    "target": self.target,
                } if project else None),
                "assets": [{
                    "identifier": a.identifier,
                    "scope": a.scope.value,
                } for a in assets],
                "tools": [{
                    "key": tool.spec.key,
                    "name": tool.spec.name,
                    "category": tool.spec.category.value,
                    "installed": tool.installed,
                } for tool in self.context.tools.all()],
                "plan": ({
                    "goal": plan.goal,
                    "summary": plan.summary,
                    "refused": plan.refused,
                    "refusal_reason": plan.refusal_reason,
                    "steps": [{
                        "index": i,
                        "title": step.title,
                        "rationale": step.rationale,
                        "command": step.command,
                        "target": step.target,
                        "warning": step.warning,
                        "status": step.status.value,
                        "output": step.output,
                    } for i, step in enumerate(plan.steps)],
                } if plan else None),
                "running": self.running,
                "log": list(self.log),
                "scans": [{
                    "tool": scan.tool,
                    "status": scan.status.value,
                    "command": scan.command,
                    "exit_code": scan.exit_code,
                } for scan in scans[:20]],
            }


def _make_handler(state: WebState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecurityOpsLocal/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            if self.command == "GET" and urlsplit(self.path).path == "/api/state":
                return
            _LOG.info("HTTP %s - %s", self.address_string(), fmt % args)

        def _is_local_request(self) -> bool:
            try:
                address = ipaddress.ip_address(self.client_address[0])
            except ValueError:
                return False
            expected_port = self.server.server_port
            allowed_hosts = {
                f"127.0.0.1:{expected_port}",
                f"localhost:{expected_port}",
            }
            return address.is_loopback and self.headers.get("Host", "").lower() in allowed_hosts

        def _is_same_origin_post(self) -> bool:
            """Reject cross-site POSTs (CSRF) from pages open in the user's browser.

            Requiring ``application/json`` forces a CORS preflight that this server
            never answers, and any Origin / Sec-Fetch-Site the browser sends must
            identify this server itself.
            """
            content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if content_type != "application/json":
                return False
            fetch_site = self.headers.get("Sec-Fetch-Site", "").lower()
            if fetch_site and fetch_site not in {"same-origin", "none"}:
                return False
            origin = self.headers.get("Origin")
            if origin is None:
                return True
            port = self.server.server_port
            return origin.lower() in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

        def _json(self, status: HTTPStatus, value: object) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("Invalid request body length.") from exc
            if length <= 0 or length > _MAX_BODY_BYTES:
                raise ValueError("Request body must be between 1 byte and 64 KB.")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise TypeError("Request body must be a JSON object.")
            return data

        def do_GET(self) -> None:
            if not self._is_local_request():
                self._json(HTTPStatus.FORBIDDEN, {"error": "Loopback requests only."})
                return
            path = urlsplit(self.path).path
            if path == "/api/state":
                self._json(HTTPStatus.OK, state.snapshot())
            else:
                self._static(path)

        def _static(self, path: str) -> None:
            relative = unquote(path.lstrip("/")) or "index.html"
            parts = relative.split("/")
            if "\\" in relative or any(part in {".", ".."} for part in parts):
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
                return
            resource = files("securityops").joinpath("web", "dist", *parts)
            if not resource.is_file():
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
                return
            body = resource.read_bytes()
            content_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
            if content_type.startswith(("text/", "application/javascript")):
                content_type += "; charset=utf-8"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            if not self._is_local_request():
                self._json(HTTPStatus.FORBIDDEN, {"error": "Loopback requests only."})
                return
            if not self._is_same_origin_post():
                self._json(HTTPStatus.FORBIDDEN, {"error": "Cross-site requests are not allowed."})
                return
            try:
                data = self._body()
                if self.path == "/api/project":
                    self._create_project(data)
                elif self.path == "/api/project/close":
                    self._close_project()
                elif self.path == "/api/plan":
                    self._create_plan(data)
                elif self.path == "/api/plan/reset":
                    self._reset_plan()
                elif self.path == "/api/run":
                    self._run_steps(data)
                elif self.path == "/api/cancel":
                    self._cancel()
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except (OSError, sqlite3.Error, RuntimeError):
                _LOG.exception("Local web request failed")
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR,
                           {"error": "The request failed. Check the local application log."})

        def _create_project(self, data: dict[str, Any]) -> None:
            name = data.get("name")
            target = data.get("target")
            if not isinstance(name, str) or not name.strip() or len(name) > 120:
                raise ValueError("Enter a project name of 1–120 characters.")
            if not isinstance(target, str) or len(target) > 500:
                raise ValueError("Enter a valid hostname, IP address, or URL.")
            parsed = extract_target(target.strip())
            if not parsed or _normalized_target(parsed.raw) != _normalized_target(target):
                raise ValueError("Enter one hostname, IP address, or URL as the target.")
            if data.get("authorized") is not True:
                raise ValueError("Confirm that you own the target or have written authorization.")
            with state.lock:
                if state.running:
                    raise ValueError("Wait for the current workflow to finish first.")
                project = state.context.database.projects.create(
                    Project(name=name.strip(), authorized=True))
                if project.id is None:
                    raise RuntimeError("The database did not assign a project id.")
                state.context.database.assets.create(Asset(
                    project_id=project.id,
                    identifier=target.strip(),
                    asset_type=AssetType.URL if parsed.is_url else AssetType.HOST,
                    scope=ScopeState.IN_SCOPE,
                ))
                state.project_id = project.id
                state.target = target.strip()
                state.plan = None
            self._json(HTTPStatus.CREATED, {"ok": True})

        def _close_project(self) -> None:
            with state.lock:
                if state.running:
                    raise ValueError("Wait for the current workflow to finish first.")
                state.project_id = None
                state.target = ""
                state.plan = None
                state.log.clear()
            self._json(HTTPStatus.OK, {"ok": True})

        def _reset_plan(self) -> None:
            with state.lock:
                if state.running:
                    raise ValueError("Wait for the current workflow to finish first.")
                state.plan = None
                state.log.clear()
            self._json(HTTPStatus.OK, {"ok": True})

        def _create_plan(self, data: dict[str, Any]) -> None:
            goal = data.get("goal")
            if not isinstance(goal, str) or not goal.strip() or len(goal) > 2000:
                raise ValueError("Describe the assessment goal (up to 2,000 characters).")
            with state.lock:
                if state.running:
                    raise ValueError("Wait for the current workflow to finish first.")
                project = (state.context.database.projects.get(state.project_id)
                           if state.project_id is not None else None)
                if not project or not project.authorized or not state.target:
                    raise ValueError("Create an authorized project and in-scope target first.")
                parsed_goal_target = extract_target(goal)
                if (parsed_goal_target and
                        _normalized_target(parsed_goal_target.raw) !=
                        _normalized_target(state.target)):
                    raise ValueError("The goal target must match the project's authorized target.")
                complete_goal = f"{goal.strip()} {state.target}"
                plan = state.planner.plan(complete_goal)
                state.plan = plan
                state.log.clear()
            self._json(HTTPStatus.OK, {"ok": True})

        def _run_steps(self, data: dict[str, Any]) -> None:
            indexes = data.get("steps")
            if (not isinstance(indexes, list) or not indexes or
                    any(type(i) is not int for i in indexes)):
                raise ValueError("Select at least one plan step to approve.")
            with state.lock:
                if state.running:
                    raise ValueError("A workflow is already running.")
                project = (state.context.database.projects.get(state.project_id)
                           if state.project_id is not None else None)
                if not project or not project.authorized or not state.plan:
                    raise ValueError("An authorized project and reviewed plan are required.")
                if state.plan.refused:
                    raise ValueError(state.plan.refusal_reason or "This request was refused.")
                if len(set(indexes)) != len(indexes):
                    raise ValueError("The step selection contains duplicates.")
                if any(i < 0 or i >= len(state.plan.steps) for i in indexes):
                    raise ValueError("The step selection is invalid.")
                assets = state.context.database.assets.list_for_project(project.id)
                target_allowed = any(
                    asset.scope is ScopeState.IN_SCOPE
                    and _normalized_target(asset.identifier) == _normalized_target(state.target)
                    for asset in assets
                )
                if not target_allowed:
                    raise ValueError("The target is no longer marked in scope.")
                for step in state.plan.steps:
                    if step.status != StepStatus.PENDING:
                        raise ValueError("This plan has already been submitted for execution.")
                for index in indexes:
                    state.plan.steps[index].status = StepStatus.APPROVED
                state.running = True
                state.start_requested.emit(state.plan, project.id)
            self._json(HTTPStatus.ACCEPTED, {"ok": True})

        def _cancel(self) -> None:
            with state.lock:
                if not state.running:
                    raise ValueError("There is no running workflow to cancel.")
                state.cancel_requested.emit()
            self._json(HTTPStatus.ACCEPTED, {"ok": True})

    return Handler


def main() -> int:
    """Start the local browser UI on http://127.0.0.1:8765."""
    import argparse

    parser = argparse.ArgumentParser(description="Run the SecurityOps local web UI.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address; only loopback addresses are allowed.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open a browser automatically.")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost"}:
        parser.error("SecurityOps web UI can only bind to IPv4 localhost.")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")

    app = QCoreApplication.instance() or QCoreApplication([])
    context = build_context()
    state = WebState(context)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _make_handler(state))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="securityops-web",
                              daemon=True)
    thread.start()
    url = f"http://{args.host}:{server.server_port}"
    print(f"SecurityOps Assistant is available at {url}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        return app.exec()
    except KeyboardInterrupt:
        return 0
    finally:
        state.engine.cancel()
        context.tasks.cancel_all()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
