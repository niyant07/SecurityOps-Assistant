"""HTTP server for the browser interface.

By default it only listens on 127.0.0.1. ``--public`` (or SECURITYOPS_PUBLIC=1)
is for hosting it online: it then listens on all interfaces and every API call
needs the access code from the SECURITYOPS_ACCESS_CODE environment variable.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import mimetypes
import sqlite3
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from ..core import config as config_mod
from ..core.logging_config import configure_logging, get_logger
from . import api
from .state import AssessmentSession

_LOG = get_logger("web")
_MAX_BODY_BYTES = 64_000


def _make_handler(state: AssessmentSession,
                  access_code: str | None = None) -> type[BaseHTTPRequestHandler]:
    """Build the request handler. An *access_code* switches on public mode."""
    public = access_code is not None

    class Handler(BaseHTTPRequestHandler):
        server_version = "SecurityOpsLocal/1.0"

        def log_message(self, fmt: str, *args: object) -> None:
            if self.command == "GET" and urlsplit(self.path).path == "/api/status":
                return
            _LOG.info("HTTP %s - %s", self.address_string(), fmt % args)

        def _is_local_request(self) -> bool:
            if public:  # hosted online: the access code is the gate instead
                return True
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
            if public:
                host = self.headers.get("Host", "").lower()
                return origin.lower() in {f"https://{host}", f"http://{host}"}
            port = self.server.server_port
            return origin.lower() in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

        def _has_access(self) -> bool:
            if not public:
                return True
            supplied = self.headers.get("X-Access-Code", "")
            return hmac.compare_digest(supplied.encode(), str(access_code).encode())

        def _json(self, status: HTTPStatus | int, value: object) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _download(self, download: api.Download) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", download.content_type)
            self.send_header("Content-Length", str(len(download.body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # Reports and evidence are untrusted content: never let them run
            # script in the app's origin, where they could call the API.
            self.send_header("Content-Security-Policy", "sandbox; default-src 'none'; "
                             "img-src data:; style-src 'unsafe-inline'")
            disposition = "inline" if download.inline else "attachment"
            self.send_header("Content-Disposition",
                             f"{disposition}; filename*=UTF-8''{quote(download.filename)}")
            self.end_headers()
            self.wfile.write(download.body)

        def _body(self, path: str) -> dict[str, Any]:
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

        def _dispatch(self, handler: Any, argument: Any) -> None:
            try:
                result = handler(state, argument)
            except api.ApiError as exc:
                self._json(exc.status, {"error": str(exc)})
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except (OSError, sqlite3.Error, RuntimeError):
                _LOG.exception("Local web request failed")
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR,
                           {"error": "The request failed. Check the local application log."})
            else:
                if isinstance(result, api.Download):
                    self._download(result)
                else:
                    self._json(HTTPStatus.OK, result)

        def do_GET(self) -> None:
            if not self._is_local_request():
                self._json(HTTPStatus.FORBIDDEN, {"error": "Loopback requests only."})
                return
            url = urlsplit(self.path)
            if url.path == "/healthz":
                self._json(HTTPStatus.OK, {"ok": True})
                return
            if url.path.startswith("/api/") and not self._has_access():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Access code required.",
                                                     "code_required": True})
                return
            handler = api.GET_ROUTES.get(url.path)
            if handler is not None:
                self._dispatch(handler, dict(parse_qsl(url.query)))
            elif url.path.startswith("/api/"):
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            else:
                self._static(url.path)

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
            if not self._has_access():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "Access code required.",
                                                     "code_required": True})
                return
            path = urlsplit(self.path).path
            handler = api.POST_ROUTES.get(path)
            if handler is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
                return
            try:
                data = self._body(path)
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._dispatch(handler, data)

    return Handler


def main() -> int:
    """Start the local browser UI on http://127.0.0.1:8765."""
    import argparse

    parser = argparse.ArgumentParser(description="Run the SecurityOps local web UI.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address; only loopback addresses are allowed.")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8765")))
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not open a browser automatically.")
    parser.add_argument("--public", action="store_true",
                        default=os.environ.get("SECURITYOPS_PUBLIC") == "1",
                        help="Host online: listen on all interfaces and require the "
                             "SECURITYOPS_ACCESS_CODE access code.")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost"}:
        parser.error("Use --public to host online; --host only accepts localhost.")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")
    access_code = None
    if args.public:
        access_code = os.environ.get("SECURITYOPS_ACCESS_CODE", "")
        if len(access_code) < 8:
            parser.error("Public mode needs SECURITYOPS_ACCESS_CODE set to at least 8 "
                         "characters, so strangers cannot use your scanner.")

    config = config_mod.load_config()
    configure_logging(config.section("logging"))
    session = AssessmentSession(config, public=args.public)
    bind = "0.0.0.0" if args.public else "127.0.0.1"  # noqa: S104 - public mode only
    server = ThreadingHTTPServer((bind, args.port), _make_handler(session, access_code))
    server.daemon_threads = True
    url = f"http://{args.host}:{server.server_port}"
    if args.public:
        args.no_browser = True
        print("Public mode: listening on all interfaces; the access code is required.")
    print(f"SecurityOps Assistant is available at {url}  (AI provider: {session.provider.name})")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
