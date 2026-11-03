"""Component 1 — Information Gathering.

Collects publicly observable facts about one authorized target. Every check is
passive or a normal client request (DNS queries, two HTTP GETs, one TLS
handshake); nothing is brute-forced, fuzzed, or exploited.

The entry point is :func:`run_assessment`, which returns a :class:`ScanResult`
— plain data that the analysis and report steps consume.
"""

from __future__ import annotations

import html
import ipaddress
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

try:  # dnspython gives MX/NS/TXT records; without it we fall back to A/AAAA.
    import dns.exception
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover - depends on the environment
    HAVE_DNSPYTHON = False

USER_AGENT = "SecurityOps-Assistant/1.0 (authorized security assessment)"
DEFAULT_TIMEOUT = 8.0

# Header name -> why it matters. HSTS is only expected on HTTPS responses.
SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "Forces browsers to use HTTPS for future visits.",
    "Content-Security-Policy": "Limits where scripts and content can load from (XSS defence).",
    "X-Frame-Options": "Stops other sites framing this page (clickjacking defence).",
    "X-Content-Type-Options": "Stops browsers guessing content types (MIME sniffing).",
    "Referrer-Policy": "Controls how much of the URL leaks to other sites.",
    "Permissions-Policy": "Restricts access to camera, microphone, location, etc.",
}

# (technology, regex over the HTML body)
_BODY_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("WordPress", re.compile(r"wp-content|wp-includes", re.I)),
    ("Drupal", re.compile(r"Drupal\.settings|/sites/default/files", re.I)),
    ("Joomla", re.compile(r"/media/jui/|Joomla!", re.I)),
    ("Next.js", re.compile(r"/_next/static", re.I)),
    ("Nuxt", re.compile(r"/_nuxt/", re.I)),
    ("Angular", re.compile(r"ng-version=", re.I)),
    ("React", re.compile(r"data-reactroot|react-dom", re.I)),
    ("jQuery", re.compile(r"jquery[.-]?\d", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(\.min)?\.(css|js)", re.I)),
)
_COOKIE_TECH = {
    "phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel", "csrftoken": "Django", "connect.sid": "Express (Node.js)",
}
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                       r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


class TargetError(ValueError):
    """The target is not a single valid hostname, IP address, or URL."""


@dataclass
class Target:
    host: str
    port: int | None = None        # only when the user gave one, e.g. a lab on :8080
    scheme: str | None = None      # only when the user gave one

    @property
    def display(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host


@dataclass
class ScanResult:
    """Everything collected about one target."""

    target: str
    host: str
    started_at: str = ""
    finished_at: str = ""
    dns: dict[str, list[str]] = field(default_factory=dict)
    http: dict[str, dict] = field(default_factory=dict)       # "http" / "https" -> response info
    tls: dict = field(default_factory=dict)
    headers: list[dict] = field(default_factory=list)          # security header checks
    technologies: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Target validation
# --------------------------------------------------------------------------- #
def parse_target(text: str) -> Target:
    """Validate user input: one domain, IP, or URL (scheme/port allowed, no paths needed)."""
    raw = (text or "").strip()
    if not raw or len(raw) > 300 or any(c.isspace() for c in raw):
        raise TargetError("Enter one domain, IP address, or URL (for example example.com).")
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    scheme = parsed.scheme.lower() or None
    if scheme not in (None, "http", "https"):
        raise TargetError("Only http:// and https:// URLs are supported.")
    try:
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError as exc:
        raise TargetError("The port number is not valid.") from exc
    if not host:
        raise TargetError("Enter one domain, IP address, or URL (for example example.com).")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.match(host):
            raise TargetError(f"'{host}' is not a valid domain name.") from None
    return Target(host=host, port=port, scheme=scheme)


def is_public_host(host: str) -> bool:
    """True if every address the host resolves to is a public internet address.

    Used when the app is hosted online, so it cannot be pointed at the hosting
    provider's internal network or cloud metadata service (SSRF protection).
    """
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    return bool(addresses) and all(
        ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses)


class _PublicOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects to private/internal addresses (hosted mode)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        host = urlsplit(newurl).hostname or ""
        if not is_public_host(host):
            raise urllib.error.URLError(f"redirect to non-public address {host} blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# --------------------------------------------------------------------------- #
# Individual checks (each returns plain data and never raises for network errors)
# --------------------------------------------------------------------------- #
def gather_dns(host: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, list[str]]:
    """A, AAAA, CNAME, MX, NS and TXT records (A/AAAA only without dnspython)."""
    try:
        ipaddress.ip_address(host)
        return {"A": [host]}  # an IP needs no lookup
    except ValueError:
        pass
    records: dict[str, list[str]] = {}
    if HAVE_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            try:
                answer = resolver.resolve(host, rtype)
            except (dns.exception.DNSException, OSError):
                continue
            records[rtype] = sorted(r.to_text().strip('"') for r in answer)
        if records:
            return records
    # Fallback (or local names like "localhost" that resolvers don't know).
    try:
        for info in socket.getaddrinfo(host, None):
            key = "AAAA" if info[0] == socket.AF_INET6 else "A"
            if info[4][0] not in records.setdefault(key, []):
                records[key].append(info[4][0])
    except OSError:
        pass
    return records


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT, verify: bool = True,
          allow_private: bool = True) -> dict:
    """GET one URL and describe the response (follows redirects)."""
    handlers: list[urllib.request.BaseHandler] = []
    if not allow_private:
        handlers.append(_PublicOnlyRedirect())
    if not verify:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    started = time.monotonic()
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:  # 4xx/5xx still carry headers
        response = exc
    with response:
        body = response.read(300_000).decode("utf-8", errors="replace")
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        return {
            "url": url,
            "final_url": response.geturl(),
            "status": response.status,
            "reason": response.reason,
            "response_ms": round((time.monotonic() - started) * 1000),
            "headers": {k: v for k, v in response.headers.items()},
            "cookies": response.headers.get_all("Set-Cookie") or [],
            "title": html.unescape(title.group(1)).strip()[:150] if title else "",
            "body": body,
        }


def gather_http(target: Target, timeout: float = DEFAULT_TIMEOUT,
                allow_private: bool = True) -> tuple[dict[str, dict], list[str]]:
    """Request the site over HTTP and HTTPS. Returns (results by scheme, errors)."""
    schemes = [target.scheme] if target.scheme else ["http", "https"]
    results: dict[str, dict] = {}
    errors: list[str] = []
    for scheme in schemes:
        port = f":{target.port}" if target.port else ""
        url = f"{scheme}://{target.host}{port}/"
        try:
            results[scheme] = fetch(url, timeout, allow_private=allow_private)
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLError):
                # Still collect headers; the TLS check reports the certificate problem.
                try:
                    results[scheme] = fetch(url, timeout, verify=False,
                                            allow_private=allow_private)
                    results[scheme]["certificate_error"] = str(exc.reason)
                    continue
                except (urllib.error.URLError, OSError) as retry_exc:
                    exc = retry_exc  # type: ignore[assignment]
            errors.append(f"{scheme.upper()}: {getattr(exc, 'reason', exc)}")
        except (OSError, ValueError) as exc:
            errors.append(f"{scheme.upper()}: {exc}")
    return results, errors


def gather_tls(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Certificate subject, issuer, validity and the negotiated protocol."""
    info: dict = {"host": host, "port": port, "valid": False}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                info["protocol"] = tls.version()
                info["cipher"] = (tls.cipher() or ("",))[0]
    except ssl.SSLCertVerificationError as exc:
        info["error"] = f"Certificate verification failed: {exc.verify_message}"
        return info
    except (ssl.SSLError, OSError) as exc:
        info["error"] = f"No TLS service reachable on port {port}: {exc}"
        return info

    subject = dict(item[0] for item in cert.get("subject", ()))
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)  # noqa: UP017
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)  # noqa: UP017
    info.update({
        "valid": True,
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
        "san": [v for kind, v in cert.get("subjectAltName", ()) if kind == "DNS"][:25],
        "not_before": not_before.date().isoformat(),
        "not_after": not_after.date().isoformat(),
        "days_remaining": (not_after - datetime.now(timezone.utc)).days,  # noqa: UP017
    })
    return info


def check_security_headers(response: dict | None) -> list[dict]:
    """Which recommended security headers the main response sets."""
    if not response:
        return []
    headers = {k.lower(): v for k, v in response["headers"].items()}
    is_https = response["final_url"].startswith("https://")
    csp = headers.get("content-security-policy", "")
    rows = []
    for name, purpose in SECURITY_HEADERS.items():
        value = headers.get(name.lower(), "")
        if name == "X-Frame-Options" and not value and "frame-ancestors" in csp:
            value = "(covered by CSP frame-ancestors)"
        rows.append({
            "name": name, "present": bool(value), "value": value[:300], "purpose": purpose,
            "applicable": is_https or name != "Strict-Transport-Security",
        })
    return rows


def detect_technologies(response: dict | None) -> list[dict]:
    """Technology hints visible in headers, cookies, and page markup."""
    if not response:
        return []
    found: dict[str, str] = {}
    headers = {k.lower(): v for k, v in response["headers"].items()}
    for header in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "via"):
        if headers.get(header):
            found[headers[header]] = f"{header.title()} header"
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                          response["body"], re.I)
    if generator:
        found[generator.group(1)] = "meta generator tag"
    for name, pattern in _BODY_MARKERS:
        if pattern.search(response["body"]):
            found.setdefault(name, "page markup")
    for cookie in response["cookies"]:
        name = cookie.split("=", 1)[0].strip().lower()
        if name in _COOKIE_TECH:
            found.setdefault(_COOKIE_TECH[name], f"'{name}' cookie")
    if "cf-ray" in headers:
        found.setdefault("Cloudflare", "CF-Ray header")
    return [{"name": name, "evidence": evidence} for name, evidence in found.items()]


def main_response(result: ScanResult) -> dict | None:
    """The response used for header/technology checks: HTTPS when available."""
    return result.http.get("https") or result.http.get("http")


def summarize(result: ScanResult) -> str:
    """A short plain-English summary of what was collected."""
    parts = []
    addresses = result.dns.get("A", []) + result.dns.get("AAAA", [])
    parts.append(f"{result.host} resolves to {', '.join(addresses[:4])}." if addresses
                 else f"{result.host} did not resolve in DNS.")
    for scheme in ("https", "http"):
        response = result.http.get(scheme)
        if response:
            parts.append(f"{scheme.upper()} answered {response['status']} "
                         f"({response['final_url']}).")
    if not result.http:
        parts.append("No web server answered on HTTP or HTTPS.")
    if result.tls.get("valid"):
        parts.append(f"TLS certificate from {result.tls['issuer']} is valid for "
                     f"{result.tls['days_remaining']} more days ({result.tls['protocol']}).")
    elif result.tls.get("error"):
        parts.append(result.tls["error"] + ".")
    applicable = [h for h in result.headers if h["applicable"]]
    if applicable:
        missing = [h["name"] for h in applicable if not h["present"]]
        parts.append(f"{len(applicable) - len(missing)} of {len(applicable)} recommended "
                     f"security headers are set" + (f"; missing: {', '.join(missing)}."
                                                    if missing else "."))
    if result.technologies:
        parts.append("Visible technology: "
                     + ", ".join(t["name"] for t in result.technologies[:6]) + ".")
    return " ".join(parts)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
Progress = Callable[[str, str], None]   # (step name, status) e.g. ("DNS records", "done")
STEPS = ("DNS records", "HTTP/HTTPS response", "TLS certificate", "Security headers",
         "Technologies", "Summary")


def run_assessment(target_text: str, progress: Progress | None = None,
                   timeout: float = DEFAULT_TIMEOUT, allow_private: bool = True) -> ScanResult:
    """Run every information-gathering step against one target."""
    report = progress or (lambda _step, _status: None)
    target = parse_target(target_text)
    result = ScanResult(target=target.display, host=target.host,
                        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))  # noqa: UP017

    report("DNS records", "running")
    result.dns = gather_dns(target.host, timeout)
    if not result.dns:
        result.errors.append(f"DNS: {target.host} did not resolve.")
    report("DNS records", "done")

    report("HTTP/HTTPS response", "running")
    result.http, http_errors = gather_http(target, timeout, allow_private)
    result.errors.extend(http_errors)
    report("HTTP/HTTPS response", "done")

    report("TLS certificate", "running")
    if target.scheme == "http":
        result.tls = {"skipped": True, "error": "Not checked: the target was given as http://"}
    else:
        tls_port = target.port if target.scheme == "https" and target.port else 443
        result.tls = gather_tls(target.host, tls_port, timeout)
    report("TLS certificate", "done")

    response = main_response(result)
    report("Security headers", "running")
    result.headers = check_security_headers(response)
    report("Security headers", "done")

    report("Technologies", "running")
    result.technologies = detect_technologies(response)
    report("Technologies", "done")

    # The full page body is only needed for detection; keep results small.
    for data in result.http.values():
        data.pop("body", None)
    report("Summary", "running")
    result.summary = summarize(result)
    result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")  # noqa: UP017
    report("Summary", "done")
    return result
