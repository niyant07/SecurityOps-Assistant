"""Built-in, install-free network checks.

These give the workflow real assessment capability on any machine (including
Windows) when the Kali tools are not installed. The module uses only the Python
standard library and is executed as a standalone script, so a built-in check is
launched exactly like any other tool — as a reviewable command, approved by the
operator, streamed, cancellable, and recorded in the scan history::

    python checks.py <check> <target>

All checks are conservative and non-destructive: a TCP connect scan of common
ports, a handful of HTTP requests, and one TLS handshake. Nothing is exploited,
brute-forced, or fuzzed.

Output conventions (parsed by ``securityops.workflow.parsers.parse_builtin``):

* ``<port>/tcp open <service>`` — an open port, in nmap's format
* ``Status: <code> <path>``     — a reachable web path
* ``+ <text>``                  — an observation worth highlighting
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import html
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import urlsplit

USER_AGENT = "SecurityOps-Assistant/0.1 (authorized security assessment)"
TIMEOUT = 8.0

# Common TCP ports and the service names nmap reports for them.
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Content-Security-Policy", "restricts where scripts and content may load from"),
    ("X-Frame-Options", "prevents clickjacking via framing"),
    ("X-Content-Type-Options", "stops MIME-type sniffing"),
    ("Referrer-Policy", "limits referrer leakage"),
    ("Permissions-Policy", "restricts powerful browser features"),
)

# Paths worth checking on any web server; kept short so the check stays quiet.
COMMON_PATHS: tuple[str, ...] = (
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.git/HEAD", "/.env",
    "/.DS_Store", "/.htaccess", "/web.config", "/server-status", "/phpinfo.php",
    "/admin/", "/administrator/", "/wp-login.php", "/phpmyadmin/", "/backup/",
    "/config.php.bak", "/actuator/health", "/swagger.json", "/openapi.json",
    "/crossdomain.xml",
)

# Content that proves a sensitive file is real rather than a custom error page.
_PROOF = {
    "/.git/HEAD": re.compile(r"^ref: refs/", re.M),
    "/.env": re.compile(r"^[A-Z0-9_]+=", re.M),
    "/phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version", re.I),
    "/server-status": re.compile(r"Apache Server Status", re.I),
    "/.DS_Store": re.compile(r"Bud1"),
}

_TECH_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("WordPress", re.compile(r"wp-content|wp-includes", re.I)),
    ("Drupal", re.compile(r"Drupal\.settings|/sites/default/files", re.I)),
    ("Joomla", re.compile(r"/media/jui/|Joomla!", re.I)),
    ("Next.js", re.compile(r"/_next/static", re.I)),
    ("Nuxt", re.compile(r"/_nuxt/", re.I)),
    ("Angular", re.compile(r"ng-version=", re.I)),
    ("React", re.compile(r"data-reactroot|react-dom", re.I)),
    ("jQuery", re.compile(r"jquery[.-]?\d", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(\.min)?\.(css|js)", re.I)),
    ("Cloudflare", re.compile(r"cdn-cgi/", re.I)),
)

_COOKIE_TECH = {
    "phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel", "csrftoken": "Django", "connect.sid": "Express",
}


def say(line: str = "") -> None:
    print(line, flush=True)


# --------------------------------------------------------------------------- #
# Target helpers
# --------------------------------------------------------------------------- #
def host_of(target: str) -> str:
    parsed = urlsplit(target if "://" in target else f"//{target}")
    return (parsed.hostname or "").rstrip(".")


def base_url(target: str) -> str:
    """The target as a URL; bare hosts prefer HTTPS when it answers."""
    if "://" in target:
        parsed = urlsplit(target)
        return f"{parsed.scheme}://{parsed.netloc}"
    host = target.strip().rstrip("/")
    try:
        with socket.create_connection((host, 443), timeout=3):
            return f"https://{host}"
    except OSError:
        return f"http://{host}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url: str, follow: bool = True, limit: int = 200_000,
          verify: bool = True) -> tuple[int, dict[str, str], list[str], str, str]:
    """GET *url*; returns (status, headers, set-cookie values, body, final url)."""
    handlers: list[urllib.request.BaseHandler] = []
    if not follow:
        handlers.append(_NoRedirect())
    if not verify:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        response = opener.open(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        body = response.read(limit).decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = response.headers.get_all("Set-Cookie") or []
        return response.status, headers, cookies, body, response.geturl()


def fetch_lenient(url: str) -> tuple[int, dict[str, str], list[str], str, str]:
    """Fetch, retrying without certificate verification (TLS is checked separately)."""
    try:
        return fetch(url)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLError):
            say(f"+ TLS certificate could not be verified for {url} ({exc.reason}); "
                "continuing without verification.")
            return fetch(url, verify=False)
        raise


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def check_dns(target: str) -> int:
    host = host_of(target)
    say(f"DNS lookup for {host}")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        say(f"+ {host} does not resolve ({exc}).")
        return 1
    addresses = sorted({info[4][0] for info in infos})
    for address in addresses:
        family = "IPv6" if ":" in address else "IPv4"
        say(f"+ {host} resolves to {address} ({family})")
        try:
            name = socket.gethostbyaddr(address)[0]
            say(f"  reverse DNS: {name}")
        except OSError:
            say("  reverse DNS: (none)")
    return 0


def check_ports(target: str) -> int:
    host = host_of(target)
    try:
        address = socket.gethostbyname(host)
    except OSError as exc:
        say(f"+ {host} does not resolve ({exc}).")
        return 1
    say(f"TCP connect scan of {len(COMMON_PORTS)} common ports on {host} ({address})")

    def probe(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            return sock.connect_ex((address, port)) == 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = dict(zip(COMMON_PORTS, pool.map(probe, COMMON_PORTS)))
    open_ports = [port for port, is_open in results.items() if is_open]
    say("PORT      STATE  SERVICE")
    for port in open_ports:
        say(f"{port}/tcp open {COMMON_PORTS[port]}")
    closed = len(COMMON_PORTS) - len(open_ports)
    say(f"{len(open_ports)} open, {closed} closed or filtered.")
    return 0


def check_http(target: str) -> int:
    url = target if "://" in target else base_url(target)
    say(f"HTTP probe of {url}")
    status, headers, cookies, body, final = fetch_lenient(url)
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = html.unescape(title_match.group(1)).strip()[:120] if title_match else ""
    server = headers.get("server", "")
    say(f"+ {final} [{status}] [{title or 'no title'}]" + (f" [{server}]" if server else ""))
    if final.rstrip("/") != url.rstrip("/"):
        say(f"  redirected from {url}")
    if server:
        say(f"+ Server: {server}")
    for header in ("x-powered-by", "x-generator", "x-aspnet-version"):
        if headers.get(header):
            say(f"+ {header.title()}: {headers[header]}")
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                          body, re.I)
    if generator:
        say(f"+ Generator: {generator.group(1)}")
    techs = [name for name, pattern in _TECH_MARKERS if pattern.search(body)]
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip().lower()
        if name in _COOKIE_TECH:
            techs.append(_COOKIE_TECH[name])
    for tech in dict.fromkeys(techs):
        say(f"+ Technology: {tech}")
    return 0


def check_headers(target: str) -> int:
    url = target if "://" in target else base_url(target)
    say(f"Security header audit of {url}")
    _status, headers, cookies, _body, final = fetch_lenient(url)
    https = final.startswith("https://")
    if https:
        if "strict-transport-security" not in headers:
            say("+ The Strict-Transport-Security header is not present "
                "(browsers may be downgraded to HTTP).")
        else:
            say(f"  Strict-Transport-Security: {headers['strict-transport-security']}")
    csp = headers.get("content-security-policy", "")
    for name, purpose in SECURITY_HEADERS:
        if name.lower() in headers:
            say(f"  {name}: {headers[name.lower()]}")
        elif name == "X-Frame-Options" and "frame-ancestors" in csp:
            say("  X-Frame-Options: (covered by CSP frame-ancestors)")
        else:
            say(f"+ The {name} header is not present ({purpose}).")
    if headers.get("access-control-allow-origin") == "*":
        say("+ Access-Control-Allow-Origin is '*' (any site may read responses).")
    if headers.get("server") and re.search(r"\d", headers["server"]):
        say(f"+ Server: {headers['server']} (version disclosed)")
    if headers.get("x-powered-by"):
        say(f"+ X-Powered-By: {headers['x-powered-by']} (technology disclosed)")
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        flags = cookie.lower()
        missing = [flag for flag, token in (("Secure", "secure"), ("HttpOnly", "httponly"),
                                            ("SameSite", "samesite"))
                   if token not in flags and not (flag == "Secure" and not https)]
        if missing:
            say(f"+ Cookie '{name}' is set without {', '.join(missing)}.")
    if https:
        host = urlsplit(final).hostname or ""
        try:
            _s, _h, _c, _b, plain_final = fetch(f"http://{host}/")
            if not plain_final.startswith("https://"):
                say("+ HTTP does not redirect to HTTPS.")
            else:
                say("  HTTP redirects to HTTPS.")
        except (urllib.error.URLError, OSError):
            say("  Plain HTTP is not served.")
    return 0


def check_tls(target: str) -> int:
    host = host_of(target)
    parsed = urlsplit(target if "://" in target else f"//{target}")
    port = parsed.port or 443
    say(f"TLS inspection of {host}:{port}")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                version, cipher = tls.version(), tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        say(f"+ Certificate verification failed: {exc.verify_message} "
            "(self-signed, expired, untrusted, or wrong hostname).")
        return 0
    except (ssl.SSLError, OSError) as exc:
        say(f"+ No TLS service reachable on {host}:{port} ({exc}).")
        return 1

    subject = dict(item[0] for item in cert.get("subject", ()))
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    say(f"  Protocol: {version}; cipher: {cipher[0] if cipher else 'unknown'}")
    say(f"  Subject: {subject.get('commonName', '?')}; issuer: "
        f"{issuer.get('organizationName') or issuer.get('commonName', '?')}")
    names = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if names:
        say(f"  Covers: {', '.join(names[:10])}" + (" …" if len(names) > 10 else ""))
    if version in {"TLSv1", "TLSv1.1", "SSLv3"}:
        say(f"+ Outdated protocol negotiated: {version}.")
    not_after = cert.get("notAfter")
    if not_after:
        expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), dt.timezone.utc)
        days = (expires - dt.datetime.now(dt.timezone.utc)).days
        say(f"  Valid until {expires:%Y-%m-%d} ({days} days)")
        if days < 30:
            say(f"+ Certificate expires in {days} days ({expires:%Y-%m-%d}).")
    return 0


def check_paths(target: str) -> int:
    root = (target if "://" in target else base_url(target)).rstrip("/")
    root = f"{urlsplit(root).scheme}://{urlsplit(root).netloc}"
    say(f"Checking {len(COMMON_PATHS)} common paths on {root}")

    def get(path: str) -> tuple[int, str]:
        try:
            status, _h, _c, body, _f = fetch(root + path, follow=False, limit=4096,
                                             verify=False)
        except (urllib.error.URLError, OSError):
            return 0, ""
        return status, body

    # A random path tells us how the server answers for things that don't exist.
    baseline_status, baseline_body = get(f"/{uuid.uuid4().hex}")
    for path in COMMON_PATHS:
        status, body = get(path)
        time.sleep(0.15)
        if status in (0, 404, 410) or status >= 500:
            continue
        if status == baseline_status == 200 and abs(len(body) - len(baseline_body)) < 64:
            continue  # same page the server returns for anything (soft 404)
        say(f"Status: {status} {path} [Size: {len(body)}]")
        proof = _PROOF.get(path)
        if status == 200 and proof and proof.search(body):
            say(f"+ Sensitive file exposed: {path} (contents confirmed)")
    return 0


def check_securitytxt(target: str) -> int:
    host = host_of(target)
    say(f"Looking for security.txt (RFC 9116) on {host}")
    for url in (f"https://{host}/.well-known/security.txt", f"https://{host}/security.txt",
                f"http://{host}/.well-known/security.txt"):
        try:
            status, headers, _c, body, _f = fetch(url, limit=32_000)
        except (urllib.error.URLError, OSError):
            continue
        if status != 200 or "html" in headers.get("content-type", ""):
            continue
        fields = [line.strip() for line in body.splitlines()
                  if re.match(r"^(Contact|Expires|Policy|Encryption|Preferred-Languages)"
                              r"\s*:", line.strip(), re.I)]
        if fields:
            say(f"+ security.txt found at {url}")
            for line in fields:
                say(f"  {line}")
            return 0
    say("+ No security.txt is published (consider adding one per RFC 9116).")
    return 0


CHECKS = {
    "dns": check_dns,
    "ports": check_ports,
    "http": check_http,
    "headers": check_headers,
    "tls": check_tls,
    "paths": check_paths,
    "securitytxt": check_securitytxt,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in CHECKS:
        say(f"usage: checks.py {{{','.join(CHECKS)}}} <target>")
        return 2
    check, target = argv
    if not host_of(target):
        say(f"Invalid target: {target}")
        return 2
    try:
        return CHECKS[check](target)
    except (urllib.error.URLError, OSError) as exc:
        say(f"+ {target} could not be reached ({exc}).")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
