"""Component 2 — AI Security Analysis.

How it works (and why it is safe):

1. :func:`rule_based_findings` turns the scan results into findings using fixed,
   explainable rules. These are the ground truth: each one quotes the evidence
   that produced it.
2. :func:`analyze` sends the *already collected* results plus those findings to
   an LLM as text. The model can only write text back — it has no tools and
   cannot run commands.
3. :func:`merge_ai_findings` validates the model's JSON. The model may improve
   explanations, adjust severity, and add *potential* risks, but it cannot
   change evidence, mark its own ideas as confirmed, or delete rule findings.

If no model is configured or reachable, the rule-based findings are returned
with a clear message, so the application always produces a result.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..ai.llm import LLMConfig, LocalLLM, _extract_json
from .gather import ScanResult, main_response

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
CONFIRMED = "Confirmed"          # directly observed in the collected evidence
POTENTIAL = "Potential risk"     # inferred; needs manual verification


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    status: str
    category: str
    evidence: str
    why_it_matters: str
    remediation: str


@dataclass
class Analysis:
    source: str                      # "ai" or "rules"
    provider: str
    executive_summary: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""                  # why the AI step was not used, if it wasn't
    generated_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# 1. Rule-based findings (deterministic, evidence-backed)
# --------------------------------------------------------------------------- #
_HEADER_RULES = {
    # header: (severity, title, why, fix)
    "Strict-Transport-Security": (
        "Medium", "HSTS header not set",
        "Without HSTS a user's first request can be downgraded to plain HTTP and "
        "intercepted on an untrusted network.",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS "
        "responses once every subdomain supports HTTPS."),
    "Content-Security-Policy": (
        "Medium", "Content-Security-Policy not set",
        "A CSP is the main browser-side defence that limits the damage of cross-site "
        "scripting (XSS) if an injection bug exists.",
        "Start with a report-only policy (e.g. default-src 'self'), review violations, "
        "then enforce it."),
    "X-Frame-Options": (
        "Low", "Clickjacking protection not set",
        "Other websites can load this page in a hidden frame and trick users into "
        "clicking buttons (clickjacking).",
        "Send 'X-Frame-Options: DENY' (or SAMEORIGIN), or CSP 'frame-ancestors'."),
    "X-Content-Type-Options": (
        "Low", "X-Content-Type-Options not set",
        "Browsers may guess ('sniff') file types and execute uploaded content as script.",
        "Send 'X-Content-Type-Options: nosniff'."),
    "Referrer-Policy": (
        "Low", "Referrer-Policy not set",
        "Full URLs, which can contain tokens or IDs, may leak to third-party sites.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
    "Permissions-Policy": (
        "Informational", "Permissions-Policy not set",
        "Embedded third-party content is not restricted from requesting powerful "
        "browser features.",
        "Send a Permissions-Policy that disables unused features, e.g. "
        "'camera=(), microphone=(), geolocation=()'."),
}


def rule_based_findings(scan: ScanResult) -> list[Finding]:
    findings: list[Finding] = []

    def add(severity: str, status: str, category: str, title: str, evidence: str,
            why: str, fix: str) -> None:
        findings.append(Finding(f"F{len(findings) + 1}", title, severity, status, category,
                                evidence, why, fix))

    https, http = scan.http.get("https"), scan.http.get("http")

    # --- Reachability and transport security ---
    if not scan.http:
        add("Informational", CONFIRMED, "Availability", "No web server responded",
            "; ".join(scan.errors) or "Neither HTTP nor HTTPS answered.",
            "Nothing web-facing could be assessed; the host may be offline or filtered.",
            "Confirm the target address and that the web service is running.")
    elif http and not https and not scan.tls.get("skipped"):
        add("High", CONFIRMED, "Transport security", "Site is not available over HTTPS",
            f"HTTP answered {http['status']}; HTTPS failed "
            f"({scan.tls.get('error', 'no response')}).",
            "All traffic, including logins and cookies, travels unencrypted and can be "
            "read or modified on the network.",
            "Install a TLS certificate (e.g. free from Let's Encrypt) and serve the site "
            "over HTTPS.")
    if http and https and http["final_url"].startswith("http://"):
        add("Medium", CONFIRMED, "Transport security", "HTTP does not redirect to HTTPS",
            f"http:// request ended at {http['final_url']} (status {http['status']}).",
            "Visitors who type the address or follow old links stay on an unencrypted "
            "connection.",
            "Redirect all HTTP requests to HTTPS with a 301 response.")

    tls = scan.tls
    if tls.get("error", "").startswith("Certificate verification failed"):
        add("High", CONFIRMED, "TLS", "TLS certificate is not trusted", tls["error"],
            "Browsers show a security warning; users who click through are exposed to "
            "interception.",
            "Install a certificate from a trusted authority that matches the hostname and "
            "includes the full chain.")
    if tls.get("valid"):
        days = tls["days_remaining"]
        if days < 0:
            add("High", CONFIRMED, "TLS", "TLS certificate has expired",
                f"Certificate expired on {tls['not_after']}.",
                "Browsers block or warn on expired certificates.",
                "Renew the certificate and automate renewal.")
        elif days < 30:
            add("High" if days < 7 else "Medium", CONFIRMED, "TLS",
                "TLS certificate expires soon",
                f"Certificate expires on {tls['not_after']} ({days} days left).",
                "If it lapses, users will see errors and may be unable to reach the site.",
                "Renew now and automate renewal (e.g. certbot or your provider's auto-renew).")
        if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
            add("Medium", CONFIRMED, "TLS", "Outdated TLS protocol negotiated",
                f"Server negotiated {tls['protocol']}.",
                "TLS 1.0/1.1 have known weaknesses and are deprecated by browsers.",
                "Disable TLS 1.0/1.1 and support TLS 1.2 and 1.3 only.")

    # --- Security headers ---
    for header in scan.headers:
        if header["applicable"] and not header["present"] and header["name"] in _HEADER_RULES:
            severity, title, why, fix = _HEADER_RULES[header["name"]]
            add(severity, CONFIRMED, "Security headers", title,
                f"The response from {(main_response(scan) or {}).get('final_url', scan.host)} "
                f"has no {header['name']} header.", why, fix)

    response = main_response(scan)
    if response:
        headers = {k.lower(): v for k, v in response["headers"].items()}
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            value = headers.get(name, "")
            if any(ch.isdigit() for ch in value):
                add("Low", POTENTIAL, "Information disclosure",
                    f"Software version disclosed in {name.title()} header",
                    f"{name.title()}: {value}",
                    "Exact versions help attackers look up known vulnerabilities. This is "
                    "only a risk if the version is outdated, which needs manual checking.",
                    "Hide version numbers in server configuration and keep the software "
                    "patched.")
        if headers.get("access-control-allow-origin") == "*":
            add("Low", POTENTIAL, "Security headers", "CORS allows any origin",
                "Access-Control-Allow-Origin: *",
                "Any website can read these responses. This matters only if they contain "
                "non-public data.",
                "Return CORS headers only for the specific origins that need access.")
        for cookie in response["cookies"]:
            name = cookie.split("=", 1)[0].strip()
            flags = cookie.lower()
            missing = [flag for flag in ("Secure", "HttpOnly", "SameSite")
                       if flag.lower() not in flags and not
                       (flag == "Secure" and not response["final_url"].startswith("https"))]
            if missing:
                add("Low", CONFIRMED, "Cookies", f"Cookie '{name}' missing security flags",
                    f"Set-Cookie: {cookie[:160]} (missing {', '.join(missing)})",
                    "Cookies without these flags can be sent over HTTP, read by scripts, "
                    "or attached to cross-site requests.",
                    "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.")

    # --- Email/DNS hygiene (only relevant when the domain receives mail) ---
    if scan.dns.get("MX") and not any(t.lower().startswith("v=spf1")
                                      for t in scan.dns.get("TXT", [])):
        add("Low", POTENTIAL, "DNS", "No SPF record found",
            f"Domain has MX records ({', '.join(scan.dns['MX'][:2])}) but no 'v=spf1' TXT "
            "record.",
            "Without SPF (and DMARC) it is easier to send spoofed email that appears to "
            "come from this domain.",
            "Publish an SPF record listing your mail senders, then add DMARC.")
    return findings


# --------------------------------------------------------------------------- #
# 2. LLM providers (text in, text out — no tools, no command execution)
# --------------------------------------------------------------------------- #
class ProviderError(RuntimeError):
    """The model could not be reached or did not return a usable answer."""


class LLMProvider:
    name = "none"

    def complete(self, system: str, prompt: str) -> str:
        raise ProviderError("No AI provider is configured (llm.provider: none).")


class OllamaProvider(LLMProvider):
    """A local model served by Ollama (http://localhost:11434 by default)."""

    def __init__(self, host: str, model: str) -> None:
        self.name = f"Ollama ({model})"
        self._llm = LocalLLM(LLMConfig(host=host, model=model, request_timeout=180.0))

    def complete(self, system: str, prompt: str) -> str:
        if not self._llm.available(refresh=True):
            raise ProviderError("The local Ollama server is not reachable at "
                                f"{self._llm._cfg.host}. Start it with 'ollama serve' and "
                                f"pull a model with 'ollama pull {self._llm.model}'.")
        text = self._llm.generate(prompt, system=system)
        if not text:
            raise ProviderError("The local model returned no answer (is the model pulled?).")
        return text


class AnthropicProvider(LLMProvider):
    """Claude via the Anthropic API. The key comes from ANTHROPIC_API_KEY, never config."""

    def __init__(self, model: str) -> None:
        self.model = model
        self.name = f"Anthropic ({model})"

    def complete(self, system: str, prompt: str) -> str:
        try:
            import anthropic
        except ImportError as exc:
            raise ProviderError("The 'anthropic' package is not installed. Run: "
                                "pip install anthropic") from exc
        try:
            client = anthropic.Anthropic()
            # Server-side fallback: if a safety classifier declines (e.g. on security
            # wording), the API retries on a suitable fallback model automatically.
            # Sent via extra_body so older SDK versions without the keyword work too.
            response = client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                betas=["server-side-fallback-2026-07-01"],
                extra_body={"fallbacks": "default"},
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.AuthenticationError as exc:
            raise ProviderError("Anthropic rejected the API key. Set a valid "
                                "ANTHROPIC_API_KEY environment variable.") from exc
        except anthropic.RateLimitError as exc:
            raise ProviderError("Anthropic rate limit reached; try again shortly.") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError("Could not connect to the Anthropic API (network).") from exc
        except TypeError as exc:  # e.g. no API key could be resolved
            raise ProviderError(f"Anthropic client error: {exc}. Set the ANTHROPIC_API_KEY "
                                "environment variable.") from exc
        if response.stop_reason == "refusal":
            raise ProviderError("The model declined to analyse these results.")
        text = "".join(block.text for block in response.content if block.type == "text")
        if not text.strip():
            raise ProviderError("The model returned an empty answer.")
        return text


def make_provider(config: Any) -> LLMProvider:
    """Build the provider named in config (llm.provider: ollama | anthropic | none)."""
    if not config.get("llm.enabled", True):
        return LLMProvider()
    provider = str(config.get("llm.provider", "ollama")).lower()
    if provider == "anthropic":
        return AnthropicProvider(str(config.get("llm.api_model", "claude-opus-5-5")))
    if provider == "ollama":
        return OllamaProvider(str(config.get("llm.host", "http://localhost:11434")),
                              str(config.get("llm.model", "llama3")))
    return LLMProvider()


# --------------------------------------------------------------------------- #
# 3. Analysis: prompt, validation, fallback
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = """You are a web security analyst writing for the owner of a website \
they are authorized to assess. You receive passive scan results (DNS, HTTP responses, \
TLS certificate, security headers, technology hints) and rule-based findings.

Rules:
- Use only the evidence provided. Never invent ports, versions, vulnerabilities or CVEs.
- Keep every rule-based finding (refer to it by its id). You may adjust its severity \
(Critical, High, Medium, Low, Informational) and improve "why_it_matters" and \
"remediation" in plain English.
- You may add up to 5 extra items, but only as "Potential risk" with the evidence that \
suggests them.
- Give defensive remediation only. Do not give exploitation steps.

Reply with JSON only, in this shape:
{"executive_summary": "3-5 sentences for a non-technical reader",
 "findings": [{"id": "F1 or null for a new item", "title": "...", "severity": "...",
   "status": "Confirmed or Potential risk", "evidence": "...",
   "why_it_matters": "...", "remediation": "..."}]}"""


def build_prompt(scan: ScanResult, baseline: list[Finding]) -> str:
    """The scan data the model sees: compact JSON, response bodies excluded."""
    data = scan.to_dict()
    for response in data["http"].values():
        response.pop("body", None)
        response["headers"] = dict(list(response["headers"].items())[:40])
    return ("Scan results:\n" + json.dumps(data, indent=1, default=str)[:30_000]
            + "\n\nRule-based findings:\n"
            + json.dumps([asdict(f) for f in baseline], indent=1))


def _clean(value: Any, limit: int = 2000) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def merge_ai_findings(baseline: list[Finding], data: Any) -> tuple[str, list[Finding]]:
    """Validate the model's JSON against the rule findings.

    Raises ProviderError if the answer is not usable.
    """
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ProviderError("The model's answer was not in the expected JSON format.")
    by_id = {f.id: f for f in baseline}
    merged: dict[str, Finding] = {f.id: Finding(**asdict(f)) for f in baseline}
    extra: list[Finding] = []
    for item in data["findings"]:
        if not isinstance(item, dict):
            continue
        severity = item.get("severity") if item.get("severity") in SEVERITIES else None
        known = by_id.get(str(item.get("id")))
        if known is not None:
            finding = merged[known.id]           # evidence and status stay as observed
            finding.severity = severity or finding.severity
            finding.why_it_matters = _clean(item.get("why_it_matters")) or finding.why_it_matters
            finding.remediation = _clean(item.get("remediation")) or finding.remediation
        elif len(extra) < 5 and _clean(item.get("title")) and _clean(item.get("evidence")):
            extra.append(Finding(
                id=f"AI{len(extra) + 1}", title=_clean(item["title"], 200),
                severity=severity or "Low", status=POTENTIAL,   # never "Confirmed"
                category="AI observation", evidence=_clean(item["evidence"]),
                why_it_matters=_clean(item.get("why_it_matters")),
                remediation=_clean(item.get("remediation"))))
    summary = _clean(data.get("executive_summary"), 3000)
    return summary, list(merged.values()) + extra


def rules_summary(scan: ScanResult, findings: list[Finding]) -> str:
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    worst = next((s for s in SEVERITIES if counts[s]), None)
    if not findings:
        return (f"The passive assessment of {scan.host} found no issues in the areas "
                "checked. This does not prove the site is secure; see the limitations.")
    counted = ", ".join(f"{n} {s.lower()}" for s, n in counts.items() if n)
    return (f"The passive assessment of {scan.host} produced {len(findings)} findings "
            f"({counted}). The most severe is rated {worst}. {scan.summary}")


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), f.status != CONFIRMED))


def analyze(scan: ScanResult, provider: LLMProvider) -> Analysis:
    """Rule findings, enriched by the LLM when it is available."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")  # noqa: UP017
    baseline = rule_based_findings(scan)
    try:
        answer = provider.complete(SYSTEM_PROMPT, build_prompt(scan, baseline))
        summary, findings = merge_ai_findings(baseline, _extract_json(answer))
    except ProviderError as exc:
        return Analysis(source="rules", provider=provider.name,
                        executive_summary=rules_summary(scan, baseline),
                        findings=sort_findings(baseline), generated_at=now,
                        error=f"AI analysis unavailable: {exc} Showing the rule-based "
                              "analysis instead.")
    return Analysis(source="ai", provider=provider.name,
                    executive_summary=summary or rules_summary(scan, findings),
                    findings=sort_findings(findings), generated_at=now)
