"""RFC 9116 ``security.txt`` detection and parsing.

A published ``security.txt`` (served at ``/.well-known/security.txt``) is the
standard way an organization advertises how to report vulnerabilities. This
module parses one into a :class:`SecurityContact`. Parsing is offline; fetching
is a separate, explicitly user-triggered network call to the target.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from ..core.logging_config import get_logger

_LOG = get_logger("disclosure.security_txt")

_FIELD = re.compile(r"^([A-Za-z-]+):\s*(.+?)\s*$")


@dataclass
class SecurityContact:
    """Parsed responsible-disclosure contact details."""

    contacts: list[str] = field(default_factory=list)   # mailto:/https:/tel: values
    policy: str = ""
    encryption: str = ""
    acknowledgments: str = ""
    preferred_languages: str = ""
    canonical: str = ""
    expires: str = ""
    source: str = ""                                    # where it was loaded from
    raw: str = ""

    @property
    def has_contact(self) -> bool:
        return bool(self.contacts)

    @property
    def primary_email(self) -> str:
        """The first email contact, if any (without the ``mailto:`` scheme)."""
        for c in self.contacts:
            if c.lower().startswith("mailto:"):
                return c[len("mailto:"):]
            if "@" in c and "://" not in c:
                return c
        return ""

    @property
    def primary_url(self) -> str:
        for c in self.contacts:
            if c.lower().startswith(("http://", "https://")):
                return c
        return ""


def parse_security_txt(text: str, source: str = "") -> SecurityContact:
    """Parse the contents of a ``security.txt`` file."""
    contact = SecurityContact(source=source, raw=text)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _FIELD.match(line)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip()
        if key == "contact":
            contact.contacts.append(value)
        elif key == "policy":
            contact.policy = value
        elif key == "encryption":
            contact.encryption = value
        elif key == "acknowledgments":
            contact.acknowledgments = value
        elif key == "preferred-languages":
            contact.preferred_languages = value
        elif key == "canonical":
            contact.canonical = value
        elif key == "expires":
            contact.expires = value
    _LOG.info("Parsed security.txt: %d contact(s) from %s",
              len(contact.contacts), source or "text")
    return contact


def fetch_security_txt(host: str, timeout: float = 5.0) -> SecurityContact | None:
    """Attempt to fetch a target's ``security.txt`` (user-triggered network call).

    Tries the RFC 9116 well-known location, then the legacy root path. Returns
    ``None`` if none is found or the host is unreachable. This performs an
    outbound request **to the assessment target only** and should be invoked
    solely on explicit user action.
    """
    host = re.sub(r"^https?://", "", host.strip()).split("/")[0]
    if not host:
        return None
    candidates = [
        f"https://{host}/.well-known/security.txt",
        f"https://{host}/security.txt",
    ]
    for url in candidates:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SecurityOps-Assistant"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    continue
                body = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            _LOG.info("No security.txt at %s (%s)", url, exc)
            continue
        if "contact:" in body.lower():
            return parse_security_txt(body, source=url)
    return None
