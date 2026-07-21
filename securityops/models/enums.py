"""Enumerations for domain models.

All enums are ``str``-backed so their values persist cleanly in SQLite and
serialize naturally into JSON/reports.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Finding severity, aligned with common CVSS qualitative bands."""

    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        """Numeric ordering (higher == more severe) for sorting."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @property
    def color(self) -> str:
        """Hex color used in the UI and reports."""
        return {
            Severity.INFO: "#6c8ebf",
            Severity.LOW: "#3fb950",
            Severity.MEDIUM: "#d29922",
            Severity.HIGH: "#db6d28",
            Severity.CRITICAL: "#f85149",
        }[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Map a CVSS base score (0.0-10.0) to a qualitative severity."""
        if score <= 0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


class Confidence(str, Enum):
    """How strongly a finding is substantiated by collected evidence.

    Used to rank disclosures and to flag issues that still need manual
    verification. Never report a fabricated issue — an unverified observation
    must be marked ``TENTATIVE``.
    """

    CONFIRMED = "Confirmed"      # reproduced with concrete evidence
    FIRM = "Firm"                # strong evidence, minor verification remaining
    TENTATIVE = "Tentative"      # requires additional manual verification

    @property
    def rank(self) -> int:
        return {
            Confidence.TENTATIVE: 0,
            Confidence.FIRM: 1,
            Confidence.CONFIRMED: 2,
        }[self]

    @property
    def needs_verification(self) -> bool:
        return self is Confidence.TENTATIVE


class DisclosureStatus(str, Enum):
    """Lifecycle of a responsible-disclosure submission."""

    DRAFT = "Draft"
    APPROVED = "Approved"           # user approved; ready to deliver
    PREPARED = "Prepared"           # email/report handed to mail client or exported
    SUBMITTED = "Submitted"         # user confirmed it was sent
    ACKNOWLEDGED = "Acknowledged"   # vendor acknowledged receipt
    CLOSED = "Closed"


class ScanStatus(str, Enum):
    """Lifecycle state of a launched scan/task."""

    QUEUED = "Queued"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


class ScopeState(str, Enum):
    """Whether an asset is authorized for testing."""

    IN_SCOPE = "In Scope"
    OUT_OF_SCOPE = "Out of Scope"
    PENDING = "Pending"


class AssetType(str, Enum):
    """Category of an inventoried asset."""

    HOST = "Host"
    IP_RANGE = "IP Range"
    DOMAIN = "Domain"
    URL = "URL"
    WEB_APP = "Web Application"
    NETWORK = "Network"
    OTHER = "Other"
