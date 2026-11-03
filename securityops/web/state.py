"""The current assessment, shared between HTTP requests and background threads."""

from __future__ import annotations

import threading
from typing import Any

from ..assessment.analysis import Analysis, LLMProvider, analyze, make_provider
from ..assessment.gather import STEPS, ScanResult, TargetError, parse_target, run_assessment
from ..bugbounty.scope import Scope, ScopeValidator
from ..core.logging_config import get_logger

_LOG = get_logger("web.assessment")
_AUDIT = get_logger("audit")


class ScopeError(ValueError):
    """The target is outside the configured assessment scope."""


class AssessmentSession:
    """One assessment at a time: gather in the background, then analyze on request."""

    def __init__(self, config: Any, provider: LLMProvider | None = None) -> None:
        self.config = config
        self.provider = provider or make_provider(config)
        self.lock = threading.Lock()
        self.status = "idle"          # idle | running | done | error
        self.analyzing = False
        self.target = ""
        self.steps: list[dict[str, str]] = []
        self.scan: ScanResult | None = None
        self.analysis: Analysis | None = None
        self.error = ""

    # ------------------------------------------------------------------ #
    def check_scope(self, target: str) -> None:
        """Respect assessment.allowed_targets / blocked_targets from the config."""
        allowed = [str(t) for t in self.config.get("assessment.allowed_targets", []) or []]
        blocked = [str(t) for t in self.config.get("assessment.blocked_targets", []) or []]
        host = parse_target(target).host
        if blocked and ScopeValidator(Scope(in_scope=blocked)).is_in_scope(host):
            raise ScopeError(f"{host} is listed in assessment.blocked_targets.")
        if allowed and not ScopeValidator(Scope(in_scope=allowed)).is_in_scope(host):
            raise ScopeError(f"{host} is not in assessment.allowed_targets "
                             f"({', '.join(allowed)}).")

    def start(self, target: str) -> None:
        """Validate and start information gathering in a background thread."""
        parse_target(target)  # raises TargetError with a friendly message
        self.check_scope(target)
        with self.lock:
            if self.status == "running" or self.analyzing:
                raise RuntimeError("An assessment is already in progress.")
            self.status, self.target, self.error = "running", target.strip(), ""
            self.scan, self.analysis = None, None
            self.steps = [{"name": name, "status": "pending"} for name in STEPS]
        _AUDIT.info("Assessment started for %s (authorization confirmed by operator)", target)
        threading.Thread(target=self._gather, args=(target,), daemon=True,
                         name="assessment").start()

    def _progress(self, name: str, status: str) -> None:
        with self.lock:
            for step in self.steps:
                if step["name"] == name:
                    step["status"] = status

    def _gather(self, target: str) -> None:
        timeout = float(self.config.get("assessment.timeout_seconds", 8))
        try:
            scan = run_assessment(target, self._progress, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - report every failure to the UI
            _LOG.exception("Assessment of %s failed", target)
            with self.lock:
                self.status, self.error = "error", f"The assessment failed: {exc}"
            return
        with self.lock:
            self.scan, self.status = scan, "done"
        _AUDIT.info("Assessment finished for %s", target)

    def start_analysis(self) -> None:
        with self.lock:
            if self.scan is None:
                raise RuntimeError("Run an assessment before requesting AI analysis.")
            if self.analyzing:
                raise RuntimeError("AI analysis is already running.")
            self.analyzing = True
            scan = self.scan
        threading.Thread(target=self._analyze, args=(scan,), daemon=True,
                         name="analysis").start()

    def _analyze(self, scan: ScanResult) -> None:
        try:
            result = analyze(scan, self.provider)
        except Exception as exc:  # noqa: BLE001
            _LOG.exception("Analysis failed")
            with self.lock:
                self.analyzing, self.error = False, f"Analysis failed: {exc}"
            return
        with self.lock:
            self.analysis, self.analyzing = result, False

    def reset(self) -> None:
        with self.lock:
            if self.status == "running" or self.analyzing:
                raise RuntimeError("Wait for the current step to finish.")
            self.status, self.target, self.error = "idle", "", ""
            self.steps, self.scan, self.analysis = [], None, None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "status": self.status,
                "analyzing": self.analyzing,
                "target": self.target,
                "steps": [dict(step) for step in self.steps],
                "scan": self.scan.to_dict() if self.scan else None,
                "analysis": self.analysis.to_dict() if self.analysis else None,
                "error": self.error,
                "provider": self.provider.name,
            }


__all__ = ["AssessmentSession", "ScopeError", "TargetError"]
