"""AI Bug Bounty Assistant module.

Integrates with the rest of the platform (project database, workflow engine,
AI assistant, reporting) and adds bug-bounty-specific capabilities:

* **Scope import & validation** — parse an engagement's in-scope / out-of-scope
  rules and enforce them as a hard gate before anything targets an asset.
* **Target-type methodology** — build an assessment workflow tailored to the
  asset type (web app, API, mobile backend, desktop, network).
* **Scope-aware planning** — produce a reviewable plan that only ever targets
  authorized, in-scope assets.
* **Bug bounty reporting** — reports with scope, methodology, and per-finding
  reproduction steps.

Everything runs locally; no cloud services are used.
"""

from __future__ import annotations

from .scope import Scope, ScopeDecision, ScopeValidator, TargetType, parse_scope_text

__all__ = ["Scope", "ScopeDecision", "ScopeValidator", "TargetType", "parse_scope_text"]
