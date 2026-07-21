"""Offline assistant package.

The "AI" assistant is a deterministic, fully offline knowledge base. It makes no
network requests and calls no external LLM. It reasons over the tool catalog and
a curated set of assessment-phase heuristics and remediation templates.
"""

from __future__ import annotations

from .assistant import Assistant, AssistantReply

__all__ = ["Assistant", "AssistantReply"]
