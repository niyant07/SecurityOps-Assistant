"""Local LLM client (Ollama) with offline-safe fallback.

This module talks to a locally-running `Ollama <https://ollama.com>`_ instance
over ``http://localhost:11434`` using only the Python standard library, so it
adds no dependency and makes no call to any cloud service. If Ollama is not
running (or no model is pulled), :meth:`LocalLLM.available` returns ``False`` and
callers fall back to the deterministic rule-based logic elsewhere in the app.

Nothing here executes commands or takes actions — it only turns text into text.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..core.logging_config import get_logger

_LOG = get_logger("ai.llm")


@dataclass
class LLMConfig:
    """Configuration for the local LLM connection."""

    host: str = "http://localhost:11434"
    model: str = "llama3"
    #: Seconds to wait when probing availability (kept short so the UI stays snappy).
    probe_timeout: float = 1.5
    #: Seconds to wait for a full generation.
    request_timeout: float = 120.0
    #: Lower = more deterministic. Planning wants low creativity.
    temperature: float = 0.1


class LocalLLM:
    """Thin, dependency-free client for a local Ollama server."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self._cfg = config or LLMConfig()
        self._available: bool | None = None  # cached probe result

    @property
    def model(self) -> str:
        return self._cfg.model

    # ------------------------------------------------------------------ #
    # Availability
    # ------------------------------------------------------------------ #
    def available(self, refresh: bool = False) -> bool:
        """Return True if a local Ollama server with the configured model responds."""
        if self._available is not None and not refresh:
            return self._available
        self._available = self._probe()
        return self._available

    def _probe(self) -> bool:
        try:
            req = urllib.request.Request(f"{self._cfg.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=self._cfg.probe_timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            _LOG.info("Local LLM unavailable (%s); using deterministic fallback.", exc)
            return False

        models = {m.get("name", "").split(":")[0] for m in payload.get("models", [])}
        if self._cfg.model.split(":")[0] not in models and models:
            _LOG.warning(
                "Ollama is up but model %r not found. Available: %s",
                self._cfg.model, ", ".join(sorted(models)) or "(none)",
            )
        _LOG.info("Local LLM available at %s (model=%s)", self._cfg.host, self._cfg.model)
        return True

    # ------------------------------------------------------------------ #
    # Generation
    # ------------------------------------------------------------------ #
    def generate(self, prompt: str, system: str | None = None) -> str | None:
        """Return the model's completion, or ``None`` on any failure.

        The caller is expected to treat ``None`` as "fall back to rules".
        """
        body: dict[str, object] = {
            "model": self._cfg.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self._cfg.temperature},
        }
        if system:
            body["system"] = system

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self._cfg.host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._cfg.request_timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            _LOG.warning("LLM generation failed (%s); falling back.", exc)
            self._available = False
            return None
        return str(payload.get("response", "")).strip() or None

    def generate_json(self, prompt: str, system: str | None = None) -> object | None:
        """Generate and parse a JSON response, tolerating code-fenced output."""
        raw = self.generate(prompt, system)
        if raw is None:
            return None
        return _extract_json(raw)


def _extract_json(text: str) -> object | None:
    """Best-effort extraction of a JSON object/array from model output."""
    fenced = text
    if "```" in fenced:
        # strip the first fenced block's language hint and fences
        parts = fenced.split("```")
        if len(parts) >= 2:
            fenced = parts[1]
            if fenced.lstrip().lower().startswith("json"):
                fenced = fenced.lstrip()[4:]
    # Narrow to the outermost bracket pair.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = fenced.find(opener)
        end = fenced.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(fenced[start : end + 1])
            except ValueError:
                continue
    return None
