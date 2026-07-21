"""Tests for the local LLM client's offline-safe behavior.

These never contact a real server: the client must degrade gracefully to
"unavailable" when nothing is listening, which is what drives the deterministic
fallback everywhere else.
"""

from __future__ import annotations

from securityops.ai.llm import LLMConfig, LocalLLM, _extract_json


def test_unavailable_when_no_server() -> None:
    # Use a port nothing listens on with a tiny timeout.
    llm = LocalLLM(LLMConfig(host="http://127.0.0.1:9", probe_timeout=0.2))
    assert llm.available() is False


def test_generate_returns_none_when_unavailable() -> None:
    llm = LocalLLM(LLMConfig(host="http://127.0.0.1:9", request_timeout=0.2))
    assert llm.generate("hello") is None
    assert llm.generate_json("hello") is None


def test_extract_json_plain() -> None:
    assert _extract_json('{"tools": ["nmap"]}') == {"tools": ["nmap"]}


def test_extract_json_fenced() -> None:
    text = "Sure!\n```json\n{\"tools\": [\"nmap\", \"nikto\"]}\n```\nDone."
    assert _extract_json(text) == {"tools": ["nmap", "nikto"]}


def test_extract_json_embedded_array() -> None:
    assert _extract_json("noise [1, 2, 3] trailing") == [1, 2, 3]


def test_extract_json_invalid_returns_none() -> None:
    assert _extract_json("no json here at all") is None
