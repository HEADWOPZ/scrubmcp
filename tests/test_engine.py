from __future__ import annotations

import json

import pytest

from scrubmcp import LOCAL_ONLY, REMOTE_LLM, __version__, detect, scrub, scrub_path
from scrubmcp.engine import dumps_detect


def test_public_contract() -> None:
    assert LOCAL_ONLY is True
    assert REMOTE_LLM is False
    assert __version__


def test_stable_tokens_for_repeated_values() -> None:
    text = "alice@example.com then alice@example.com and bob.builder@example.org"
    result = scrub(text)
    assert result.text.count("[EMAIL_1]") == 2
    assert "[EMAIL_2]" in result.text
    assert "alice@example.com" not in result.text


def test_detect_omits_raw_values() -> None:
    text = "alice@example.com 078-05-1120"
    payload = json.loads(dumps_detect(scrub(text)))
    blob = json.dumps(payload)
    assert "alice@example.com" not in blob
    assert "078-05-1120" not in blob
    assert payload["uploads"] is False
    assert payload["remote_llm"] is False


def test_scrub_path_rejects_urls(tmp_path) -> None:
    with pytest.raises(ValueError, match="local-only"):
        scrub_path("https://example.com/secret.csv")


def test_scrub_path_reads_local(tmp_path) -> None:
    path = tmp_path / "note.txt"
    path.write_text("hello alice@example.com", encoding="utf-8")
    result = scrub_path(path)
    assert result.text == "hello [EMAIL_1]"
    assert result.source.endswith("note.txt")


def test_detect_spans_align_with_original() -> None:
    text = "user alice@example.com done"
    findings = detect(text)
    assert findings[0].kind == "email"
    assert text[findings[0].start : findings[0].end] == "alice@example.com"
