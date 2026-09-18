"""Golden tests against checked-in fixture dumps. Offline only."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scrubmcp.engine import dumps_detect, scrub

SECRET_NEEDLES = (
    "alice@example.com",
    "bob.builder@example.org",
    "078-05-1120",
    "219-09-9999",
    "sk-proj-THISISNOTAREALOPENAIKEY",
    "sk-ant-api03-not-a-real-anthropic-key",
    "ghp_notarealgithubtoken",
    "AKIAIOSFODNN7EXAMPLE",
    "abandon abandon abandon",
    "n0tArealAssignedSecret99",
)


def _dump_files(dumps_dir: Path) -> list[Path]:
    return sorted(p for p in dumps_dir.iterdir() if p.is_file())


def test_every_dump_has_goldens(dumps_dir: Path, expected_dir: Path) -> None:
    missing = []
    for dump in _dump_files(dumps_dir):
        for suffix in (".scrubbed", ".detect.json"):
            expected = expected_dir / f"{dump.name}{suffix}"
            if not expected.is_file():
                missing.append(str(expected))
    assert not missing, f"missing goldens: {missing}"


@pytest.mark.offline
def test_scrub_goldens(dumps_dir: Path, expected_dir: Path) -> None:
    for dump in _dump_files(dumps_dir):
        result = scrub(dump.read_text(encoding="utf-8"))
        expected = (expected_dir / f"{dump.name}.scrubbed").read_text(encoding="utf-8")
        assert result.text == expected, dump.name
        for needle in SECRET_NEEDLES:
            assert needle not in result.text


@pytest.mark.offline
def test_detect_goldens(dumps_dir: Path, expected_dir: Path) -> None:
    for dump in _dump_files(dumps_dir):
        result = scrub(dump.read_text(encoding="utf-8"))
        actual = json.loads(dumps_detect(result))
        expected = json.loads((expected_dir / f"{dump.name}.detect.json").read_text(encoding="utf-8"))
        assert actual == expected, dump.name
        blob = json.dumps(actual)
        for needle in SECRET_NEEDLES:
            assert needle not in blob


def test_clean_dump_is_empty(dumps_dir: Path) -> None:
    result = scrub((dumps_dir / "clean.txt").read_text(encoding="utf-8"))
    assert result.findings == []
    assert result.counts == {}
