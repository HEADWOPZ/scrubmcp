from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scrubmcp.cli import main, skills_root


def test_cli_scrub_file(dumps_dir: Path, capsys) -> None:
    path = dumps_dir / "emails.txt"
    assert main(["scrub", "-q", str(path)]) == 0
    out = capsys.readouterr().out
    assert "alice@example.com" not in out
    assert "[EMAIL_1]" in out


def test_cli_detect_json_hides_secrets(dumps_dir: Path, capsys) -> None:
    path = dumps_dir / "mixed.txt"
    assert main(["detect", "-q", str(path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    blob = json.dumps(payload)
    assert "alice@example.com" not in blob
    assert "sk-proj-THISISNOTAREALOPENAIKEY" not in blob
    assert payload["counts"]["email"] == 1
    assert payload["counts"]["api_key"] >= 1


def test_cli_pipe_scrub(dumps_dir: Path) -> None:
    raw = (dumps_dir / "emails.txt").read_bytes()
    proc = subprocess.run(
        [sys.executable, "-m", "scrubmcp", "scrub", "-q"],
        input=raw,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert b"alice@example.com" not in proc.stdout
    assert b"[EMAIL_1]" in proc.stdout


def test_cli_default_is_scrub(dumps_dir: Path) -> None:
    raw = (dumps_dir / "emails.txt").read_bytes()
    proc = subprocess.run(
        [sys.executable, "-m", "scrubmcp", "-q"],
        input=raw,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert b"[EMAIL_1]" in proc.stdout


def test_cli_version(capsys) -> None:
    assert main(["version"]) == 0
    assert "scrubmcp" in capsys.readouterr().out


def test_cli_skills_lists_both() -> None:
    root = skills_root()
    names = {p.name for p in root.iterdir() if p.is_dir()}
    assert {"pre-cloud-scrub", "footprint-audit"} <= names
