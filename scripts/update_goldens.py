#!/usr/bin/env python3
"""Rewrite tests/fixtures/expected from the current local engine."""

from __future__ import annotations

from pathlib import Path

from scrubmcp.engine import dumps_detect, scrub

ROOT = Path(__file__).resolve().parents[1]
DUMPS = ROOT / "tests" / "fixtures" / "dumps"
EXPECTED = ROOT / "tests" / "fixtures" / "expected"


def main() -> None:
    EXPECTED.mkdir(parents=True, exist_ok=True)
    for dump in sorted(p for p in DUMPS.iterdir() if p.is_file()):
        result = scrub(dump.read_text(encoding="utf-8"))
        (EXPECTED / f"{dump.name}.scrubbed").write_text(result.text, encoding="utf-8")
        (EXPECTED / f"{dump.name}.detect.json").write_text(dumps_detect(result), encoding="utf-8")
        print(f"updated {dump.name}: {result.status}")


if __name__ == "__main__":
    main()
