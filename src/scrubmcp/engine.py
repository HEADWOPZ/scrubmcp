"""Detect + redact locally. This module must never import a network client."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from scrubmcp.detectors import RawMatch, iter_matches, mask_value
from scrubmcp.privacy import assert_local_only, counts_only

MAX_FILE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    token: str
    masked: str
    detector: str

    def to_public_dict(self) -> dict[str, object]:
        """JSON-safe record. Raw value is intentionally omitted."""
        return {
            "kind": self.kind,
            "start": self.start,
            "end": self.end,
            "token": self.token,
            "masked": self.masked,
            "detector": self.detector,
        }


@dataclass
class ScrubResult:
    text: str
    findings: list[Finding] = field(default_factory=list)
    source: str = "text"

    @property
    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for finding in self.findings:
            counts[finding.kind] += 1
        return dict(counts)

    @property
    def status(self) -> str:
        return counts_only(self.counts)

    def to_public_dict(self, *, include_text: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "source": self.source,
            "counts": self.counts,
            "findings": [f.to_public_dict() for f in self.findings],
            "uploads": False,
            "remote_llm": False,
        }
        if include_text:
            payload["text"] = self.text
        return payload


def detect(text: str) -> list[Finding]:
    """Return PII/secret findings with masked previews only."""
    assert_local_only()
    raw = iter_matches(text)
    return _to_findings(raw)


def scrub(text: str) -> ScrubResult:
    """Replace findings with stable placeholders like [EMAIL_1]."""
    assert_local_only()
    findings = detect(text)
    if not findings:
        return ScrubResult(text=text, findings=[])
    pieces: list[str] = []
    cursor = 0
    for finding in findings:
        pieces.append(text[cursor : finding.start])
        pieces.append(finding.token)
        cursor = finding.end
    pieces.append(text[cursor:])
    return ScrubResult(text="".join(pieces), findings=findings)


def scrub_path(path: str | Path) -> ScrubResult:
    """Read a local file and scrub it. Rejects URLs and missing paths."""
    text, resolved = read_local_file(path)
    result = scrub(text)
    result.source = str(resolved)
    return result


def detect_path(path: str | Path) -> ScrubResult:
    text, resolved = read_local_file(path)
    result = ScrubResult(text=text, findings=detect(text), source=str(resolved))
    return result


def read_local_file(path: str | Path) -> tuple[str, Path]:
    raw = str(path).strip()
    if not raw:
        raise ValueError("path is empty")
    lowered = raw.lower()
    if lowered.startswith(("http://", "https://", "ftp://", "s3://")):
        raise ValueError("remote URLs are rejected; ScrubMCP is local-only")
    resolved = Path(raw).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"not a local file: {resolved}")
    size = resolved.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES} byte limit")
    return resolved.read_text(encoding="utf-8", errors="replace"), resolved


def dumps_detect(result: ScrubResult) -> str:
    return json.dumps(result.to_public_dict(include_text=False), indent=2, sort_keys=True) + "\n"


def dumps_scrub_json(result: ScrubResult) -> str:
    return json.dumps(result.to_public_dict(include_text=True), indent=2, sort_keys=True) + "\n"


def _to_findings(raw_matches: list[RawMatch]) -> list[Finding]:
    counters: dict[str, int] = defaultdict(int)
    seen_value: dict[tuple[str, str], str] = {}
    findings: list[Finding] = []
    for match in raw_matches:
        key = (match.kind, match.value)
        if key in seen_value:
            token = seen_value[key]
        else:
            counters[match.kind] += 1
            token = f"[{_token_prefix(match.kind)}_{counters[match.kind]}]"
            seen_value[key] = token
        findings.append(
            Finding(
                kind=match.kind,
                start=match.start,
                end=match.end,
                token=token,
                masked=mask_value(match.kind, match.value),
                detector=match.detector,
            )
        )
    return findings


def _token_prefix(kind: str) -> str:
    return {
        "email": "EMAIL",
        "phone": "PHONE",
        "ssn": "SSN",
        "seed_phrase": "SEED_PHRASE",
        "api_key": "API_KEY",
    }.get(kind, kind.upper())
