"""Local regex / wordlist detectors. No network. No LLM."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Iterable, Iterator

KIND_EMAIL = "email"
KIND_PHONE = "phone"
KIND_SSN = "ssn"
KIND_SEED = "seed_phrase"
KIND_API_KEY = "api_key"

KINDS = (KIND_EMAIL, KIND_PHONE, KIND_SSN, KIND_SEED, KIND_API_KEY)

# Officially reserved / documentation examples only. Used for tests + docs.
EXAMPLE_EMAIL = "alice@example.com"
EXAMPLE_PHONE = "+1 415 555 0132"
EXAMPLE_SSN = "078-05-1120"  # historically published; not a live SSN
EXAMPLE_SEED = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"
)

# NANP first, then short E.164. Intentionally does not match ###-##-#### (SSN).
_NANP_RE = re.compile(
    r"(?<!\w)(?:\+?1[\s.\-]*)?(?:\(?[2-9]\d{2}\)?[\s.\-]+)\d{3}[\s.\-]+\d{4}(?!\w)"
)
_E164_RE = re.compile(
    r"(?<!\w)\+[2-9]\d{0,2}(?:[\s.\-]*\d{2,4}){2,3}(?!\d)"
)

_SSN_RE = re.compile(r"(?<!\d)(?!000|666)[0-8]\d{2}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")

_SEED_LABEL_RE = re.compile(
    r"(?i)\b(?:seed(?:\s+phrase)?|recovery(?:\s+phrase)?|mnemonic|secret\s+phrase|wallet\s+words?)\b"
)

_WORD_RE = re.compile(r"[A-Za-z]+")

# Prefix / shape detectors for secrets agents actually paste into context.
_API_KEY_SPECS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("github", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("stripe", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("google_api", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    (
        "assigned_secret",
        re.compile(
            r"(?i)(?:api[_-]?key|secret(?:_key)?|access[_-]?token|auth[_-]?token"
            r"|private[_-]?key|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+]{16,})['\"]?"
        ),
    ),
    (
        "eth_privkey",
        re.compile(r"(?i)(?:private[_-]?key|privkey|secret[_-]?key)\s*[:=]?\s*(0x[a-f0-9]{64})"),
    ),
)

MIN_SEED_UNLABELED = 12
MIN_SEED_LABELED = 8
SEED_LENGTHS = {12, 15, 18, 21, 24}


@dataclass(frozen=True)
class RawMatch:
    kind: str
    start: int
    end: int
    value: str
    detector: str


@lru_cache(maxsize=1)
def bip39_words() -> frozenset[str]:
    data = resources.files("scrubmcp").joinpath("data/bip39_en.txt").read_text(encoding="utf-8")
    words = {line.strip().lower() for line in data.splitlines() if line.strip()}
    if len(words) != 2048:
        raise RuntimeError("BIP39 English wordlist must contain 2048 words")
    return frozenset(words)


def iter_matches(text: str) -> list[RawMatch]:
    """Collect raw matches, then drop overlaps (longest / earliest wins)."""
    found: list[RawMatch] = []
    found.extend(_scan_regex(text, KIND_EMAIL, _EMAIL_RE, "email"))
    found.extend(_scan_regex(text, KIND_PHONE, _NANP_RE, "phone_nanp"))
    found.extend(_scan_regex(text, KIND_PHONE, _E164_RE, "phone_e164"))
    found.extend(_scan_regex(text, KIND_SSN, _SSN_RE, "ssn"))
    found.extend(_scan_api_keys(text))
    found.extend(_scan_seed_phrases(text))
    return _resolve_overlaps(found)


def _scan_regex(text: str, kind: str, pattern: re.Pattern[str], detector: str) -> Iterator[RawMatch]:
    for match in pattern.finditer(text):
        yield RawMatch(kind, match.start(), match.end(), match.group(0), detector)


def _scan_api_keys(text: str) -> Iterator[RawMatch]:
    for detector, pattern in _API_KEY_SPECS:
        for match in pattern.finditer(text):
            if match.lastindex:
                start, end = match.span(1)
                value = match.group(1)
            else:
                start, end = match.span(0)
                value = match.group(0)
            if _looks_like_placeholder(value):
                continue
            if detector == "assigned_secret" and re.fullmatch(r"0x[a-fA-F0-9]{64}", value):
                continue
            yield RawMatch(KIND_API_KEY, start, end, value, detector)


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in ("your_", "xxx", "todo", "changeme", "placeholder", "<"))


def _label_hits(text: str) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    exact: list[tuple[int, int]] = []
    windows: list[tuple[int, int]] = []
    for match in _SEED_LABEL_RE.finditer(text):
        exact.append((match.start(), match.end()))
        windows.append((match.start(), min(len(text), match.end() + 400)))
    return exact, windows


def _covered(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in spans)


def _near_label(start: int, end: int, labels: list[tuple[int, int]]) -> bool:
    return any(ls <= start < le or ls < end <= le for ls, le in labels)


def _scan_seed_phrases(text: str) -> Iterator[RawMatch]:
    words = bip39_words()
    label_exact, label_windows = _label_hits(text)
    tokens = list(_WORD_RE.finditer(text))
    i = 0
    n = len(tokens)
    while i < n:
        if tokens[i].group(0).lower() not in words or _covered(tokens[i].start(), label_exact):
            i += 1
            continue
        j = i
        while j < n and tokens[j].group(0).lower() in words:
            if _covered(tokens[j].start(), label_exact):
                break
            if j > i and not _only_separators(text, tokens[j - 1].end(), tokens[j].start()):
                break
            j += 1
        run = tokens[i:j]
        if not run:
            i += 1
            continue
        labeled = _near_label(run[0].start(), run[-1].end(), label_windows)
        snapped = _snap_seed_run(run, labeled)
        if snapped:
            start = snapped[0].start()
            end = snapped[-1].end()
            yield RawMatch(KIND_SEED, start, end, text[start:end], "bip39")
        i = j if j > i else i + 1


def _snap_seed_run(run: list, labeled: bool) -> list:
    """Prefer 12/15/18/21/24-word suffixes so headings like 'twelve' drop off."""
    length = len(run)
    if labeled and length >= MIN_SEED_LABELED:
        if length in SEED_LENGTHS:
            return run
        for target in (24, 21, 18, 15, 12):
            if length > target:
                return run[-target:]
        return run
    if length >= MIN_SEED_UNLABELED:
        if length in SEED_LENGTHS:
            return run
        for target in (24, 21, 18, 15, 12):
            if length >= target:
                return run[-target:]
    return []


def _only_separators(text: str, left: int, right: int) -> bool:
    gap = text[left:right]
    if not gap:
        return True
    # Allow spaces, commas, newlines, numbering like "1." / "12)" between words.
    return re.fullmatch(r"[\s,;:\-–—|/]+(?:\d{1,2}[.)]\s*)?", gap) is not None or re.fullmatch(
        r"[\s,;:\-–—|/]*\d{1,2}[.)]\s*", gap
    ) is not None


def _resolve_overlaps(matches: Iterable[RawMatch]) -> list[RawMatch]:
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start), m.kind))
    kept: list[RawMatch] = []
    for match in ordered:
        if any(not (match.end <= k.start or match.start >= k.end) for k in kept):
            continue
        kept.append(match)
    return sorted(kept, key=lambda m: m.start)


def mask_value(kind: str, value: str) -> str:
    """Return a display-safe preview. Never the full secret."""
    if kind == KIND_EMAIL:
        local, _, domain = value.partition("@")
        head = local[:1] if local else "*"
        return f"{head}***@{domain}"
    if kind == KIND_PHONE:
        digits = re.sub(r"\D", "", value)
        tail = digits[-4:] if len(digits) >= 4 else "****"
        return f"***-***-{tail}"
    if kind == KIND_SSN:
        return f"***-**-{value[-4:]}" if len(value) >= 4 else "***-**-****"
    if kind == KIND_SEED:
        parts = _WORD_RE.findall(value)
        if not parts:
            return "[seed]"
        if len(parts) == 1:
            return f"{parts[0][:2]}***"
        return f"{parts[0]} ***({len(parts)} words)*** {parts[-1]}"
    if kind == KIND_API_KEY:
        if len(value) <= 8:
            return value[:2] + "****"
        return f"{value[:4]}…{value[-4:]}"
    return "****"
