"""Privacy contract: local-only execution and secret-safe logging.

ScrubMCP never opens a network socket for detection or redaction. Logging is
redacted by default and disabled unless SCRUBMCP_LOG is truthy. Raw matches
are never written to log records.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

NEVER_UPLOADS = True
_SECRETISH = re.compile(
    r"("
    r"sk-[A-Za-z0-9_\-]{8,}"
    r"|sk-ant-[A-Za-z0-9_\-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}"
    r"|github_pat_[A-Za-z0-9_]{8,}"
    r"|AKIA[0-9A-Z]{8,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{8,}"
    r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"
    r"|[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
    r"|\b\d{3}-\d{2}-\d{4}\b"
    r")",
    re.IGNORECASE,
)


class RedactingFilter(logging.Filter):
    """Drop or mask anything that looks like a secret before it is emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact_text(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: _redact_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(_redact_value(v) for v in record.args)
            else:
                record.args = _redact_value(record.args)
        return True


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _redact_text(text: str) -> str:
    return _SECRETISH.sub("[REDACTED]", text)


def logging_enabled() -> bool:
    flag = os.environ.get("SCRUBMCP_LOG", "").strip().lower()
    return flag in {"1", "true", "yes", "on"}


def configure_logging() -> logging.Logger:
    """Attach a redacting stderr logger. Off by default."""
    logger = logging.getLogger("scrubmcp")
    logger.handlers.clear()
    logger.propagate = False
    if not logging_enabled():
        logger.addHandler(logging.NullHandler())
        logger.setLevel(logging.CRITICAL)
        return logger
    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter())
    handler.setFormatter(logging.Formatter("scrubmcp: %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def assert_local_only() -> None:
    """Documented invariant: scrubbing never leaves the process."""
    if not NEVER_UPLOADS:
        raise RuntimeError("privacy contract broken: NEVER_UPLOADS is false")


def counts_only(counts: dict[str, int]) -> str:
    """Human status line that cannot contain secret values."""
    if not counts:
        return "redacted 0 findings"
    parts = [f"{kind}={n}" for kind, n in sorted(counts.items()) if n]
    total = sum(counts.values())
    return f"redacted {total} findings ({' '.join(parts)})"
