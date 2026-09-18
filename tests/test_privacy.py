from __future__ import annotations

import logging

from scrubmcp.privacy import NEVER_UPLOADS, RedactingFilter, assert_local_only, counts_only


def test_never_uploads_contract() -> None:
    assert NEVER_UPLOADS is True
    assert_local_only()


def test_redacting_filter_strips_secretish() -> None:
    filt = RedactingFilter()
    record = logging.LogRecord(
        name="scrubmcp",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="leaked alice@example.com and sk-proj-THISISNOTAREALOPENAIKEY_abc1234567890xyz",
        args=(),
        exc_info=None,
    )
    assert filt.filter(record) is True
    assert "alice@example.com" not in record.msg
    assert "sk-proj-THISISNOTAREALOPENAIKEY" not in record.msg
    assert "[REDACTED]" in record.msg


def test_counts_only_has_no_values() -> None:
    line = counts_only({"email": 2, "api_key": 1})
    assert "redacted 3 findings" in line
    assert "email=2" in line
    assert "@" not in line
