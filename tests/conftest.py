"""Offline pytest harness. Tests must never open a network socket."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
DUMPS = FIXTURE_ROOT / "dumps"
EXPECTED = FIXTURE_ROOT / "expected"


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("network disabled: ScrubMCP tests are offline")

    class _BlockedSocket:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("network disabled: ScrubMCP tests are offline")

    monkeypatch.setattr(socket, "socket", _BlockedSocket)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    if hasattr(socket, "create_server"):
        monkeypatch.setattr(socket, "create_server", _blocked)


@pytest.fixture
def dumps_dir() -> Path:
    return DUMPS


@pytest.fixture
def expected_dir() -> Path:
    return EXPECTED
