from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from scrubmcp.mcp_server import TOOLS, call_tool, handle_message, serve_text_ndjson


def test_tools_list_names() -> None:
    reply = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert reply is not None
    names = {tool["name"] for tool in reply["result"]["tools"]}
    assert names == {"scrub_text", "scrub_file", "detect_pii"}
    assert {t["name"] for t in TOOLS} == names


def test_initialize_privacy_banner() -> None:
    reply = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        }
    )
    assert reply is not None
    text = json.dumps(reply)
    assert "Never uploads" in text
    assert reply["result"]["serverInfo"]["name"] == "scrubmcp"


def test_scrub_text_tool() -> None:
    payload = json.loads(
        call_tool("scrub_text", {"text": "mail alice@example.com please"})
    )
    assert payload["text"] == "mail [EMAIL_1] please"
    assert payload["uploads"] is False
    assert payload["remote_llm"] is False


def test_detect_pii_tool_masks() -> None:
    raw = call_tool("detect_pii", {"text": "alice@example.com"})
    assert "alice@example.com" not in raw
    payload = json.loads(raw)
    assert payload["findings"][0]["kind"] == "email"
    assert payload["findings"][0]["masked"] == "a***@example.com"


def test_scrub_file_tool(dumps_dir: Path) -> None:
    payload = json.loads(call_tool("scrub_file", {"path": str(dumps_dir / "emails.txt")}))
    assert "[EMAIL_1]" in payload["text"]
    assert "alice@example.com" not in payload["text"]


def test_scrub_file_rejects_url() -> None:
    result = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "scrub_file", "arguments": {"path": "https://evil.test/x"}},
        }
    )
    assert result is not None
    assert result["result"]["isError"] is True


def test_ndjson_stdio_roundtrip() -> None:
    stdin = StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}) + "\n"
    )
    stdout = StringIO()
    serve_text_ndjson(stdin, stdout)
    reply = json.loads(stdout.getvalue())
    assert "tools" in reply["result"]
