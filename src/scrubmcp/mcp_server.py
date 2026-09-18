"""Minimal MCP stdio server. Local tools only. No remote LLM calls.

Speaks official Content-Length framing and accepts newline-delimited JSON
so hosts and tests can both talk to it without extra SDKs.
"""

from __future__ import annotations

import json
import sys
from typing import Any, BinaryIO, TextIO

from scrubmcp import __version__
from scrubmcp.engine import ScrubResult, detect, dumps_detect, read_local_file, scrub, scrub_path
from scrubmcp.privacy import assert_local_only

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "scrubmcp"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scrub_text",
        "description": (
            "Redact PII and secret-like strings in text locally "
            "(emails, phones, SSN-like, seed-phrase-ish, API-key-ish). "
            "Never uploads. Never calls a remote LLM. Use before any cloud model."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Raw text to scrub."},
            },
            "required": ["text"],
        },
    },
    {
        "name": "scrub_file",
        "description": (
            "Read a local file and return scrubbed text. Rejects URLs. "
            "Local filesystem only. Never uploads the file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative local path."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "detect_pii",
        "description": (
            "Detect PII/secret-like spans and return masked findings "
            "(no raw secrets). Local-only. Optional path reads a local file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Raw text to scan."},
                "path": {"type": "string", "description": "Local file to scan instead of text."},
            },
        },
    },
]


class MCPError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """Process one JSON-RPC message. Notifications return None."""
    assert_local_only()
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}
    if method is None:
        return _error(msg_id, -32600, "Invalid Request")
    if msg_id is None and method.startswith("notifications/"):
        return None
    if method == "initialize":
        return _result(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": __version__,
                    "description": "Local PII scrub + footprint hygiene. Never uploads.",
                },
                "instructions": (
                    "Call scrub_text or scrub_file before sending dumps to a cloud model. "
                    "ScrubMCP never uploads data and never logs secrets."
                ),
            },
        )
    if method == "ping":
        return _result(msg_id, {})
    if method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        try:
            name = params.get("name")
            arguments = params.get("arguments") or {}
            payload = call_tool(name, arguments)
            return _result(
                msg_id,
                {
                    "content": [{"type": "text", "text": payload}],
                    "isError": False,
                },
            )
        except MCPError as exc:
            return _result(
                msg_id,
                {
                    "content": [{"type": "text", "text": exc.message}],
                    "isError": True,
                },
            )
        except Exception as exc:  # pragma: no cover - defensive
            return _result(
                msg_id,
                {
                    "content": [{"type": "text", "text": f"tool error: {exc.__class__.__name__}"}],
                    "isError": True,
                },
            )
    return _error(msg_id, -32601, f"Method not found: {method}")


def call_tool(name: str | None, arguments: dict[str, Any]) -> str:
    if name == "scrub_text":
        text = arguments.get("text")
        if not isinstance(text, str):
            raise MCPError(-32602, "scrub_text requires string argument 'text'")
        result = scrub(text)
        return json.dumps(result.to_public_dict(include_text=True), indent=2)
    if name == "scrub_file":
        path = arguments.get("path")
        if not isinstance(path, str):
            raise MCPError(-32602, "scrub_file requires string argument 'path'")
        result = scrub_path(path)
        return json.dumps(result.to_public_dict(include_text=True), indent=2)
    if name == "detect_pii":
        text = arguments.get("text")
        path = arguments.get("path")
        if isinstance(path, str) and path:
            source_text, resolved = read_local_file(path)
            result = ScrubResult(
                text=source_text, findings=detect(source_text), source=str(resolved)
            )
            return dumps_detect(result)
        if not isinstance(text, str):
            raise MCPError(-32602, "detect_pii requires 'text' or 'path'")
        result = ScrubResult(text=text, findings=detect(text), source="text")
        return dumps_detect(result)
    raise MCPError(-32601, f"Unknown tool: {name}")


def _result(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _read_stdio_message(buffer: BinaryIO) -> dict[str, Any] | None:
    header_line = buffer.readline()
    if not header_line:
        return None
    if header_line in {b"\n", b"\r\n"}:
        return _read_stdio_message(buffer)
    if header_line.lower().startswith(b"content-length:"):
        length = int(header_line.split(b":", 1)[1].strip())
        while True:
            line = buffer.readline()
            if line in {b"", b"\n", b"\r\n"}:
                break
        body = buffer.read(length)
        if len(body) < length:
            return None
        return json.loads(body.decode("utf-8"))
    # Newline-delimited JSON (tests / simple hosts).
    line = header_line.decode("utf-8").strip()
    if not line:
        return _read_stdio_message(buffer)
    return json.loads(line)


def _write_stdio_message(buffer: BinaryIO, message: dict[str, Any]) -> None:
    body = json.dumps(message, ensure_ascii=True).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    buffer.write(header + body)
    buffer.flush()


def serve(
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    *,
    ndjson: bool = False,
) -> None:
    """Run until stdin closes. Never writes secrets to logs."""
    assert_local_only()
    in_buf = stdin or sys.stdin.buffer
    out_buf = stdout or sys.stdout.buffer
    while True:
        try:
            message = _read_stdio_message(in_buf)
        except json.JSONDecodeError:
            continue
        if message is None:
            break
        reply = handle_message(message)
        if reply is None:
            continue
        if ndjson:
            out_buf.write((json.dumps(reply) + "\n").encode("utf-8"))
            out_buf.flush()
        else:
            _write_stdio_message(out_buf, reply)


def serve_text_ndjson(stdin: TextIO, stdout: TextIO) -> None:
    """Test helper: one JSON object per line, no Content-Length."""
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        reply = handle_message(json.loads(line))
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
