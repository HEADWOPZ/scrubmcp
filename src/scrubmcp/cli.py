"""CLI pipe: ``scrubmcp scrub`` / ``detect`` over stdin or files.

Examples::

    cat dump.json | scrubmcp
    cat dump.json | scrubmcp scrub
    scrubmcp detect dump.json
    scrubmcp serve
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scrubmcp import __version__
from scrubmcp.engine import (
    ScrubResult,
    detect,
    detect_path,
    dumps_detect,
    dumps_scrub_json,
    scrub,
    scrub_path,
)
from scrubmcp.privacy import assert_local_only, configure_logging

COMMANDS = {"scrub", "detect", "serve", "skills", "version"}


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    assert_local_only()
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw in (["--version"], ["-V"]):
        sys.stdout.write(f"scrubmcp {__version__}\n")
        return 0
    args = _build_parser().parse_args(_normalize(raw))

    if args.command == "serve":
        from scrubmcp.mcp_server import serve

        serve(ndjson=args.ndjson)
        return 0
    if args.command == "skills":
        return _cmd_skills(args)
    if args.command == "version":
        sys.stdout.write(f"scrubmcp {__version__}\n")
        return 0

    try:
        results = _collect(args)
    except (OSError, ValueError) as exc:
        _err(f"error: {exc}")
        return 2

    if args.command == "detect":
        return _emit_detect(results, args)
    return _emit_scrub(results, args)


def _normalize(argv: list[str]) -> list[str]:
    if not argv:
        return ["scrub"]
    if argv[0] in COMMANDS or argv[0] in {"-h", "--help"}:
        return argv
    return ["scrub", *argv]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scrubmcp",
        description=(
            "Local PII + secret hygiene for agent pipelines. "
            "Never uploads. Never calls a remote LLM."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scrub_p = sub.add_parser("scrub", help="Redact PII/secrets from stdin or files")
    _add_io_flags(scrub_p)
    scrub_p.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit structured JSON (scrubbed text + masked findings)",
    )

    detect_p = sub.add_parser("detect", help="Detect PII/secrets; print masked findings JSON")
    _add_io_flags(detect_p)

    serve_p = sub.add_parser("serve", help="Run the MCP stdio server")
    serve_p.add_argument(
        "--ndjson",
        action="store_true",
        help="Write newline-delimited JSON instead of Content-Length framing",
    )

    skills_p = sub.add_parser("skills", help="Show bundled Hermes / agent skill paths")
    skills_p.add_argument("--path", action="store_true", help="Print the skills root only")

    sub.add_parser("version", help="Print version")
    return parser


def _add_io_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files to read. If omitted, read stdin.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Do not print the counts status line on stderr",
    )


def _collect(args: argparse.Namespace) -> list[ScrubResult]:
    command = args.command
    paths = list(getattr(args, "paths", []) or [])
    if paths:
        results = []
        for path in paths:
            results.append(detect_path(path) if command == "detect" else scrub_path(path))
        return results
    if sys.stdin.isatty():
        raise ValueError("nothing to read: pipe stdin or pass a file")
    text = sys.stdin.read()
    if command == "detect":
        return [ScrubResult(text=text, findings=detect(text), source="stdin")]
    result = scrub(text)
    result.source = "stdin"
    return [result]


def _emit_scrub(results: list[ScrubResult], args: argparse.Namespace) -> int:
    as_json = bool(getattr(args, "as_json", False))
    quiet = bool(getattr(args, "quiet", False))
    if as_json:
        if len(results) == 1:
            sys.stdout.write(dumps_scrub_json(results[0]))
        else:
            payload = [r.to_public_dict(include_text=True) for r in results]
            sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        for index, result in enumerate(results):
            if index:
                sys.stdout.write("\n")
            sys.stdout.write(result.text)
            if result.text and not result.text.endswith("\n"):
                sys.stdout.write("\n")
    if not quiet:
        for result in results:
            label = result.source if result.source != "text" else "stdin"
            _err(f"{label}: {result.status}")
    return 0


def _emit_detect(results: list[ScrubResult], args: argparse.Namespace) -> int:
    quiet = bool(getattr(args, "quiet", False))
    if len(results) == 1:
        sys.stdout.write(dumps_detect(results[0]))
    else:
        payload = [r.to_public_dict(include_text=False) for r in results]
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if not quiet:
        for result in results:
            _err(f"{result.source}: {result.status}")
    return 0


def _cmd_skills(args: argparse.Namespace) -> int:
    root = skills_root()
    if args.path:
        sys.stdout.write(f"{root}\n")
        return 0
    sys.stdout.write("Hermes / Claude Code skills (copy or symlink into your skills dir):\n")
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        skill = child / "SKILL.md"
        if skill.is_file():
            sys.stdout.write(f"  {child.name}\t{child}\n")
    sys.stdout.write(
        "\nInstall hint:\n"
        f"  mkdir -p ~/.hermes/skills ~/.claude/skills\n"
        f"  cp -R {root}/* ~/.hermes/skills/\n"
        f"  cp -R {root}/* ~/.claude/skills/\n"
    )
    return 0


def skills_root() -> Path:
    here = Path(__file__).resolve().parent
    packaged = here / "skills"
    if packaged.is_dir():
        return packaged
    repo = here.parents[1] / "skills"
    if repo.is_dir():
        return repo
    raise FileNotFoundError("bundled skills not found")


def _err(message: str) -> None:
    sys.stderr.write(f"scrubmcp: {message}\n")


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    run()
