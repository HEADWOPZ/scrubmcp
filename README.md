# ScrubMCP

Local PII scrub + footprint hygiene for **agent pipelines**.

Drop-in MCP + CLI that redacts emails, phones, SSN-like values, seed-phrase-ish
text, and API-key-ish secrets **before** a dump leaves the machine. Optional
Hermes skills walk a **pre-cloud scrub** and a **self-only footprint opt-out
checklist**.

**Owner:** Kevin Lance Murray (HEADWOPZ)  
**License:** MIT  
**Not VoiceRail.** VoiceRail is audio. ScrubMCP is text-pipeline privacy.

---

## Privacy guarantees

| Guarantee | Meaning |
|-----------|---------|
| **Never uploads** | Detection and redaction run in-process. No telemetry. No SaaS. |
| **No remote LLM** | Pattern + BIP39 wordlist only. Nothing is sent to a model to "help scrub." |
| **Never logs secrets** | Logging is off unless `SCRUBMCP_LOG=1`, and even then records are redacted. |
| **Local files only** | `scrub_file` rejects `http(s)://` and other remote URLs. |
| **Masked detect** | `detect` / `detect_pii` return kinds, spans, placeholders, and masked previews — not raw secrets. |
| **Opt-out, not doxxing** | `footprint-audit` is a first-party checklist. No people-search, harassment, or skip-trace tooling. |

If a future change opens a network socket or a cloud model for scrubbing, it is a bug.

```text
cat dump.json | scrubmcp          # same machine, stdout only
```

---

## Install

Python 3.10+.

```bash
python -m pip install -e ".[dev]"   # from this repo
# or, once published:
# python -m pip install scrubmcp
```

Smoke check (offline):

```bash
scrubmcp version
echo 'write alice@example.com' | scrubmcp scrub -q
# write [EMAIL_1]
```

---

## CLI pipe

| Command | What it does |
|---------|----------------|
| `scrubmcp` / `scrubmcp scrub` | Read stdin or files, print redacted text |
| `scrubmcp detect` | Masked findings JSON (no raw secrets) |
| `scrubmcp serve` | MCP stdio server |
| `scrubmcp skills` | Print bundled Hermes / Claude skill paths |

```bash
cat dump.json | scrubmcp
cat dump.json | scrubmcp scrub
scrubmcp scrub ./dump.json --json
scrubmcp detect ./dump.json
scrubmcp scrub notes.txt crm.csv
```

Stderr gets a **counts-only** status line (`redacted 4 findings (email=1 …)`).
Use `-q` to silence it. Placeholders are stable per value inside one document
(`[EMAIL_1]`, `[PHONE_1]`, `[SSN_1]`, `[SEED_PHRASE_1]`, `[API_KEY_1]`).

---

## MCP tools

| Tool | Args | Result |
|------|------|--------|
| `scrub_text` | `text` | Scrubbed text + masked findings |
| `scrub_file` | `path` | Same, from a local file |
| `detect_pii` | `text` or `path` | Masked inventory only |

### Claude Desktop / Cursor / Claude Code snippet

```json
{
  "mcpServers": {
    "scrubmcp": {
      "command": "scrubmcp",
      "args": ["serve"]
    }
  }
}
```

`python -m scrubmcp serve` works if the script is not on `PATH`.

Copy [`examples/mcp.json`](examples/mcp.json) into your host config. The server
speaks official `Content-Length` framing (newline-delimited JSON is also
accepted on stdin).

Call `scrub_text` / `scrub_file` **before** any cloud model sees a wallet dump,
CRM CSV, `.env`, or log.

---

## Hermes skills

Bundled Agent Skills (`SKILL.md` frontmatter):

| Skill | Use when |
|-------|----------|
| `pre-cloud-scrub` | An agent is about to send local data to a remote model |
| `footprint-audit` | The operator wants a **self** opt-out checklist |

```bash
scrubmcp skills
mkdir -p ~/.hermes/skills ~/.claude/skills
cp -R "$(scrubmcp skills --path)"/* ~/.hermes/skills/
cp -R "$(scrubmcp skills --path)"/* ~/.claude/skills/
```

`footprint-audit` lists official consumer opt-out pages only. It will not help
research, scrape, or harass a third party.

---

## What gets flagged

Local detectors (no model):

- **Emails** — `user@domain.tld`
- **Phones** — NANP / simple international; not SSN-shaped
- **SSN-like** — `###-##-####`
- **Seed-phrase-ish** — BIP39 English runs (12–24; shorter if labeled recovery/mnemonic)
- **API-key-ish** — OpenAI / Anthropic / GitHub / AWS `AKIA` / Slack / Stripe / Google / JWT, plus `api_key=` / `secret=` / `0x` + 64-hex private-key assignments

False positives happen. Placeholders are cheaper than leaking a seed.

---

## Tests / CI

```bash
pytest -q
```

GitHub Actions installs the package from PyPI as usual, then runs the same
suite **offline**: fixture dumps under `tests/fixtures/dumps/` compared to
frozen goldens in `tests/fixtures/expected/`. Sockets are blocked in
`conftest.py` for the pytest step only (no dead `HTTP_PROXY` on checkout /
`pip install`). Tests assert that raw fixture secrets never appear in scrub
or detect output.

Regenerate goldens after an intentional detector change:

```bash
python scripts/update_goldens.py
```

---

## Layout

```text
src/scrubmcp/          engine, CLI, MCP server, BIP39 list, skills
skills/                same Hermes skills at repo root
tests/fixtures/dumps/  checked-in dumps (synthetic / reserved examples only)
.github/workflows/ci.yml
```

© 2026 Kevin Lance Murray (HEADWOPZ). MIT.
