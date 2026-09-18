---
name: pre-cloud-scrub
description: Scrub emails, phones, SSN-like values, seed-phrase-ish text, and API-key-ish secrets locally with ScrubMCP before any cloud model call. Use when an agent is about to send dumps, CSVs, wallet notes, CRM exports, logs, or chat history to a remote LLM.
license: MIT
compatibility: Requires the local scrubmcp CLI or MCP server. No network. Not VoiceRail.
metadata:
  author: Kevin Lance Murray (HEADWOPZ)
  privacy: never-uploads
---

# Pre-cloud scrub

Run this skill **before** any remote / cloud model sees user data. ScrubMCP is a local pipe stage. It does not upload. It does not call a remote LLM. It is not VoiceRail.

## Hard rules

1. Never paste raw dumps, wallet notes, CRM CSVs, `.env` files, or logs into a cloud model.
2. Never log, print, or echo raw matches. Status lines may include **counts and kinds only**.
3. Never send secrets to a URL, gist, pastebin, ticket, or chat to "debug" them.
4. Prefer the local MCP tools `scrub_text`, `scrub_file`, and `detect_pii`, or the CLI pipe.

## Workflow

1. Identify the payload that would leave the machine (file, stdin, or in-memory text).
2. Scrub locally:

```bash
cat dump.json | scrubmcp scrub
scrubmcp scrub ./dump.json --json
scrubmcp detect ./dump.json
```

3. MCP (same machine, stdio only):

- `scrub_text` with the raw string
- `scrub_file` with a **local** path (URLs are rejected)
- `detect_pii` for a masked inventory (no raw secrets)

4. Forward **only** the scrubbed text (placeholders such as `[EMAIL_1]`, `[API_KEY_1]`) to the cloud model.
5. If detection reports `seed_phrase` or `api_key`, treat the original as high-risk. Do not attempt to reconstruct the secret. Tell the user it was redacted locally.

## What is redacted

| Kind | Token | Notes |
|------|--------|--------|
| email | `[EMAIL_n]` | Local-part masked in detect output |
| phone | `[PHONE_n]` | Last-4 only in detect output |
| ssn | `[SSN_n]` | SSN-like `###-##-####` |
| seed_phrase | `[SEED_PHRASE_n]` | BIP39-ish 12–24 word runs |
| api_key | `[API_KEY_n]` | OpenAI/Anthropic/GitHub/AWS/Slack/Stripe/JWT/assigned secrets |

## Privacy contract

- **Never uploads.**
- **No remote LLM** is used for detection or redaction.
- **No secret logging.** `SCRUBMCP_LOG` is off unless the operator opts in, and even then records are redacted.
- Same value → same placeholder inside one document so agents can reason without the secret.

## Do not

- Do not "just this once" send the original dump to a stronger cloud model.
- Do not write raw findings to transcripts, tickets, or memory files.
- Do not fetch remote files. If the user gives a URL, ask them to download it locally first.
