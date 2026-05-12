# Casefile — Offensive Security Case Tracker for pi

Track durable security cases during bug bounties, CTFs, and security audits. Each case is a structured record that persists across sessions and automatically injects context into the LLM's system prompt.

## Install

```bash
pi install npm:pi-casefile
```

Or from source:

```bash
pi install git:github.com/x4cc3/casefile
```

For local development, symlink or copy into `~/.pi/agent/extensions/casefile/`.

## Tools

| Tool | Description |
|------|-------------|
| **CaseAdd** | Open a new case (hypothesis, evidence, confirmed vulnerability, etc.) |
| **CaseUpdate** | Update status, evidence, confidence, severity, next steps |
| **CaseGet** | Full details of a single case by ID |
| **CaseList** | Browse cases with status/severity/priority/tag filters + pagination |
| **CaseSearch** | Full-text search across cases, optionally field-scoped |
| **CaseLink** | Bidirectionally link two cases (exploit chains) |
| **CaseUnlink** | Remove a link between two cases |

## Case Fields

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Short case title (required) |
| `status` | enum | `hypothesis` → `investigating` → `confirmed` → `blocked`/`killed`/`reported` |
| `confidence` | enum | `low`, `medium`, `high` |
| `severity` | enum | `info`, `low`, `medium`, `high`, `critical` |
| `priority` | enum | `P0`–`P4` triage rating |
| `target` | string | Target asset, host, repo, or scope |
| `endpoint` | string | Route, file, or object path |
| `bug_class` | string | Bug class (SSRF, IDOR, XSS, etc.) |
| `evidence` | string | Observed evidence or reproduction steps |
| `impact` | string | Security impact or chain value |
| `next_step` | string | Next validation or exploit step |
| `poc` | string | Proof of concept steps |
| `remediation` | string | How to fix it |
| `references` | string[] | External URLs, CVEs |
| `blockers` | string[] | Current blockers |
| `tags` | string[] | Tags for filtering |
| `linked_case_ids` | string[] | Related case IDs |

## Commands

- `/casefile` — Interactive dashboard showing all cases with status summary

## Context Injection

On each turn, the extension injects a `<casefile_context>` block into the system prompt showing active cases (excluding killed/reported). Case titles and next steps are sanitized and truncated before injection, and the prompt marks them as untrusted data.

## Storage

By default, cases are stored per project at `.pi/casefile.jsonl` under the detected workspace root. This prevents old bounty cases from leaking into unrelated directories.

Environment overrides:

- `PI_CASEFILE_PATH=/absolute/or/relative/file.jsonl` — force an exact ledger path
- `PI_CASEFILE_SCOPE=project` — use project-local storage (default)
- `PI_CASEFILE_SCOPE=global` — use the shared global ledger at `~/.pi/casefile/casefile.jsonl`

Each line is a complete JSON record. Features:

- **Project-scoped storage by default** — separate ledgers across workspaces
- **Append-based adds/updates** — preserves history, deduped on read (last write wins)
- **Mutation locking** — serializes writes and reduces concurrent update loss
- **Atomic rewrite** — link/unlink/delete rewrite through temp file + rename
- **Delete with cleanup** — removes dangling linked IDs from other cases

## Offensive Security Workflow

1. **Hypothesize** — `CaseAdd` with `status: hypothesis`
2. **Investigate** — `CaseUpdate` to `status: investigating`, add `evidence`
3. **Confirm** — `CaseUpdate` to `status: confirmed`, set `severity`, write `poc`
4. **Chain** — `CaseLink` to connect primitives to escalations
5. **Report** — `CaseUpdate` to `status: reported`, add `remediation` and `references`
6. **Kill** — `CaseUpdate` to `status: killed` for dead ends