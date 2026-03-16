---
name: idap
description: Headless IDA Pro workflows through the idap CLI. Use when opening binaries, binding or switching sessions, decompiling, disassembling, querying functions/xrefs/search/types/memory, renaming, commenting, patching, saving, or managing per-agent idap contexts in multi-agent analysis.
---

# idap

Use `idap` for headless IDA work. Prefer first-class `idap` commands over `idap raw call ...`, and prefer both over `idap py eval ...`.

## Quick start

Parent agent:

```sh
idap daemon status || idap daemon start
eval "$(idap context ensure --shell)"
```

Run the parent bootstrap once per shell. In fresh-shell Codex executions, `idap` will reuse the cached parent context automatically.

Subagent:

```sh
eval "$(idap context ensure --shell --force-new)"
```

Open a sample and bind it to the current context:

```sh
idap sessions open path/to/binary --alias sample
idap funcs show main
idap funcs decompile main --summary
idap xrefs main --direction both
```

## Context and session rules

- Every agent gets one context.
- Every subagent gets a fresh context with `--force-new`.
- Use `idap sessions use <session>` to persistently bind the current context.
- Use `--session` only for one-shot overrides.
- Inspect state with:
  - `idap context current`
  - `idap context list`
  - `idap sessions current`
  - `idap sessions list`
  - `idap sessions info <session>`

Read [references/context-and-sessions.md](references/context-and-sessions.md) when you need the full model.

## Preferred command patterns

- Prefer `--json` for structured agent use.
- Bootstrap once per shell, not before every `idap` command.
- Once a session is bound, treat it as stable unless there is evidence it changed.
- Use shaping flags to reduce context:
  - `--limit`
  - `--offset`
  - `--query`
  - `--select`
  - `--sort`
- Use body slicing for large outputs:
  - `--summary`
  - `--contains`
  - `--around`
  - `--lines`
- Resolve a stable address once, then keep using that address instead of repeating name-based discovery.
- Prefer one deeper branch-closure loop over several shallow rediscovery passes.
- Prefer purpose-built command families before falling back:
  - `funcs`
  - `xrefs`
  - `search`
  - `types`
  - `stack`
  - `memory`
  - `convert`
  - `patch`
- Use `idap raw call ...` only if no high-level command exists.
- Use `idap py eval ...` only for truly ad hoc one-off logic or when a workflow needs direct IDAPython.

Command examples live in [references/cli.md](references/cli.md).

## Common workflows

- New sample:
  - open binary
  - inspect `main`
  - enumerate callers/callees/strings/constants/xrefs
  - use `search`, `types`, and `memory` as needed
- Multi-session work:
  - `sessions list`
  - `sessions use <alias>`
- Mutations:
  - rename
  - comment
  - patch bytes/assembly
  - `sessions save`
- Codex RE pass hygiene:
  - bootstrap once
  - find anchor
  - resolve a stable address
  - inspect callers/callees/xrefs once
  - decompile `--summary` first, then full only if needed
  - record the result before moving to the next branch
- Trace review:
  - use `idap trace codex --recent 3 --cwd <repo>` to spot repeated bootstrap, duplicate `idap` queries, and state rediscovery churn
  - use `idap trace claude --recent 3 --cwd <repo>` to review the same churn patterns in Claude session traces

Read [references/workflows.md](references/workflows.md) for the full sequence.

## Mutation rules

- Save after meaningful rename/comment work.
- Save after meaningful patching or type-application work too.
- Use `--database-path` for binaries in read-only locations.
- Avoid `--no-analysis` if you need name-based lookups or decompilation.

## Troubleshooting

- Tiny import stubs often disassemble better than they decompile.
- If `Failed to open database` occurs on system binaries, retry with `--database-path`.
- If no session is bound, inspect context and session state before retrying.
- If behavior looks stale after code changes, check daemon status/logs.

Read [references/troubleshooting.md](references/troubleshooting.md) before falling back to ad hoc guesses.
