# `idap` Operator Guide

## Overview

`idap` is a daemon-backed CLI for `idalib` workflows.

It is designed for:
- humans using a persistent local IDA session from the shell
- agents and subagents sharing one daemon without stomping on each other's selected session

Core model:
- one daemon process
- many tracked sessions
- one actively loaded database at a time
- one default session binding per context

CLI discovery:
- `idap --help` provides a command reference with examples and shaping guidance
- nested `--help` screens describe each subcommand
- mistyped commands and long flags return ranked suggestions

## Quickstart

```sh
uv run idap daemon start
eval "$(uv run idap context ensure --shell)"
uv run idap sessions open tests/crackme03.elf --alias crackme
uv run idap funcs show main
uv run idap funcs decompile main --summary
```

## Context Lifecycle

### Agent bootstrap

```sh
eval "$(uv run idap context ensure --shell)"
```

### Subagent bootstrap

```sh
eval "$(uv run idap context ensure --shell --force-new)"
```

### Inspect contexts

```sh
uv run idap context current
uv run idap context list
```

### Release current context

```sh
uv run idap context release
```

For manual shell usage, `idap` caches the current local context in the state directory so later commands reuse the same binding.

## Session Lifecycle

Open a binary and bind it to the current context:

```sh
uv run idap sessions open tests/crackme03.elf --alias crackme
```

Open a second session:

```sh
uv run idap sessions open /bin/ls --alias ls --database-path /tmp/ls.i64 --no-analysis
```

Inspect and switch:

```sh
uv run idap sessions list
uv run idap sessions info crackme
uv run idap sessions use crackme
uv run idap sessions current
```

Save explicitly:

```sh
uv run idap sessions save /tmp/crackme_saved.i64 --session-ref crackme
```

## Workflow Commands

### Function inspection

```sh
uv run idap funcs show main
uv run idap funcs disasm main --summary
uv run idap funcs decompile main --summary
uv run idap funcs callers check_pw
uv run idap funcs callees main
uv run idap funcs strings main
uv run idap funcs constants main
```

### Metadata and lookups

```sh
uv run idap idb metadata
uv run idap imports list --limit 20
uv run idap globals list --query 'name:*flag*'
uv run idap strings list --query 'text:*password*'
uv run idap xrefs to 0x123e
```

### Modification flows

```sh
uv run idap rename 0x123e crackme_main
uv run idap comment set 0x123e stage2-comment
uv run idap comment append 0x123e finding-note
uv run idap types enums upsert --name WCAppMsgInnerType --member WC_APPMSG_INNER_BRAND_MP_VIDEO=54
uv run idap py eval 'import idc; print(idc.get_cmt(0x123e, 0))'
```

## Output Formats

### JSON

```sh
uv run idap --json sessions list
```

### JSONL

```sh
uv run idap funcs list --limit 10 --format jsonl
uv run idap --format jsonl strings list --limit 10
```

### Text

Text mode renders:
- body text for decompile/disasm/py eval outputs
- compact tables for collection results
- `key: value` mappings for simple status-like responses

## Diagnostics

Daemon status:

```sh
uv run idap --json daemon status
```

Daemon logs:

```sh
uv run idap daemon logs
uv run idap --json daemon logs --tail 50
```

Health:

```sh
uv run idap sessions health
uv run idap sessions warmup
```

## Integrations

### Shared skill

One canonical skill lives in `skills/idap/`.

Inspect it and verify the bridge:

```sh
idap integrations skill doctor
idap integrations skill show --agent all --format json
```

### Claude

```sh
uv run idap integrations claude install
uv run idap integrations claude install-skill
```

### Codex

Best-effort installer:

```sh
uv run idap integrations codex install
uv run idap integrations codex install-skill
```

If no install target is detected, use:

```sh
uv run idap integrations codex --format json
```

### OpenCode

```sh
uv run idap integrations opencode install
uv run idap integrations opencode --format json
```

### Pi

```sh
uv run idap integrations pi install
uv run idap integrations pi --format json
```

## Troubleshooting

- If `funcs show main` fails, do not use `--no-analysis` for that session.
- If the daemon state is stale after code changes, `idap` will restart mismatched daemons automatically.
- If a binary lives in a read-only directory, use `--database-path` or let `idap` stage it into state storage.
- If a command says no session is bound, inspect the active binding with `idap context current` and `idap sessions list`.

## Validation

Fast suite:

```sh
uv run --with pytest pytest -q \
  tests/test_cli_main.py \
  tests/test_cli_helpers.py \
  tests/test_daemon.py \
  tests/test_client.py \
  tests/test_querying.py \
  tests/test_idalib_session_manager.py \
  tests/test_integrations.py \
  tests/test_state.py
```

Live CLI suite:

```sh
uv run --with pytest pytest -q tests/test_cli_live_e2e.py
```

Marker-based selection:

```sh
uv run --with pytest pytest -q tests -m fast
uv run --with pytest pytest -q tests -m live_idap
```
