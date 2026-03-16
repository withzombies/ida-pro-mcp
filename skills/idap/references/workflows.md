# Common Workflows

## Analyze a new sample

```sh
idap daemon status || idap daemon start
eval "$(idap context ensure --shell)"
idap sessions open tests/crackme03.elf --alias crackme
idap funcs show main
idap funcs decompile main --summary
idap xrefs main --direction both
idap funcs callers check_pw
```

Run the bootstrap once at shell start. Do not repeat `eval "$(idap context ensure --shell)"` before every follow-up `idap` call in the same shell.

## Multi-session switching

```sh
idap sessions open tests/crackme03.elf --alias crackme
idap sessions open /bin/ls --database-path /tmp/ls.i64 --alias ls --no-analysis
idap sessions list
idap sessions use crackme
```

## Inspect relationships around a function

```sh
idap funcs callers check_pw
idap funcs callees main
idap funcs strings main
idap funcs constants main
idap funcs basic-blocks main --limit 20
idap funcs callgraph main --direction both --max-depth 2
idap xrefs check_pw --direction to --type code
```

Efficient Codex loop:

```sh
idap funcs show check_pw
idap funcs callers 0x4011b0
idap funcs callees 0x4011b0
idap xrefs 0x4011b0 --direction both
idap funcs decompile 0x4011b0 --summary
```

Once a stable address is known, keep using that address for the rest of the branch. Prefer `--summary` first and only run the full decompile if the summary is insufficient.

## Search and type recovery

```sh
idap search regex 'password|token'
idap search refs string password
idap types list --kind struct --filter http
idap types structs search conn
idap types infer 0x123e --depth 1
idap stack frame main
```

## Memory inspection

```sh
idap memory bytes 0x401000 --size 32
idap memory int 0x401000 --width 8
idap memory string 0x402000 --max-len 64
idap memory table 0x404000 --width 8 --count 12 --resolve-names
```

## Rename, comment, patch, and save

```sh
idap rename 0x123e crackme_main
idap comment set 0x123e stage2-comment
idap comment append 0x123e finding-note
idap types enums upsert --name WCAppMsgInnerType --member WC_APPMSG_INNER_BRAND_MP_VIDEO=54
idap patch asm 0x123e 'nop'
idap sessions save /tmp/crackme_saved.i64 --session-ref crackme
```

## Review Codex trace churn

```sh
idap trace codex --recent 3 --cwd /path/to/repo
idap trace claude --recent 3 --cwd /path/to/repo
```

Use this after a long RE pass to spot repeated bootstrap, duplicate `idap` invocations, repeated decompile targets, and session/context rediscovery churn.
