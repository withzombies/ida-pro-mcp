# Troubleshooting

## Open failures

If opening a system binary fails, use a writable database path:

```sh
idap sessions open /bin/ls --database-path /tmp/ls.i64
```

## No bound session

Inspect both the context and the session list:

```sh
idap context current
idap sessions list
```

Bind explicitly if needed:

```sh
idap sessions use <session>
```

## Decompilation failed

Tiny import stubs or extern thunks may not decompile. Try:

```sh
idap funcs disasm <name-or-addr> --summary
```

## Name lookup fails

Do not use `--no-analysis` if you need `funcs show main`, decompilation, or other name-based workflows.

## Prefer direct commands over Python

Prefer first-class commands before reaching for Python:

```sh
idap funcs list --calls recv
idap search regex 'password|token'
idap types list --kind struct
idap memory table 0x404000 --width 8 --count 16
```

Use `idap py eval ...` only if there is still no direct command for the task.

## Prefer high-level commands over raw calls

Use `idap raw list` and `idap raw schema <tool>` to inspect the low-level bridge, but prefer the high-level commands when they exist.

## Stale daemon behavior

Check:

```sh
idap daemon status
idap daemon logs --tail 50
```

The CLI fingerprints the daemon and should restart stale code automatically.

## Too much Codex trace churn

If a long pass feels slower than expected, review the recent traces:

```sh
idap trace codex --recent 3 --cwd /path/to/repo
idap trace claude --recent 3 --cwd /path/to/repo
```

Common fixes:

- Bootstrap once per shell instead of repeating `context ensure`.
- After `funcs show`, keep using the resolved address for callers/callees/xrefs/decompile.
- Use `funcs decompile --summary` before requesting the full body.
- Avoid repeated `sessions list` or `context current` unless state actually changed.
