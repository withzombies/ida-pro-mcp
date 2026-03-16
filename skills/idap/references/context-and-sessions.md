# Context and Sessions

`idap` isolates work by context.

Rules:
- one daemon process
- many tracked sessions
- one actively loaded database at a time
- one default session binding per context

Agent pattern:

```sh
eval "$(idap context ensure --shell)"
```

Run it once per parent-agent shell. In fresh-shell environments such as Codex `exec_command`, `idap` reuses the cached parent context by default instead of minting a new one each time.

Subagent pattern:

```sh
eval "$(idap context ensure --shell --force-new)"
```

Persistent binding:

```sh
idap sessions use <session>
```

One-shot override:

```sh
idap --session <session> funcs show main
```

Inspect state:

```sh
idap context current
idap context list
idap sessions current
idap sessions list
idap sessions info <session>
```

Use `sessions use` for stable work. Avoid repeating `--session` on every command unless you are intentionally crossing bindings.
