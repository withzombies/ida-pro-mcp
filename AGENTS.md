# AGENTS

Use the shared `idap` skill for any headless IDA Pro workflow through the local `idap` CLI.

Primary entrypoint:
- [skills/idap/SKILL.md](skills/idap/SKILL.md)

Load the references only as needed:
- [skills/idap/references/cli.md](skills/idap/references/cli.md)
- [skills/idap/references/context-and-sessions.md](skills/idap/references/context-and-sessions.md)
- [skills/idap/references/workflows.md](skills/idap/references/workflows.md)
- [skills/idap/references/troubleshooting.md](skills/idap/references/troubleshooting.md)

Use the skill when the task involves:
- bootstrapping an `idap` context for an agent or subagent
- opening or switching IDA databases
- decompiling, disassembling, or querying functions
- xrefs, imports, globals, strings, comments, renames, or saves
- multi-agent isolation through `idap context ensure`
