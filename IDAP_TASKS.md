# IDAP Task List

This tracks the remaining `idap` work after the initial CLI/daemon rollout.

## In Progress

- [x] Add live end-to-end coverage against a real IDA database through the CLI/daemon stack.
- [x] Expand live coverage to include multi-session switching, save flows, and mutation flows.
- [x] Improve context/session UX with more explicit inspection commands.
- [x] Extend operator docs for multi-agent usage, shaping examples, and troubleshooting.

## Pending

- [x] Add more ergonomic workflow commands so common usage does not fall back to `raw call`.
- [x] Broaden output-shaping coverage and text rendering consistency across more command shapes.
- [x] Add richer daemon diagnostics and failure-mode coverage.
- [x] Add real installer/integration automation for non-Claude clients where stable config surfaces exist.
- [x] Add packaging/release polish for the `idap` CLI and its docs.

## Completed

- [x] Shared daemon-backed `idap` CLI with context isolation.
- [x] Generic `context ensure` bootstrap flow for agents and subagents.
- [x] Output shaping with pagination, filtering, projection, sorting, slicing, and JSONL.
- [x] Real daemon fingerprinting and stale-daemon cleanup.
- [x] Real daemon log file support and context release semantics.
- [x] Live end-to-end smoke coverage for open, list, resolve, disasm, decompile, and JSONL output.
- [x] Validation scripts and pytest markers for fast and live `idap` coverage.
