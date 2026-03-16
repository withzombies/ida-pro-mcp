"""Command line interface for idap."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
import time
from typing import Any

from .client import DaemonClientError, daemon_request, ensure_daemon_running, load_daemon_info, stop_daemon
from .codex_trace import (
    analyze_claude_traces,
    analyze_codex_traces,
    find_claude_trace_paths,
    find_codex_trace_paths,
)
from .core.querying import apply_collection_options
from .integrations import (
    claude_hooks_payload,
    generic_bootstrap_payload,
    generic_bootstrap_text,
    install_claude_hooks,
    install_claude_skill,
    install_codex_skill,
    install_generic_provider,
    install_opencode_bootstrap,
    install_pi_bootstrap,
    skill_doctor,
    skill_show,
)
from .state import current_context_path, read_json, remove_file, write_json


HELP_FORMATTER = argparse.RawTextHelpFormatter
SUGGESTION_LIMIT = 3

_INVALID_CHOICE_RE = re.compile(r"argument (?P<name>\w+): invalid choice: '(?P<bad>[^']+)'")
_UNRECOGNIZED_RE = re.compile(r"unrecognized arguments: (?P<args>.+)")


class IdapArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        suggestion = _format_parser_error(self, message)
        self.exit(2, f"{suggestion}\n")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        result = _dispatch(args)
    except DaemonClientError as exc:
        raise SystemExit(_format_client_error(str(exc))) from exc

    rendered = _render_output(result, fmt=_output_format(args))
    if rendered is not None:
        print(rendered)


def _build_parser() -> IdapArgumentParser:
    parser = IdapArgumentParser(
        prog="idap",
        description=(
            "Headless IDA Pro workflows through the local idap daemon.\n"
            "Use structured output and shaping flags for agent-friendly responses."
        ),
        epilog=(
            "Common commands:\n"
            "  idap sessions open path/to/binary --alias sample\n"
            "  idap funcs decompile main --summary --format json\n"
            "  idap funcs callers check_pw --limit 20\n"
            "  idap sessions open /bin/ls --database-path /tmp/ls.i64\n\n"
            "Agent-friendly output:\n"
            "  Prefer --json or --format jsonl for structured output.\n"
            "  Use --limit/--query/--select/--sort to reduce output size."
        ),
        formatter_class=HELP_FORMATTER,
    )
    parser.add_argument("--context", default=None, help="Explicit idap context ID for this invocation.")
    parser.add_argument("--session", default=None, help="One-shot session override without rebinding the current context.")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Alias for --format json.")
    parser.add_argument(
        "--format",
        choices=["text", "json", "jsonl"],
        default="text",
        help="Output format. Use json/jsonl for agent parsing.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    _build_context_parser(
        subparsers.add_parser(
            "context",
            help="Bootstrap, inspect, and release per-agent contexts.",
            description="Context management for multi-agent idap workflows.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_daemon_parser(
        subparsers.add_parser(
            "daemon",
            help="Start, stop, inspect, and read daemon logs.",
            description="Daemon lifecycle and diagnostics.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_trace_parser(
        subparsers.add_parser(
            "trace",
            help="Analyze Codex execution traces for repeated idap workflow patterns.",
            description="Codex trace analysis helpers for repeated bootstrap, duplicate idap commands, and workflow churn.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_sessions_parser(
        subparsers.add_parser(
            "sessions",
            help="Open, bind, inspect, save, and close IDA sessions.",
            description="Tracked IDA session management for the current context.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_jobs_parser(
        subparsers.add_parser(
            "jobs",
            help="Inspect and wait on asynchronous daemon jobs.",
            description="Daemon job management for long-running session opens.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_funcs_parser(
        subparsers.add_parser(
            "funcs",
            help="Inspect functions, decompilation, disassembly, callers, and constants.",
            description="Function-level analysis commands.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_funcs_parser(
        subparsers.add_parser(
            "functions",
            help="Alias for 'funcs'.",
            description="Function-level analysis commands.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_simple_list_parser(
        subparsers.add_parser(
            "imports",
            help="List import symbols.",
            description="Import symbol queries.",
            formatter_class=HELP_FORMATTER,
        ),
        "imports",
    )
    _build_simple_list_parser(
        subparsers.add_parser(
            "globals",
            help="List global symbols.",
            description="Global symbol queries.",
            formatter_class=HELP_FORMATTER,
        ),
        "globals",
    )
    _build_simple_list_parser(
        subparsers.add_parser(
            "strings",
            help="List extracted strings.",
            description="String queries across the current database.",
            formatter_class=HELP_FORMATTER,
        ),
        "strings",
    )
    _build_xrefs_parser(
        subparsers.add_parser(
            "xrefs",
            help="Query cross references to an address or symbol.",
            description="Cross-reference inspection commands.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_search_parser(
        subparsers.add_parser(
            "search",
            help="Search strings, bytes, and references.",
            description="Search and matching helpers.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_types_parser(
        subparsers.add_parser(
            "types",
            help="Inspect and apply types and structs.",
            description="Type declaration, application, and struct helpers.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_stack_parser(
        subparsers.add_parser(
            "stack",
            help="Inspect and edit stack frame variables.",
            description="Stack-frame inspection and mutation helpers.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_memory_parser(
        subparsers.add_parser(
            "memory",
            help="Read bytes, integers, strings, globals, and tables.",
            description="Memory inspection helpers.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_patch_parser(
        subparsers.add_parser(
            "patch",
            help="Patch bytes or assembly at addresses.",
            description="Mutation helpers for bytes and assembly patching.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_convert_parser(
        subparsers.add_parser(
            "convert",
            help="Convert integers to alternate representations.",
            description="Numeric conversion helpers.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_idb_parser(
        subparsers.add_parser(
            "idb",
            help="Inspect database-level metadata.",
            description="Database metadata commands.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_integrations_parser(
        subparsers.add_parser(
            "integrations",
            help="Install hooks, shared skills, and integration helpers.",
            description="Agent integration helpers for Claude, Codex, and related tooling.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_comment_parser(
        subparsers.add_parser(
            "comment",
            help="Set comments in the current database.",
            description="Comment mutation commands.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_rename_parser(
        subparsers.add_parser(
            "rename",
            help="Rename a symbol or function.",
            description="Rename a symbol in the current database.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_py_parser(
        subparsers.add_parser(
            "py",
            help="Run Python inside the current IDA session.",
            description="Execute Python in the active IDA database context.",
            formatter_class=HELP_FORMATTER,
        )
    )
    _build_raw_parser(
        subparsers.add_parser(
            "raw",
            help="Call lower-level daemon operations directly.",
            description="Raw escape hatch for operations without ergonomic wrappers.",
            formatter_class=HELP_FORMATTER,
        )
    )
    return parser


def _dispatch(args: argparse.Namespace) -> Any:
    context_id = _resolve_context(args)
    if args.command == "context":
        if args.subcommand == "list":
            result = daemon_request("GET", "/v1/contexts", None)
            return apply_collection_options(
                result.get("items", []),
                limit=_collection_limit(args),
                offset=getattr(args, "offset", 0),
                page=getattr(args, "page", None),
                query_terms=[],
                select_fields=_split_csv(getattr(args, "select", None)),
                sort_spec=getattr(args, "sort", None),
            )
        if args.subcommand == "current":
            if not context_id:
                context_id = _ensure_default_context()
            try:
                return daemon_request("GET", f"/v1/contexts/{context_id}", None)
            except DaemonClientError:
                return {"context": {"context_id": context_id}, "session": None}
        if args.subcommand == "release":
            if not context_id:
                return {"released": False, "context_id": ""}
            result = daemon_request("POST", "/v1/contexts/release", {"context_id": context_id})
            if result.get("released") and _cached_context_id() == context_id:
                remove_file(current_context_path())
            return result
        payload = {
            "current_context_id": os.environ.get("IDAP_CONTEXT") or _cached_context_id(),
            "force_new": getattr(args, "force_new", False),
        }
        result = daemon_request("POST", "/v1/contexts/ensure", payload)
        if not getattr(args, "force_new", False):
            _store_cached_context_id(str(result["context_id"]))
        if args.shell:
            return f"export IDAP_CONTEXT={result['context_id']}"
        return result if _output_format(args) == "json" else result["context_id"]
    if args.command == "daemon":
        if args.subcommand == "start":
            return ensure_daemon_running()
        if args.subcommand == "status":
            try:
                return daemon_request("GET", "/v1/daemon", None, autostart=False)
            except DaemonClientError:
                return load_daemon_info() or {"running": False}
        if args.subcommand == "logs":
            info = load_daemon_info() or {}
            log_path = info.get("log_path", "")
            if getattr(args, "tail", None):
                return {
                    "log_path": log_path,
                    "lines": _tail_file(log_path, args.tail),
                }
            return {"log_path": log_path}
        if args.subcommand == "stop":
            return stop_daemon(stop_all=args.all)
    if args.command == "trace":
        return _trace_dispatch(args)
    if args.command == "jobs":
        return _jobs_dispatch(args)
    if not context_id:
        context_id = _ensure_default_context()
    if args.command == "sessions":
        return _sessions_dispatch(args, context_id)
    if args.command in {"funcs", "functions"}:
        return _funcs_dispatch(args, context_id)
    if args.command == "idb":
        return _invoke("idb.metadata", context_id, args, {})
    if args.command == "integrations":
        return _integrations_dispatch(args)
    if args.command in {"imports", "globals", "strings"}:
        return _list_dispatch(args, context_id, f"{args.command}.list")
    if args.command == "xrefs":
        return _xrefs_dispatch(args, context_id)
    if args.command == "search":
        return _search_dispatch(args, context_id)
    if args.command == "types":
        return _types_dispatch(args, context_id)
    if args.command == "stack":
        return _stack_dispatch(args, context_id)
    if args.command == "memory":
        return _memory_dispatch(args, context_id)
    if args.command == "convert":
        return _convert_dispatch(args, context_id)
    if args.command == "patch":
        return _patch_dispatch(args, context_id)
    if args.command == "comment":
        return _comment_dispatch(args, context_id)
    if args.command == "rename":
        return _rename_dispatch(args, context_id)
    if args.command == "py":
        return _invoke("py.eval", context_id, args, {"code": args.code, **_slice_args(args)})
    if args.command == "raw":
        return _raw_dispatch(args, context_id)
    raise SystemExit(f"Unsupported command: {args.command}")


def _sessions_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand == "open":
        result = daemon_request(
            "POST",
            "/v1/jobs/open-session",
            {
                "context_id": context_id,
                "input_path": args.path,
                "alias": args.alias,
                "session_id": args.session_id,
                "database_path": args.database_path,
                "run_auto_analysis": not args.no_analysis,
            },
        )
        if getattr(args, "wait", False):
            timeout = getattr(args, "timeout", None)
            return _wait_for_job(result["job_id"], timeout=timeout)
        return result
    if args.subcommand == "list":
        return daemon_request(
            "POST",
            "/v1/sessions/list",
            {
                "context_id": context_id,
                "limit": _collection_limit(args),
                "offset": args.offset,
                "page": args.page,
                "query": args.query,
                "select": _split_csv(args.select),
                "sort": args.sort,
            },
        )
    if args.subcommand == "current":
        return _invoke("sessions.current", context_id, args, {})
    if args.subcommand == "info":
        return _invoke("sessions.info", context_id, args, {"session_ref": args.session_ref})
    if args.subcommand == "use":
        session_ref = args.session_ref
        return daemon_request(
            "POST",
            f"/v1/sessions/{session_ref}/bind",
            {"context_id": context_id},
        )
    if args.subcommand == "unbind":
        return daemon_request("DELETE", f"/v1/contexts/{context_id}/binding", {})
    if args.subcommand == "close":
        return daemon_request("POST", f"/v1/sessions/{args.session_ref}/close", {})
    if args.subcommand == "save":
        session_ref = args.session_ref or args.session
        if session_ref:
            return daemon_request(
                "POST",
                f"/v1/sessions/{session_ref}/save",
                {"context_id": context_id, "path": args.path},
            )
        return _invoke("sessions.save", context_id, args, {"path": args.path})
    if args.subcommand == "health":
        return _invoke("sessions.health", context_id, args, {})
    if args.subcommand == "warmup":
        return _invoke(
            "sessions.warmup",
            context_id,
            args,
            {
                "wait_auto_analysis": args.wait_auto_analysis,
                "build_caches": args.build_caches,
                "init_hexrays": args.init_hexrays,
            },
        )
    raise SystemExit(f"Unsupported sessions command: {args.subcommand}")


def _jobs_dispatch(args: argparse.Namespace) -> Any:
    if args.subcommand == "list":
        result = daemon_request("GET", "/v1/jobs", None)
        return apply_collection_options(
            result.get("items", []),
            limit=_collection_limit(args),
            offset=getattr(args, "offset", 0),
            page=getattr(args, "page", None),
            query_terms=[],
            select_fields=_split_csv(getattr(args, "select", None)),
            sort_spec=getattr(args, "sort", None),
        )
    if args.subcommand == "show":
        return daemon_request("GET", f"/v1/jobs/{args.job_id}", None)
    if args.subcommand == "wait":
        return _wait_for_job(args.job_id, timeout=getattr(args, "timeout", None))
    raise SystemExit(f"Unsupported jobs command: {args.subcommand}")


def _trace_dispatch(args: argparse.Namespace) -> Any:
    if args.subcommand == "codex":
        paths = list(args.paths or [])
        if not paths:
            paths = find_codex_trace_paths(root=args.root, recent=args.recent, cwd=args.cwd)
        if not paths:
            raise SystemExit("No Codex trace sessions matched the requested filters")
        return analyze_codex_traces(paths, duplicate_limit=args.duplicates)
    if args.subcommand == "claude":
        paths = list(args.paths or [])
        if not paths:
            paths = find_claude_trace_paths(root=args.root, recent=args.recent, cwd=args.cwd)
        if not paths:
            raise SystemExit("No Claude trace sessions matched the requested filters")
        return analyze_claude_traces(paths, duplicate_limit=args.duplicates)
    raise SystemExit(f"Unsupported trace command: {args.subcommand}")


def _funcs_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand == "list":
        payload = {
            "limit": _collection_limit(args),
            "offset": args.offset,
            "page": args.page,
            "query": args.query,
            "select": _split_csv(args.select),
            "sort": args.sort,
            "name_regex": args.name_regex,
            "min_size": args.min_size,
            "max_size": args.max_size,
            "has_type": args.has_type,
        }
        if getattr(args, "calls", None):
            payload["calls"] = args.calls
            payload["call_match"] = getattr(args, "call_match", "any")
        return _invoke(
            "funcs.list",
            context_id,
            args,
            payload,
        )
    if args.subcommand == "show":
        return _invoke("funcs.show", context_id, args, {"query": args.query})
    if args.subcommand in {"callers", "callees", "strings", "constants"}:
        return _invoke(
            f"funcs.{args.subcommand}",
            context_id,
            args,
            {
                "query": args.query,
                "limit": _collection_limit(args),
                "offset": args.offset,
                "page": args.page,
                "query_terms": args.query_filter,
                "select": _split_csv(args.select),
                "sort": args.sort,
            },
        )
    if args.subcommand == "basic-blocks":
        return _invoke(
            "funcs.basic_blocks",
            context_id,
            args,
            {
                "query": args.query,
                "limit": _collection_limit(args),
                "offset": args.offset,
                "page": args.page,
                "query_terms": args.query_filter,
                "select": _split_csv(args.select),
                "sort": args.sort,
            },
        )
    if args.subcommand == "decompile":
        return _invoke(
            "funcs.decompile",
            context_id,
            args,
            {"query": args.query, **_slice_args(args), "limit": args.limit, "offset": args.offset},
        )
    if args.subcommand in {"disasm", "disassemble"}:
        return _invoke(
            "funcs.disasm",
            context_id,
            args,
            {"query": args.query, **_slice_args(args), "limit": args.limit, "offset": args.offset},
        )
    if args.subcommand == "export":
        return _invoke(
            "funcs.export",
            context_id,
            args,
            {
                "addrs": args.queries,
                "format": args.export_format,
                "limit": _collection_limit(args),
                "offset": args.offset,
                "page": args.page,
                "query_terms": args.query,
                "select": _split_csv(args.select),
                "sort": args.sort,
            },
        )
    if args.subcommand == "callgraph":
        return _invoke(
            "funcs.callgraph",
            context_id,
            args,
            {
                "roots": args.queries,
                "max_depth": args.max_depth,
                "max_nodes": args.max_nodes,
                "max_edges": args.max_edges,
                "direction": args.direction,
            },
        )
    if args.subcommand == "stats":
        return _invoke("funcs.stats", context_id, args, {})
    raise SystemExit(f"Unsupported funcs command: {args.subcommand}")


def _list_dispatch(args: argparse.Namespace, context_id: str, command: str) -> Any:
    return _invoke(
        command,
        context_id,
        args,
        {
            "limit": _collection_limit(args),
            "offset": args.offset,
            "page": args.page,
            "query": args.query,
            "select": _split_csv(args.select),
            "sort": args.sort,
            "regex": getattr(args, "regex", None),
            "module": getattr(args, "module", None),
            "segment": getattr(args, "segment", None),
            "min_addr": getattr(args, "min_addr", None),
            "max_addr": getattr(args, "max_addr", None),
        },
    )


def _xrefs_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.query == "field":
        if not args.query_alias or not args.query_extra:
            raise SystemExit(
                "usage: idap xrefs [-h] [--json] [--format {text,json,jsonl}] "
                "[--direction {to,from,both}] [--type {any,code,data}] [--limit LIMIT] "
                "[--offset OFFSET] [--page PAGE] [--query-filter QUERY_FILTER] [--select SELECT] "
                "[--sort SORT] [query]\n"
                "idap xrefs: error: xrefs field requires <struct> and <field>\n"
                "Run 'idap xrefs --help' to see valid commands and options."
            )
        return _invoke(
            "xrefs.field",
            context_id,
            args,
            {
                "struct": args.query_alias,
                "field": args.query_extra,
                "limit": _collection_limit(args),
                "offset": args.offset,
                "page": args.page,
                "query_terms": args.query_filter,
                "select": _split_csv(args.select),
                "sort": args.sort,
            },
        )

    direction = "both"
    query = args.query

    if args.alias_direction:
        direction = args.alias_direction
        query = args.query_alias
    elif args.query in {"to", "from", "both"}:
        direction = args.query
        query = args.query_alias

    if not query:
        raise SystemExit(
            "usage: idap xrefs [-h] [--direction {to,from,both}] [--type {any,code,data}] "
            "[--limit LIMIT] [--offset OFFSET] [--page PAGE] [--query-filter QUERY_FILTER] "
            "[--select SELECT] [--sort SORT] [query] [compat_query]\n"
            "idap xrefs: error: query is required\n"
            "Run 'idap xrefs --help' to see valid commands and options."
        )

    if args.direction:
        direction = args.direction

    return _invoke(
        "xrefs.query",
        context_id,
        args,
        {
            "query": query,
            "direction": direction,
            "xref_type": args.xref_type,
            "count": _collection_limit(args),
            "offset": args.offset,
            "page": args.page,
            "query_terms": args.query_filter,
            "select": _split_csv(args.select),
            "sort": args.sort,
        },
    )


def _search_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    limit, offset = _search_pagination(_collection_limit(args), args.offset, args.page)
    if args.subcommand == "regex":
        return _invoke(
            "search.regex",
            context_id,
            args,
            {"pattern": args.pattern, "limit": limit, "offset": offset},
        )
    if args.subcommand == "bytes":
        return _invoke(
            "search.bytes",
            context_id,
            args,
            {"pattern": args.pattern, "limit": limit, "offset": offset},
        )
    if args.subcommand == "refs":
        return _invoke(
            "search.refs",
            context_id,
            args,
            {
                "ref_type": args.ref_type,
                "target": args.target,
                "limit": limit,
                "offset": offset,
            },
        )
    raise SystemExit(f"Unsupported search command: {args.subcommand}")


def _types_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand == "list":
        return _invoke(
            "types.list",
            context_id,
            args,
            {
                "filter": args.filter,
                "kind": args.kind,
                "limit": _collection_limit(args),
                "offset": args.offset,
                "page": args.page,
                "query_terms": args.query,
                "select": _split_csv(args.select),
                "sort": args.sort,
                "include_decl": not args.no_include_decl,
                "include_members": args.include_members,
                "max_members": args.max_members,
                "include_relationships": args.include_relationships,
                "count": _collection_limit(args),
            },
        )
    if args.subcommand == "declare":
        payload = _load_json_file(args.from_json) if args.from_json else args.decl
        if not payload:
            raise SystemExit("idap types declare: error: use --decl or --from-json")
        return _invoke("types.declare", context_id, args, {"decls": payload})
    if args.subcommand == "set":
        if args.from_json:
            payload = _load_json_file(args.from_json)
        else:
            if not args.target or not args.decl:
                raise SystemExit("idap types set: error: target and decl are required unless --from-json is used")
            payload = {"kind": "auto", "addr": args.target, "type": args.decl}
        return _invoke("types.set", context_id, args, {"edits": payload})
    if args.subcommand == "infer":
        payload = _load_json_file(args.from_json) if args.from_json else args.target
        if not payload:
            raise SystemExit("idap types infer: error: target is required unless --from-json is used")
        return _invoke("types.infer", context_id, args, {"addrs": payload, "depth": args.depth})
    if args.subcommand == "enums":
        if args.enums_subcommand != "upsert":
            raise SystemExit(f"Unsupported types enums command: {args.enums_subcommand}")
        if args.from_json:
            payload = _load_json_file(args.from_json)
        else:
            if not args.name or not args.member:
                raise SystemExit(
                    "idap types enums upsert: error: --name and at least one --member are required unless --from-json is used"
                )
            payload = {
                "name": args.name,
                "members": [_parse_enum_member_arg(item) for item in args.member],
                "bitfield": args.bitfield,
            }
        return _invoke("types.enums.upsert", context_id, args, {"queries": payload})
    if args.subcommand == "structs":
        if args.structs_subcommand == "search":
            return _invoke(
                "types.structs.search",
                context_id,
                args,
                {
                    "filter": args.filter,
                    "limit": _collection_limit(args),
                    "offset": args.offset,
                    "page": args.page,
                    "query_terms": args.query,
                    "select": _split_csv(args.select),
                    "sort": args.sort,
                },
            )
        if args.structs_subcommand == "read":
            return _invoke("types.structs.read", context_id, args, {"addr": args.addr, "struct": args.struct})
    raise SystemExit(f"Unsupported types command: {args.subcommand}")


def _stack_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand == "frame":
        return _invoke(
            "stack.frame",
            context_id,
            args,
            {
                "addrs": args.query,
                "limit": _collection_limit(args),
                "offset": args.offset,
                "page": args.page,
                "query_terms": args.query,
                "select": _split_csv(args.select),
                "sort": args.sort,
            },
        )
    if args.subcommand == "declare":
        return _invoke("stack.declare", context_id, args, {"items": _load_json_file(args.from_json)})
    if args.subcommand == "delete":
        return _invoke("stack.delete", context_id, args, {"items": _load_json_file(args.from_json)})
    raise SystemExit(f"Unsupported stack command: {args.subcommand}")


def _memory_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand == "bytes":
        return _invoke("memory.bytes", context_id, args, {"addr": args.addr, "size": args.size})
    if args.subcommand == "int":
        signed = "i" if args.signed else "u"
        ty = f"{signed}{args.width * 8}{args.endian}"
        return _invoke("memory.int", context_id, args, {"addr": args.addr, "ty": ty})
    if args.subcommand == "string":
        return _invoke("memory.string", context_id, args, {"addr": args.addr, "max_len": args.max_len})
    if args.subcommand == "global":
        return _invoke("memory.global", context_id, args, {"query": args.query})
    if args.subcommand == "table":
        return _invoke(
            "memory.table",
            context_id,
            args,
            {
                "addr": args.addr,
                "width": args.width,
                "count": args.count,
                "resolve_names": args.resolve_names,
                "nonzero_only": args.nonzero_only,
                "limit": _collection_limit(args),
                "offset": args.offset,
                "page": args.page,
                "query_terms": args.query,
                "select": _split_csv(args.select),
                "sort": args.sort,
            },
        )
    raise SystemExit(f"Unsupported memory command: {args.subcommand}")


def _convert_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand == "int":
        return _invoke("convert.int", context_id, args, {"value": args.value, "size": args.size, "input_format": args.input_format})
    raise SystemExit(f"Unsupported convert command: {args.subcommand}")


def _patch_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand == "bytes":
        payload = _load_json_file(args.from_json) if args.from_json else {"addr": args.addr, "data": args.data}
        return _invoke("patch.bytes", context_id, args, {"patches": payload})
    if args.subcommand == "asm":
        payload = _load_json_file(args.from_json) if args.from_json else {"addr": args.addr, "asm": args.asm}
        return _invoke("patch.asm", context_id, args, {"items": payload})
    raise SystemExit(f"Unsupported patch command: {args.subcommand}")


def _rename_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.from_json:
        return _invoke("rename", context_id, args, _load_json_file(args.from_json))
    if not args.target or not args.new_name:
        raise SystemExit(
            "usage: idap rename [-h] [--format {text,json,jsonl}] [--from-json FROM_JSON] [target] [new_name]\n"
            "idap rename: error: target and new_name are required unless --from-json is used\n"
            "Run 'idap rename --help' to see valid commands and options."
        )
    return _invoke(
        "rename",
        context_id,
        args,
        {"target": args.target, "new_name": args.new_name},
    )


def _comment_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand not in {"set", "append"}:
        raise SystemExit(f"Unsupported comment command: {args.subcommand}")
    command = f"comment.{args.subcommand}"
    if args.from_json:
        return _invoke(command, context_id, args, _load_json_file(args.from_json))
    if not args.target or args.comment is None:
        raise SystemExit(
            f"usage: idap comment {args.subcommand} [-h] [--format {{text,json,jsonl}}] [--from-json FROM_JSON] [target] [comment]\n"
            f"idap comment {args.subcommand}: error: target and comment are required unless --from-json is used\n"
            f"Run 'idap comment {args.subcommand} --help' to see valid commands and options."
        )
    payload = {"target": args.target, "comment": args.comment}
    if args.subcommand == "append":
        payload["scope"] = args.scope
        payload["dedupe"] = not args.allow_duplicate
    return _invoke(command, context_id, args, payload)


def _raw_dispatch(args: argparse.Namespace, context_id: str) -> Any:
    if args.subcommand == "list":
        return _invoke("raw.list", context_id, args, {})
    if args.subcommand == "schema":
        return _invoke("raw.schema", context_id, args, {"tool_name": args.tool_name})
    if args.subcommand == "call":
        return _invoke(
            "raw.call",
            context_id,
            args,
            {"tool_name": args.tool_name, "payload": json.loads(args.payload)},
        )
    raise SystemExit(f"Unsupported raw command: {args.subcommand}")


def _invoke(
    command: str,
    context_id: str,
    args: argparse.Namespace,
    payload: dict[str, Any],
) -> dict[str, Any]:
    return daemon_request(
        "POST",
        "/v1/invoke",
        {
            "context_id": context_id,
            "session_id": args.session,
            "command": command,
            "args": payload,
        },
    )


def _integrations_dispatch(args: argparse.Namespace) -> Any:
    subcommand = getattr(args, "subcommand", None)
    if args.provider == "skill":
        if subcommand == "doctor":
            return skill_doctor()
        return skill_show(getattr(args, "agent", "all"))
    if args.provider == "claude":
        if subcommand == "install":
            return install_claude_hooks()
        if subcommand == "install-skill":
            return install_claude_skill()
        snippet = claude_hooks_payload()
        if args.format == "json":
            return snippet
        return json.dumps(snippet, indent=2)
    if args.provider == "codex":
        if subcommand in {"install", "install-skill"}:
            return install_codex_skill()
        if args.format == "json":
            return generic_bootstrap_payload()
        return generic_bootstrap_text()
    if args.provider == "opencode":
        if subcommand == "install":
            return install_opencode_bootstrap()
        if args.format == "json":
            return generic_bootstrap_payload()
        return generic_bootstrap_text()
    if args.provider == "pi":
        if subcommand == "install":
            return install_pi_bootstrap()
        if args.format == "json":
            return generic_bootstrap_payload()
        return generic_bootstrap_text()
    if args.provider == "generic":
        if subcommand == "install":
            return install_generic_provider("generic")
        if args.format == "json":
            return generic_bootstrap_payload()
        return generic_bootstrap_text()
    raise SystemExit(f"Unsupported integration provider: {args.provider}")


def _resolve_context(args: argparse.Namespace) -> str:
    return (
        getattr(args, "context", None)
        or os.environ.get("IDAP_CONTEXT")
        or _cached_context_id()
        or ""
    )


def _ensure_default_context() -> str:
    cached_context_id = _cached_context_id()
    result = daemon_request(
        "POST",
        "/v1/contexts/ensure",
        {
            "current_context_id": os.environ.get("IDAP_CONTEXT") or cached_context_id,
            "metadata": {"launcher": "idap-cli"},
        },
    )
    context_id = str(result["context_id"])
    _store_cached_context_id(context_id)
    return context_id


def _build_context_parser(parser: argparse.ArgumentParser) -> None:
    parser.epilog = "Use 'idap context ensure --shell' once per agent and '--force-new' once per subagent."
    sub = parser.add_subparsers(dest="subcommand", required=True)
    list_cmd = sub.add_parser(
        "list",
        help="List known contexts and their current session bindings.",
        description="List all contexts known to the daemon.",
        epilog=_list_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(list_cmd)
    _add_list_flags(list_cmd)
    ensure = sub.add_parser(
        "ensure",
        help="Return the current context or mint a new one.",
        description="Create or reuse the current idap context for this agent.",
        epilog="Use --shell for eval-friendly output. Use --force-new for subagents.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(ensure)
    ensure.add_argument("--shell", action="store_true")
    ensure.add_argument("--force-new", action="store_true")
    current = sub.add_parser(
        "current",
        help="Show the current context and its bound session.",
        description="Inspect the resolved context for this shell or agent.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(current)
    release = sub.add_parser(
        "release",
        help="Release the current context and clear its binding.",
        description="Remove the current context record and its default session binding.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(release)


def _build_daemon_parser(parser: argparse.ArgumentParser) -> None:
    parser.epilog = "Use 'idap daemon status' and 'idap daemon logs --tail 50' before assuming the daemon is stale."
    sub = parser.add_subparsers(dest="subcommand", required=True)
    start = sub.add_parser("start", help="Start the local idap daemon.", formatter_class=HELP_FORMATTER)
    _add_output_flag(start)
    status = sub.add_parser(
        "status",
        help="Show daemon metadata, counts, and fingerprint details.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(status)
    logs = sub.add_parser(
        "logs",
        help="Show the daemon log path or tail recent log lines.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(logs)
    logs.add_argument("--tail", type=int)
    stop_cmd = sub.add_parser("stop", help="Stop the active daemon or all stale daemons.", formatter_class=HELP_FORMATTER)
    _add_output_flag(stop_cmd)
    stop_cmd.add_argument("--all", action="store_true")


def _build_sessions_parser(parser: argparse.ArgumentParser) -> None:
    parser.epilog = "Sessions are tracked globally, but 'sessions use' binds only the current context."
    sub = parser.add_subparsers(dest="subcommand", required=True)
    open_cmd = sub.add_parser(
        "open",
        help="Open a binary as a tracked IDA session and bind it to the current context.",
        description="Open or reuse a tracked session for a binary.",
        epilog="Use --database-path for binaries in read-only locations. Avoid --no-analysis for name-based workflows.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(open_cmd)
    open_cmd.add_argument("path")
    open_cmd.add_argument("--alias")
    open_cmd.add_argument("--session-id")
    open_cmd.add_argument("--database-path")
    open_cmd.add_argument("--no-analysis", action="store_true")
    open_cmd.add_argument("--wait", action="store_true")
    open_cmd.add_argument("--timeout", type=float)
    list_cmd = sub.add_parser(
        "list",
        help="List tracked sessions and binding state.",
        description="List all tracked sessions known to the daemon.",
        epilog=_list_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(list_cmd)
    _add_list_flags(list_cmd)
    current = sub.add_parser(
        "current",
        help="Show the session bound to the current context.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(current)
    info_cmd = sub.add_parser(
        "info",
        help="Show detailed metadata for one session.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(info_cmd)
    info_cmd.add_argument("session_ref")
    use_cmd = sub.add_parser(
        "use",
        help="Bind the current context to an existing session.",
        description="Persistently switch the current context to another tracked session.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(use_cmd)
    use_cmd.add_argument("session_ref")
    unbind = sub.add_parser("unbind", help="Clear the current context's session binding.", formatter_class=HELP_FORMATTER)
    _add_output_flag(unbind)
    close_cmd = sub.add_parser("close", help="Close a tracked session.", formatter_class=HELP_FORMATTER)
    _add_output_flag(close_cmd)
    close_cmd.add_argument("session_ref")
    save_cmd = sub.add_parser(
        "save",
        help="Save the current or referenced session to disk.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(save_cmd)
    save_cmd.add_argument("path", nargs="?")
    save_cmd.add_argument("--session-ref")
    health = sub.add_parser("health", help="Show daemon and session health for the current context.", formatter_class=HELP_FORMATTER)
    _add_output_flag(health)
    warmup = sub.add_parser("warmup", help="Warm the current session for later analysis commands.", formatter_class=HELP_FORMATTER)
    _add_output_flag(warmup)
    warmup.add_argument("--wait-auto-analysis", action=argparse.BooleanOptionalAction, default=True)
    warmup.add_argument("--build-caches", action=argparse.BooleanOptionalAction, default=True)
    warmup.add_argument("--init-hexrays", action=argparse.BooleanOptionalAction, default=True)


def _build_jobs_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    list_cmd = sub.add_parser("list", help="List daemon jobs.", formatter_class=HELP_FORMATTER)
    _add_output_flag(list_cmd)
    _add_list_flags(list_cmd, include_filters=False)
    show_cmd = sub.add_parser("show", help="Show one daemon job.", formatter_class=HELP_FORMATTER)
    _add_output_flag(show_cmd)
    show_cmd.add_argument("job_id")
    wait_cmd = sub.add_parser("wait", help="Wait for one daemon job to finish.", formatter_class=HELP_FORMATTER)
    _add_output_flag(wait_cmd)
    wait_cmd.add_argument("job_id")
    wait_cmd.add_argument("--timeout", type=float)


def _build_trace_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    codex_cmd = sub.add_parser(
        "codex",
        help="Summarize Codex session traces from ~/.codex or explicit JSONL paths.",
        description="Analyze Codex execution traces for repeated bootstrap, duplicate idap commands, and state re-discovery churn.",
        formatter_class=HELP_FORMATTER,
        epilog=(
            "Examples:\n"
            "  idap trace codex --recent 3 --cwd sample-project\n"
            "  idap trace codex ~/.codex/sessions/2026/03/09/rollout-*.jsonl --format json\n"
        ),
    )
    _add_output_flag(codex_cmd)
    codex_cmd.add_argument("paths", nargs="*", help="Explicit Codex rollout JSONL files to analyze.")
    codex_cmd.add_argument(
        "--root",
        default="~/.codex/sessions",
        help="Root directory to search when explicit trace paths are not provided.",
    )
    codex_cmd.add_argument(
        "--recent",
        type=int,
        default=1,
        help="Number of most recent matching traces to analyze when paths are not provided.",
    )
    codex_cmd.add_argument(
        "--cwd",
        help="Only include traces whose session cwd matches this value when scanning --root.",
    )
    codex_cmd.add_argument(
        "--duplicates",
        type=int,
        default=10,
        help="Maximum number of repeated commands/targets to report.",
    )
    claude_cmd = sub.add_parser(
        "claude",
        help="Summarize Claude session traces from ~/.claude/projects or explicit JSONL paths.",
        description="Analyze Claude Code session traces for repeated bash/idap commands and workflow churn.",
        formatter_class=HELP_FORMATTER,
        epilog=(
            "Examples:\n"
            "  idap trace claude --recent 3 --cwd sample-project\n"
            "  idap trace claude ~/.claude/projects/-workspace-sample-project/*.jsonl --format json\n"
        ),
    )
    _add_output_flag(claude_cmd)
    claude_cmd.add_argument("paths", nargs="*", help="Explicit Claude session JSONL files to analyze.")
    claude_cmd.add_argument(
        "--root",
        default="~/.claude/projects",
        help="Root directory to search when explicit trace paths are not provided.",
    )
    claude_cmd.add_argument(
        "--recent",
        type=int,
        default=1,
        help="Number of most recent matching traces to analyze when paths are not provided.",
    )
    claude_cmd.add_argument(
        "--cwd",
        help="Only include traces whose session cwd matches this value when scanning --root.",
    )
    claude_cmd.add_argument(
        "--duplicates",
        type=int,
        default=10,
        help="Maximum number of repeated commands/targets to report.",
    )


def _build_funcs_parser(parser: argparse.ArgumentParser) -> None:
    parser.epilog = "Prefer --summary for large bodies and --json/--format jsonl for agent parsing."
    sub = parser.add_subparsers(dest="subcommand", required=True)
    list_cmd = sub.add_parser(
        "list",
        help="List functions in the current session.",
        description="List known functions with shaping controls.",
        epilog=_list_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(list_cmd)
    _add_list_flags(list_cmd)
    list_cmd.add_argument("--name-regex")
    list_cmd.add_argument("--min-size", type=int)
    list_cmd.add_argument("--max-size", type=int)
    list_cmd.add_argument("--has-type", action=argparse.BooleanOptionalAction, default=None)
    list_cmd.add_argument("--calls", action="append")
    list_cmd.add_argument("--call-match", choices=["any", "all"], default="any")
    show_cmd = sub.add_parser(
        "show",
        help="Resolve a function by name or address.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(show_cmd)
    show_cmd.add_argument("query")
    for name, default_limit in (
        ("callers", 50),
        ("callees", 200),
        ("strings", 100),
        ("constants", 200),
    ):
        analysis_cmd = sub.add_parser(
            name,
            help=_funcs_help_text(name),
            description=_funcs_help_text(name),
            epilog=_list_help_epilog(),
            formatter_class=HELP_FORMATTER,
        )
        _add_output_flag(analysis_cmd)
        analysis_cmd.add_argument("query")
        _add_list_flags(analysis_cmd, default_limit=default_limit)
        analysis_cmd.add_argument("--query-filter", action="append")
    blocks_cmd = sub.add_parser(
        "basic-blocks",
        help="List basic blocks for a function.",
        description="List basic blocks for a function by name or address.",
        epilog=_list_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(blocks_cmd)
    blocks_cmd.add_argument("query")
    _add_list_flags(blocks_cmd, default_limit=200)
    blocks_cmd.add_argument("--query-filter", action="append")
    decomp = sub.add_parser(
        "decompile",
        help="Decompile a function by name or address.",
        epilog=_slice_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(decomp)
    decomp.add_argument("query")
    decomp.add_argument("--limit", type=int, default=5000)
    decomp.add_argument("--offset", type=int, default=0)
    _add_slice_flags(decomp)
    dis = sub.add_parser(
        "disasm",
        help="Disassemble a function by name or address.",
        epilog=_slice_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(dis)
    dis.add_argument("query")
    dis.add_argument("--limit", type=int, default=5000)
    dis.add_argument("--offset", type=int, default=0)
    _add_slice_flags(dis)

    export_cmd = sub.add_parser(
        "export",
        help="Export functions in JSON, header, or prototype form.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(export_cmd)
    _add_list_flags(export_cmd)
    export_cmd.add_argument("queries", nargs="+")
    export_cmd.add_argument("--export-format", choices=["json", "c_header", "prototypes"], default="json")

    callgraph_cmd = sub.add_parser(
        "callgraph",
        help="Build a bounded callgraph from one or more roots.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(callgraph_cmd)
    callgraph_cmd.add_argument("queries", nargs="+")
    callgraph_cmd.add_argument("--max-depth", type=int, default=5)
    callgraph_cmd.add_argument("--max-nodes", type=int, default=1000)
    callgraph_cmd.add_argument("--max-edges", type=int, default=5000)
    callgraph_cmd.add_argument("--direction", choices=["callers", "callees", "both"], default="callees")

    stats_cmd = sub.add_parser("stats", help="Summarize function naming/type coverage.", formatter_class=HELP_FORMATTER)
    _add_output_flag(stats_cmd)
    disassemble = sub.add_parser(
        "disassemble",
        help="Explicit alias for 'disasm'.",
        epilog=_slice_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(disassemble)
    disassemble.add_argument("query")
    disassemble.add_argument("--limit", type=int, default=5000)
    disassemble.add_argument("--offset", type=int, default=0)
    _add_slice_flags(disassemble)


def _build_simple_list_parser(parser: argparse.ArgumentParser, _name: str) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    list_cmd = sub.add_parser(
        "list",
        help=f"List {_name} entries.",
        description=f"List {_name} for the current session.",
        epilog=_list_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(list_cmd)
    _add_list_flags(list_cmd)
    if _name == "imports":
        list_cmd.add_argument("--module")
        list_cmd.add_argument("--regex")
    if _name in {"globals", "strings"}:
        list_cmd.add_argument("--regex")
        list_cmd.add_argument("--segment")
        list_cmd.add_argument("--min-addr")
        list_cmd.add_argument("--max-addr")


def _build_comment_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    for name, help_text in (
        ("set", "Set a comment at an address or symbol."),
        ("append", "Append a comment at an address or symbol."),
    ):
        cmd = sub.add_parser(name, help=help_text, formatter_class=HELP_FORMATTER)
        _add_output_flag(cmd)
        cmd.add_argument("--from-json")
        if name == "append":
            cmd.add_argument("--scope", choices=["auto", "func", "line"], default="auto")
            cmd.add_argument("--allow-duplicate", action="store_true")
        cmd.add_argument("target", nargs="?")
        cmd.add_argument("comment", nargs="?")


def _build_rename_parser(parser: argparse.ArgumentParser) -> None:
    parser.epilog = "Example: idap rename 0x123e crackme_main"
    _add_output_flag(parser)
    parser.add_argument("--from-json")
    parser.add_argument("target", nargs="?")
    parser.add_argument("new_name", nargs="?")


def _build_idb_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    metadata = sub.add_parser(
        "metadata",
        help="Show database metadata for the active session.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(metadata)


def _build_integrations_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="provider", required=True)
    claude = sub.add_parser("claude", help="Claude hooks and shared skill helpers.", formatter_class=HELP_FORMATTER)
    claude_sub = claude.add_subparsers(dest="subcommand")
    claude_sub.add_parser("install", help="Install Claude hook bootstrap commands.", formatter_class=HELP_FORMATTER)
    claude_sub.add_parser("install-skill", help="Install the shared idap skill into .claude/skills.", formatter_class=HELP_FORMATTER)
    claude.add_argument("--format", choices=["json", "text"], default="text")
    for name in ("generic", "codex", "opencode", "pi"):
        generic = sub.add_parser(name, help=_integration_help_text(name), formatter_class=HELP_FORMATTER)
        generic_sub = generic.add_subparsers(dest="subcommand")
        generic_sub.add_parser("install", help=f"Install the {name} bootstrap helper.", formatter_class=HELP_FORMATTER)
        if name == "codex":
            generic_sub.add_parser("install-skill", help="Install the shared idap skill into the Codex skill path.", formatter_class=HELP_FORMATTER)
        generic.add_argument("--format", choices=["json", "text"], default="text")
    skill = sub.add_parser("skill", help="Inspect the shared idap skill and bridge health.", formatter_class=HELP_FORMATTER)
    skill_sub = skill.add_subparsers(dest="subcommand", required=True)
    show = skill_sub.add_parser(
        "show",
        help="Show shared-skill install targets for Claude and Codex.",
        formatter_class=HELP_FORMATTER,
    )
    show.add_argument("--agent", choices=["claude", "codex", "all"], default="all")
    _add_output_flag(show)
    doctor = skill_sub.add_parser(
        "doctor",
        help="Check that the shared skill files and Codex bridge exist.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(doctor)


def _build_py_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    eval_cmd = sub.add_parser(
        "eval",
        help="Execute Python inside the current IDA session.",
        epilog=_slice_help_epilog(),
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(eval_cmd)
    eval_cmd.add_argument("code")
    _add_slice_flags(eval_cmd)


def _build_raw_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    list_cmd = sub.add_parser(
        "list",
        help="List low-level raw-call tools exposed by the daemon.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(list_cmd)
    schema_cmd = sub.add_parser(
        "schema",
        help="Show the payload schema for one raw-call tool.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(schema_cmd)
    schema_cmd.add_argument("tool_name")
    call_cmd = sub.add_parser(
        "call",
        help="Invoke a low-level daemon operation directly.",
        formatter_class=HELP_FORMATTER,
    )
    _add_output_flag(call_cmd)
    call_cmd.add_argument("tool_name")
    call_cmd.add_argument("payload")


def _build_xrefs_parser(parser: argparse.ArgumentParser) -> None:
    parser.usage = (
        "idap xrefs [-h] [--json] [--format {text,json,jsonl}] "
        "[--direction {to,from,both}] [--type {any,code,data}] [--limit LIMIT] "
        "[--offset OFFSET] [--page PAGE] [--query-filter QUERY_FILTER] [--select SELECT] "
        "[--sort SORT] [query]"
    )
    parser.epilog = (
        "Primary form: idap xrefs <query> --direction both|to|from --type any|code|data\n"
        "Compatibility aliases: idap xrefs to <query>, idap xrefs from <query>, idap xrefs both <query>\n"
        "Field xrefs: idap xrefs field <struct> <field>"
    )
    _add_output_flag(parser)
    parser.add_argument(
        "query",
        nargs="?",
        help="Address or symbol to inspect, or compatibility alias: to|from|both.",
    )
    parser.add_argument(
        "query_alias",
        nargs="?",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "query_extra",
        nargs="?",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--direction",
        choices=["to", "from", "both"],
        help="Xref direction. Defaults to both.",
    )
    parser.add_argument(
        "--type",
        choices=["any", "code", "data"],
        default="any",
        dest="xref_type",
        help="Filter xref kind. Defaults to any.",
    )
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--page", type=int)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--query-filter", action="append")
    parser.add_argument("--select")
    parser.add_argument("--sort")
    parser.set_defaults(alias_direction=None)


def _build_search_parser(parser: argparse.ArgumentParser) -> None:
    parser.epilog = "Search helpers for regex, byte patterns, and cross-reference style lookups."
    sub = parser.add_subparsers(dest="subcommand", required=True)

    regex_cmd = sub.add_parser("regex", help="Search strings by regex.", formatter_class=HELP_FORMATTER)
    _add_output_flag(regex_cmd)
    regex_cmd.add_argument("pattern")
    _add_list_flags(regex_cmd, default_limit=30, include_filters=False)

    bytes_cmd = sub.add_parser("bytes", help="Search raw byte patterns.", formatter_class=HELP_FORMATTER)
    _add_output_flag(bytes_cmd)
    bytes_cmd.add_argument("pattern")
    _add_list_flags(bytes_cmd, default_limit=1000, include_filters=False)

    refs_cmd = sub.add_parser("refs", help="Search strings/immediates/data refs/code refs.", formatter_class=HELP_FORMATTER)
    _add_output_flag(refs_cmd)
    refs_cmd.add_argument("ref_type", choices=["string", "immediate", "data_ref", "code_ref"])
    refs_cmd.add_argument("target")
    _add_list_flags(refs_cmd, default_limit=1000, include_filters=False)


def _build_types_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)

    list_cmd = sub.add_parser("list", help="List local types.", formatter_class=HELP_FORMATTER)
    _add_output_flag(list_cmd)
    _add_list_flags(list_cmd, default_limit=100)
    list_cmd.add_argument("--filter", default="")
    list_cmd.add_argument("--kind", choices=["any", "struct", "union", "enum", "typedef", "func", "ptr", "udt"], default="any")
    list_cmd.add_argument("--include-members", action="store_true")
    list_cmd.add_argument("--no-include-decl", action="store_true")
    list_cmd.add_argument("--max-members", type=int, default=64)
    list_cmd.add_argument("--include-relationships", action="store_true")
    declare_cmd = sub.add_parser("declare", help="Declare C types.", formatter_class=HELP_FORMATTER)
    _add_output_flag(declare_cmd)
    declare_cmd.add_argument("--decl")
    declare_cmd.add_argument("--from-json")

    set_cmd = sub.add_parser("set", help="Apply types to symbols, funcs, globals, or stack vars.", formatter_class=HELP_FORMATTER)
    _add_output_flag(set_cmd)
    set_cmd.add_argument("--from-json")
    set_cmd.add_argument("target", nargs="?")
    set_cmd.add_argument("decl", nargs="?")

    infer_cmd = sub.add_parser("infer", help="Infer likely types at addresses.", formatter_class=HELP_FORMATTER)
    _add_output_flag(infer_cmd)
    infer_cmd.add_argument("target", nargs="?")
    infer_cmd.add_argument("--from-json")
    infer_cmd.add_argument("--depth", type=int, default=1)

    enums_cmd = sub.add_parser("enums", help="Create or extend local enums.", formatter_class=HELP_FORMATTER)
    enums_sub = enums_cmd.add_subparsers(dest="enums_subcommand", required=True)
    enums_upsert = enums_sub.add_parser("upsert", help="Create enums and upsert members.", formatter_class=HELP_FORMATTER)
    _add_output_flag(enums_upsert)
    enums_upsert.add_argument("--from-json")
    enums_upsert.add_argument("--name")
    enums_upsert.add_argument("--member", action="append")
    enums_upsert.add_argument("--bitfield", action="store_true")

    structs_cmd = sub.add_parser("structs", help="Search and read structs.", formatter_class=HELP_FORMATTER)
    structs_sub = structs_cmd.add_subparsers(dest="structs_subcommand", required=True)
    structs_search = structs_sub.add_parser("search", help="Search struct names.", formatter_class=HELP_FORMATTER)
    _add_output_flag(structs_search)
    _add_list_flags(structs_search)
    structs_search.add_argument("filter")
    structs_read = structs_sub.add_parser("read", help="Read a struct view at an address.", formatter_class=HELP_FORMATTER)
    _add_output_flag(structs_read)
    structs_read.add_argument("addr")
    structs_read.add_argument("struct", nargs="?")


def _build_stack_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    frame_cmd = sub.add_parser("frame", help="Show stack frame variables.", formatter_class=HELP_FORMATTER)
    _add_output_flag(frame_cmd)
    _add_list_flags(frame_cmd)
    frame_cmd.add_argument("query")
    declare_cmd = sub.add_parser("declare", help="Declare stack variables from JSON.", formatter_class=HELP_FORMATTER)
    _add_output_flag(declare_cmd)
    declare_cmd.add_argument("--from-json", required=True)
    delete_cmd = sub.add_parser("delete", help="Delete stack variables from JSON.", formatter_class=HELP_FORMATTER)
    _add_output_flag(delete_cmd)
    delete_cmd.add_argument("--from-json", required=True)


def _build_memory_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    bytes_cmd = sub.add_parser("bytes", help="Read bytes at an address.", formatter_class=HELP_FORMATTER)
    _add_output_flag(bytes_cmd)
    bytes_cmd.add_argument("addr")
    bytes_cmd.add_argument("--size", type=int, default=16)

    int_cmd = sub.add_parser("int", help="Read an integer at an address.", formatter_class=HELP_FORMATTER)
    _add_output_flag(int_cmd)
    int_cmd.add_argument("addr")
    int_cmd.add_argument("--width", choices=[1, 2, 4, 8], type=int, default=4)
    int_cmd.add_argument("--signed", action="store_true")
    int_cmd.add_argument("--endian", choices=["le", "be"], default="le")

    string_cmd = sub.add_parser("string", help="Read a string literal.", formatter_class=HELP_FORMATTER)
    _add_output_flag(string_cmd)
    string_cmd.add_argument("addr")
    string_cmd.add_argument("--max-len", type=int)

    global_cmd = sub.add_parser("global", help="Read a global value by name or address.", formatter_class=HELP_FORMATTER)
    _add_output_flag(global_cmd)
    global_cmd.add_argument("query")

    table_cmd = sub.add_parser("table", help="Dump a pointer/integer table.", formatter_class=HELP_FORMATTER)
    _add_output_flag(table_cmd)
    _add_list_flags(table_cmd)
    table_cmd.add_argument("addr")
    table_cmd.add_argument("--width", choices=[4, 8], type=int, default=4)
    table_cmd.add_argument("--count", type=int, default=16)
    table_cmd.add_argument("--resolve-names", action="store_true")
    table_cmd.add_argument("--nonzero-only", action="store_true")


def _build_convert_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    int_cmd = sub.add_parser("int", help="Convert an integer between formats.", formatter_class=HELP_FORMATTER)
    _add_output_flag(int_cmd)
    int_cmd.add_argument("value")
    int_cmd.add_argument("--size", type=int)
    int_cmd.add_argument("--from", dest="input_format", choices=["auto", "hex", "dec", "bin", "ascii"], default="auto")


def _build_patch_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="subcommand", required=True)
    bytes_cmd = sub.add_parser("bytes", help="Patch raw bytes.", formatter_class=HELP_FORMATTER)
    _add_output_flag(bytes_cmd)
    bytes_cmd.add_argument("--from-json")
    bytes_cmd.add_argument("addr", nargs="?")
    bytes_cmd.add_argument("data", nargs="?")
    asm_cmd = sub.add_parser("asm", help="Patch assembly instructions.", formatter_class=HELP_FORMATTER)
    _add_output_flag(asm_cmd)
    asm_cmd.add_argument("--from-json")
    asm_cmd.add_argument("addr", nargs="?")
    asm_cmd.add_argument("asm", nargs="?")


def _add_list_flags(
    parser: argparse.ArgumentParser,
    *,
    default_limit: int = 50,
    include_filters: bool = True,
) -> None:
    parser.add_argument("--limit", type=int, default=default_limit)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--page", type=int)
    parser.add_argument("--all", action="store_true")
    if include_filters:
        parser.add_argument("--query", action="append")
        parser.add_argument("--select")
        parser.add_argument("--sort")


def _add_slice_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--contains")
    parser.add_argument("--around")
    parser.add_argument("--context-lines", type=int, default=3)
    parser.add_argument("--lines")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--full", action="store_true")


def _slice_args(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "contains": getattr(args, "contains", None),
        "around": getattr(args, "around", None),
        "context_lines": getattr(args, "context_lines", 3),
        "lines": getattr(args, "lines", None),
        "summary": getattr(args, "summary", False),
        "full": getattr(args, "full", False),
    }


def _split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_enum_member_arg(value: str) -> dict[str, Any]:
    if "=" not in value:
        raise SystemExit("idap types enums upsert: error: --member expects NAME=VALUE")
    name, raw_value = value.split("=", 1)
    member_name = name.strip()
    member_value = raw_value.strip()
    if not member_name or not member_value:
        raise SystemExit("idap types enums upsert: error: --member expects NAME=VALUE")
    try:
        parsed_value = int(member_value, 0)
    except ValueError as exc:
        raise SystemExit(f"idap types enums upsert: error: invalid enum value: {member_value}") from exc
    return {"name": member_name, "value": parsed_value}


def _load_json_file(path: str) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _search_pagination(limit: int, offset: int, page: int | None) -> tuple[int, int]:
    if page is not None and offset:
        raise SystemExit("Cannot combine --page with --offset")
    if page is not None and limit == 0:
        raise SystemExit("Cannot combine --page with --all")
    if page is None:
        return limit, offset
    if page <= 0:
        raise SystemExit("--page must be greater than zero")
    return limit, (page - 1) * limit


def _collection_limit(args: argparse.Namespace, attr: str = "limit") -> int:
    if getattr(args, "all", False):
        if getattr(args, "page", None) is not None:
            raise SystemExit("Cannot combine --page with --all")
        return 0
    return int(getattr(args, attr, 50))


def _add_output_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=["text", "json", "jsonl"],
        default=argparse.SUPPRESS,
    )


def _list_help_epilog() -> str:
    return (
        "Shaping flags:\n"
        "  --limit --offset --page --all --query --select --sort\n"
        "Defaults return the first page. Use --all or --limit 0 for full enumeration.\n"
        "Use --json or --format jsonl for agent-friendly structured output."
    )


def _slice_help_epilog() -> str:
    return (
        "Text slicing flags:\n"
        "  --summary --contains --around --lines --full\n"
        "Prefer --summary first for large results."
    )


def _funcs_help_text(name: str) -> str:
    return {
        "callers": "List callers of a function by name or address.",
        "callees": "List functions called by a function.",
        "strings": "List strings referenced by a function.",
        "constants": "List constants referenced by a function.",
    }[name]


def _integration_help_text(name: str) -> str:
    return {
        "generic": "Print generic idap bootstrap commands.",
        "codex": "Install or print Codex-specific idap integration helpers.",
        "opencode": "Install or print OpenCode-specific idap bootstrap helpers.",
        "pi": "Install or print Pi-specific idap bootstrap helpers.",
    }[name]


def _output_format(args: argparse.Namespace) -> str:
    if getattr(args, "json_output", False):
        return "json"
    return getattr(args, "format", "text")


def _format_parser_error(parser: argparse.ArgumentParser, message: str) -> str:
    invalid_choice = _INVALID_CHOICE_RE.search(message)
    if invalid_choice:
        name = invalid_choice.group("name")
        bad = invalid_choice.group("bad")
        candidates = _subcommand_candidates(parser, name)
        suggestions = _suggest_matches(bad, candidates)
        if suggestions:
            return _suggestion_message(
                parser,
                kind="command" if name == "command" else "subcommand",
                bad=bad,
                suggestions=suggestions,
            )

    unrecognized = _UNRECOGNIZED_RE.search(message)
    if unrecognized:
        target_parser = _deepest_parser_for_argv(parser, sys.argv[1:])
        bad = _first_long_option(unrecognized.group("args"))
        if bad:
            suggestions = _suggest_matches(bad, _long_option_candidates(target_parser))
            if suggestions:
                return _suggestion_message(
                    target_parser,
                    kind="option",
                    bad=bad,
                    suggestions=suggestions,
                )

    return f"{parser.format_usage().rstrip()}\n{parser.prog}: error: {message}\nRun '{parser.prog} --help' to see valid commands and options."


def _suggestion_message(
    parser: argparse.ArgumentParser,
    *,
    kind: str,
    bad: str,
    suggestions: list[str],
) -> str:
    lines = [
        parser.format_usage().rstrip(),
        f"{parser.prog}: error: unknown {kind} '{bad}'",
        "Did you mean:",
    ]
    lines.extend(f"  - {item}" for item in suggestions[:SUGGESTION_LIMIT])
    lines.append(f"Run '{parser.prog} --help' to see valid {'options' if kind == 'option' else 'subcommands' if kind == 'subcommand' else 'commands'}.")
    return "\n".join(lines)


def _subcommand_candidates(parser: argparse.ArgumentParser, dest_name: str) -> list[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction) and action.dest == dest_name:
            return list(action.choices.keys())
    return []


def _deepest_parser_for_argv(parser: argparse.ArgumentParser, argv: list[str]) -> argparse.ArgumentParser:
    current = parser
    index = 0
    while index < len(argv):
        token = argv[index]
        if token.startswith("-"):
            index += 2 if _option_takes_value(current, token) else 1
            continue
        subparser = _subparser_for_token(current, token)
        if subparser is None:
            break
        current = subparser
        index += 1
    return current


def _subparser_for_token(parser: argparse.ArgumentParser, token: str) -> argparse.ArgumentParser | None:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices.get(token)
    return None


def _option_takes_value(parser: argparse.ArgumentParser, option: str) -> bool:
    for action in parser._actions:
        if option in action.option_strings:
            return action.nargs != 0
    return False


def _long_option_candidates(parser: argparse.ArgumentParser) -> list[str]:
    candidates: list[str] = []
    for action in parser._actions:
        for option in action.option_strings:
            if option.startswith("--"):
                candidates.append(option)
    return candidates


def _first_long_option(value: str) -> str:
    for token in value.split():
        if token.startswith("--"):
            return token
    return ""


def _suggest_matches(bad: str, candidates: list[str], limit: int = SUGGESTION_LIMIT) -> list[str]:
    if not bad or not candidates:
        return []
    return difflib.get_close_matches(bad, candidates, n=limit, cutoff=0.55)


def _format_client_error(message: str) -> str:
    if "No session bound for this context." in message:
        return (
            "No idap session is active. "
            "Use 'idap sessions open <binary>' or 'idap sessions use <session>'."
        )
    return message


def _cached_context_id() -> str:
    data = read_json(current_context_path()) or {}
    context_id = data.get("context_id")
    return str(context_id) if context_id else ""


def _store_cached_context_id(context_id: str) -> None:
    write_json(current_context_path(), {"context_id": context_id})


def _wait_for_job(job_id: str, *, timeout: float | None = None, poll_interval: float = 0.5) -> dict[str, Any]:
    deadline = None if timeout is None else (time.time() + timeout)
    while True:
        result = daemon_request("GET", f"/v1/jobs/{job_id}", None)
        job = result.get("job") or {}
        status = str(job.get("status") or "")
        if status in {"succeeded", "failed", "canceled"}:
            return result
        if deadline is not None and time.time() >= deadline:
            raise DaemonClientError(f"Timed out waiting for job: {job_id}")
        time.sleep(poll_interval)


def _render_output(result: Any, *, fmt: str) -> str | None:
    if result is None:
        return None
    if fmt == "json":
        return json.dumps(result, indent=2)
    if fmt == "jsonl":
        items = _jsonl_items(result)
        return "\n".join(json.dumps(item, sort_keys=True) for item in items)
    if isinstance(result, str):
        return result
    text_result = _text_body(result)
    if text_result is not None:
        return text_result
    collection_result = _text_collection(result)
    if collection_result is not None:
        return collection_result
    mapping_result = _text_mapping(result)
    if mapping_result is not None:
        return mapping_result
    if isinstance(result, (dict, list)):
        return json.dumps(result, indent=2)
    return str(result)


def _jsonl_items(result: Any) -> list[Any]:
    if isinstance(result, dict) and isinstance(result.get("items"), list):
        return result["items"]
    if isinstance(result, list):
        return result
    raise SystemExit("--format jsonl is only supported for collection results")


def _text_body(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None
    text = result.get("text")
    if not isinstance(text, str):
        return None
    rendered = text
    if result.get("truncated"):
        suffix = "[truncated]"
        rendered = f"{rendered}\n{suffix}" if rendered else suffix
    return rendered


def _text_collection(result: Any) -> str | None:
    items = None
    if isinstance(result, dict) and isinstance(result.get("items"), list):
        items = result["items"]
    elif isinstance(result, dict) and isinstance(result.get("item"), list):
        items = result["item"]
    elif isinstance(result, list):
        items = result
    if items is None:
        return None
    if not items:
        return "No items"
    if not all(isinstance(item, dict) for item in items):
        return "\n".join(str(item) for item in items)
    columns = _text_columns(items)
    rows = [[_text_cell(item.get(column)) for column in columns] for item in items]
    widths = [len(column) for column in columns]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = [_text_table_row(columns, widths), _text_table_rule(widths)]
    for row in rows:
        lines.append(_text_table_row(row, widths))
    footer = _collection_footer(result)
    if footer:
        lines.append(footer)
    return "\n".join(lines)


def _collection_footer(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None
    if not result.get("paged"):
        return None
    count = int(result.get("count", 0) or 0)
    offset = int(result.get("offset", 0) or 0)
    remaining = result.get("remaining")
    has_more = bool(result.get("has_more"))
    if has_more and isinstance(remaining, int):
        return f"Paged: showing {count} item(s) at offset {offset}; {remaining} remaining."
    if has_more:
        return f"Paged: showing {count} item(s) at offset {offset}; more items remain."
    return f"Paged: showing final {count} item(s) at offset {offset}."


def _text_columns(items: list[dict[str, Any]]) -> list[str]:
    columns: list[str] = []
    seen: set[str] = set()
    for item in items:
        for key in item.keys():
            if key not in seen:
                seen.add(key)
                columns.append(key)
    return columns


def _text_table_row(values: list[str], widths: list[int]) -> str:
    return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values)).rstrip()


def _text_table_rule(widths: list[int]) -> str:
    return "  ".join("-" * width for width in widths)


def _text_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _text_mapping(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None
    return _text_mapping_lines(result)


def _text_mapping_lines(mapping: dict[str, Any], *, indent: str = "") -> str:
    lines: list[str] = []
    for key, value in mapping.items():
        prefix = f"{indent}{key}:"
        if isinstance(value, dict):
            if value:
                lines.append(prefix)
                lines.append(_text_mapping_lines(value, indent=f"{indent}  "))
            else:
                lines.append(f"{prefix} {{}}")
            continue
        if isinstance(value, list):
            if value:
                lines.append(prefix)
                lines.extend(_text_list_lines(value, indent=f"{indent}  "))
            else:
                lines.append(f"{prefix} []")
            continue
        cell = _text_cell(value)
        lines.append(f"{prefix} {cell}" if cell else prefix)
    return "\n".join(lines)


def _text_list_lines(values: list[Any], *, indent: str = "") -> list[str]:
    lines: list[str] = []
    for value in values:
        if isinstance(value, dict):
            if value:
                lines.append(f"{indent}-")
                lines.append(_text_mapping_lines(value, indent=f"{indent}  "))
            else:
                lines.append(f"{indent}- {{}}")
            continue
        if isinstance(value, list):
            if value:
                lines.append(f"{indent}-")
                lines.extend(_text_list_lines(value, indent=f"{indent}  "))
            else:
                lines.append(f"{indent}- []")
            continue
        cell = _text_cell(value)
        lines.append(f"{indent}- {cell}" if cell else f"{indent}-")
    return lines


def _tail_file(path: str, lines: int) -> list[str]:
    if not path or lines <= 0:
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().splitlines()[-lines:]
    except FileNotFoundError:
        return []


if __name__ == "__main__":
    main()
