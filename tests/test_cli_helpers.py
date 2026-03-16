from types import SimpleNamespace

import pytest

from ida_pro_mcp import cli


pytestmark = pytest.mark.fast


def test_context_current_ensures_default_context(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "")
    monkeypatch.setattr(cli, "_ensure_default_context", lambda: "ctx_test")
    monkeypatch.setattr(
        cli,
        "daemon_request",
        lambda method, path, payload: {
            "method": method,
            "path": path,
            "context_id": path.rsplit("/", 1)[-1],
        },
    )

    result = cli._dispatch(
        SimpleNamespace(command="context", subcommand="current", json_output=True)
    )

    assert result["context_id"] == "ctx_test"
    assert result["method"] == "GET"
    assert result["path"] == "/v1/contexts/ctx_test"


def test_context_release_without_context_is_safe(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "")
    result = cli._dispatch(
        SimpleNamespace(command="context", subcommand="release", json_output=True)
    )

    assert result == {"released": False, "context_id": ""}


def test_context_list_dispatches_to_contexts_endpoint(monkeypatch):
    monkeypatch.setattr(
        cli,
        "daemon_request",
        lambda method, path, payload: {
            "items": [{"context_id": "ctx_test"}],
        },
    )

    result = cli._dispatch(
        SimpleNamespace(
            command="context",
            subcommand="list",
            limit=50,
            offset=0,
            page=None,
            select=None,
            sort=None,
            all=False,
            json_output=True,
        )
    )

    assert result["count"] == 1
    assert result["items"][0]["context_id"] == "ctx_test"


def test_daemon_logs_returns_state_log_path(monkeypatch):
    monkeypatch.setattr(
        cli,
        "load_daemon_info",
        lambda: {"log_path": "/tmp/idap-daemon.log"},
    )

    result = cli._dispatch(
        SimpleNamespace(command="daemon", subcommand="logs", json_output=True)
    )

    assert result == {"log_path": "/tmp/idap-daemon.log"}


def test_daemon_logs_tail_reads_lines(monkeypatch, tmp_path):
    log_path = tmp_path / "daemon.log"
    log_path.write_text("one\ntwo\nthree\n", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "load_daemon_info",
        lambda: {"log_path": str(log_path)},
    )

    result = cli._dispatch(
        SimpleNamespace(command="daemon", subcommand="logs", tail=2, json_output=True)
    )

    assert result == {"log_path": str(log_path), "lines": ["two", "three"]}


def test_trace_dispatch_uses_explicit_paths(monkeypatch):
    monkeypatch.setattr(
        cli,
        "analyze_codex_traces",
        lambda paths, duplicate_limit: {"paths": paths, "duplicate_limit": duplicate_limit},
    )

    result = cli._dispatch(
        SimpleNamespace(
            command="trace",
            subcommand="codex",
            paths=["/tmp/one.jsonl"],
            root="~/.codex/sessions",
            recent=1,
            cwd=None,
            duplicates=7,
            json_output=True,
        )
    )

    assert result == {"paths": ["/tmp/one.jsonl"], "duplicate_limit": 7}


def test_trace_dispatch_discovers_recent_paths(monkeypatch):
    cwd_filter = "target-project"

    monkeypatch.setattr(
        cli,
        "find_codex_trace_paths",
        lambda root, recent, cwd: ["/tmp/one.jsonl", "/tmp/two.jsonl"],
    )
    monkeypatch.setattr(
        cli,
        "analyze_codex_traces",
        lambda paths, duplicate_limit: {"paths": paths, "duplicate_limit": duplicate_limit},
    )

    result = cli._dispatch(
        SimpleNamespace(
            command="trace",
            subcommand="codex",
            paths=[],
            root="~/.codex/sessions",
            recent=2,
            cwd=cwd_filter,
            duplicates=5,
            json_output=True,
        )
    )

    assert result == {"paths": ["/tmp/one.jsonl", "/tmp/two.jsonl"], "duplicate_limit": 5}


def test_trace_dispatch_discovers_recent_claude_paths(monkeypatch):
    cwd_filter = "target-project"

    monkeypatch.setattr(
        cli,
        "find_claude_trace_paths",
        lambda root, recent, cwd: ["/tmp/claude-one.jsonl"],
    )
    monkeypatch.setattr(
        cli,
        "analyze_claude_traces",
        lambda paths, duplicate_limit: {"paths": paths, "duplicate_limit": duplicate_limit},
    )

    result = cli._dispatch(
        SimpleNamespace(
            command="trace",
            subcommand="claude",
            paths=[],
            root="~/.claude/projects",
            recent=1,
            cwd=cwd_filter,
            duplicates=6,
            json_output=True,
        )
    )

    assert result == {"paths": ["/tmp/claude-one.jsonl"], "duplicate_limit": 6}


def test_funcs_disassemble_alias_invokes_disasm(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["context_id"] = context_id
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    args = SimpleNamespace(
        command="funcs",
        subcommand="disassemble",
        query="main",
        limit=10,
        offset=0,
        contains=None,
        around=None,
        context_lines=3,
        lines=None,
        summary=False,
        full=False,
        session=None,
        json_output=True,
    )
    result = cli._dispatch(args)

    assert result == {"ok": True}
    assert called["command"] == "funcs.disasm"
    assert called["context_id"] == "ctx_test"


def test_functions_command_alias_dispatches_to_funcs(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["context_id"] = context_id
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="functions",
            subcommand="show",
            query="main",
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "funcs.show"
    assert called["context_id"] == "ctx_test"


def test_funcs_list_rich_query_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="funcs",
            subcommand="list",
            limit=25,
            offset=5,
            page=None,
            query=["name:*main*"],
            select="addr,name",
            sort="size:desc",
            name_regex="^main$",
            min_size=16,
            max_size=64,
            has_type=True,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "funcs.list"
    assert called["payload"] == {
        "limit": 25,
        "offset": 5,
        "page": None,
        "query": ["name:*main*"],
        "select": ["addr", "name"],
        "sort": "size:desc",
        "name_regex": "^main$",
        "min_size": 16,
        "max_size": 64,
        "has_type": True,
    }


def test_funcs_list_dispatches_all_as_limit_zero(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="funcs",
            subcommand="list",
            limit=50,
            offset=0,
            page=None,
            query=None,
            select=None,
            sort=None,
            name_regex=None,
            min_size=None,
            max_size=None,
            has_type=None,
            calls=None,
            all=True,
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "funcs.list"
    assert called["payload"]["limit"] == 0


def test_imports_list_rich_query_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="imports",
            subcommand="list",
            limit=20,
            offset=0,
            page=None,
            query=["name:*puts*"],
            select="imported_name,module",
            sort="module",
            regex="^puts",
            module="libc*",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "imports.list"
    assert called["payload"]["regex"] == "^puts"
    assert called["payload"]["module"] == "libc*"


def test_strings_list_rich_query_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="strings",
            subcommand="list",
            limit=20,
            offset=0,
            page=None,
            query=["text:*password*"],
            select="addr,text",
            sort="addr:desc",
            regex="pass.*",
            segment=".rodata",
            min_addr="0x1000",
            max_addr="0x2000",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "strings.list"
    assert called["payload"]["segment"] == ".rodata"
    assert called["payload"]["min_addr"] == "0x1000"
    assert called["payload"]["max_addr"] == "0x2000"


def test_sessions_save_session_ref_uses_direct_save_endpoint(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    calls = {}

    def fake_daemon_request(method, path, payload):
        calls["method"] = method
        calls["path"] = path
        calls["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "daemon_request", fake_daemon_request)

    result = cli._dispatch(
        SimpleNamespace(
            command="sessions",
            subcommand="save",
            path="/tmp/out.i64",
            session_ref="sess1",
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert calls["method"] == "POST"
    assert calls["path"] == "/v1/sessions/sess1/save"
    assert calls["payload"] == {"context_id": "ctx_test", "path": "/tmp/out.i64"}


def test_sessions_info_uses_info_command(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["context_id"] = context_id
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="sessions",
            subcommand="info",
            session_ref="sess1",
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "sessions.info"
    assert called["payload"] == {"session_ref": "sess1"}


def test_sessions_warmup_dispatches_rich_flags(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="sessions",
            subcommand="warmup",
            wait_auto_analysis=False,
            build_caches=False,
            init_hexrays=True,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "sessions.warmup"
    assert called["payload"] == {
        "wait_auto_analysis": False,
        "build_caches": False,
        "init_hexrays": True,
    }


def test_xrefs_root_command_dispatches_to_query_backend(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["context_id"] = context_id
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="xrefs",
            query="main",
            query_alias=None,
            direction=None,
            alias_direction=None,
            xref_type="any",
            limit=100,
            offset=0,
            page=None,
            query_filter=None,
            select=None,
            sort=None,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "xrefs.query"
    assert called["context_id"] == "ctx_test"
    assert called["payload"]["query"] == "main"
    assert called["payload"]["direction"] == "both"
    assert called["payload"]["xref_type"] == "any"


def test_xrefs_alias_command_dispatches_to_query_backend(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="xrefs",
            query="to",
            query_alias="0x1234",
            direction=None,
            alias_direction=None,
            xref_type="code",
            limit=25,
            offset=5,
            page=None,
            query_filter=["type:code"],
            select="addr,type",
            sort="addr:desc",
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["payload"] == {
        "query": "0x1234",
        "direction": "to",
        "xref_type": "code",
        "count": 25,
        "offset": 5,
        "page": None,
        "query_terms": ["type:code"],
        "select": ["addr", "type"],
        "sort": "addr:desc",
    }


def test_xrefs_direction_flag_overrides_alias(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="xrefs",
            query="to",
            query_alias="main",
            direction="from",
            alias_direction=None,
            xref_type="any",
            limit=100,
            offset=0,
            page=None,
            query_filter=None,
            select=None,
            sort=None,
            session=None,
            json_output=True,
        )
    )

    assert called["payload"]["direction"] == "from"


def test_xrefs_requires_query(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")

    with pytest.raises(SystemExit) as exc:
        cli._dispatch(
            SimpleNamespace(
                command="xrefs",
                query=None,
                query_alias=None,
                direction=None,
                alias_direction=None,
                xref_type="any",
                limit=100,
                offset=0,
                page=None,
                query_filter=None,
                select=None,
                sort=None,
                session=None,
                json_output=True,
            )
        )

    assert "idap xrefs: error: query is required" in str(exc.value)


def test_xrefs_field_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="xrefs",
            query="field",
            query_alias="MYSTRUCT",
            query_extra="member",
            direction=None,
            alias_direction=None,
            xref_type="any",
            limit=100,
            offset=0,
            page=None,
            query_filter=None,
            select=None,
            sort=None,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "xrefs.field"
    assert called["payload"]["struct"] == "MYSTRUCT"
    assert called["payload"]["field"] == "member"


def test_search_regex_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="search",
            subcommand="regex",
            pattern="pass.*",
            limit=10,
            offset=0,
            page=2,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "search.regex"
    assert called["payload"] == {"pattern": "pass.*", "limit": 10, "offset": 10}


def test_search_regex_dispatches_all_as_limit_zero(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="search",
            subcommand="regex",
            pattern="pass.*",
            limit=30,
            offset=0,
            page=None,
            all=True,
            session=None,
            json_output=True,
        )
    )

    assert called["payload"] == {"pattern": "pass.*", "limit": 0, "offset": 0}


def test_search_refs_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="search",
            subcommand="refs",
            ref_type="code_ref",
            target="0x1234",
            limit=20,
            offset=5,
            page=None,
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "search.refs"
    assert called["payload"] == {
        "ref_type": "code_ref",
        "target": "0x1234",
        "limit": 20,
        "offset": 5,
    }


def test_search_rejects_page_with_offset(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")

    with pytest.raises(SystemExit) as exc:
        cli._dispatch(
            SimpleNamespace(
                command="search",
                subcommand="bytes",
                pattern="48 8B ??",
                limit=10,
                offset=5,
                page=2,
                session=None,
                json_output=True,
            )
        )

    assert "Cannot combine --page with --offset" in str(exc.value)


def test_search_rejects_page_with_all(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")

    with pytest.raises(SystemExit) as exc:
        cli._dispatch(
            SimpleNamespace(
                command="search",
                subcommand="regex",
                pattern="foo",
                limit=30,
                offset=0,
                page=2,
                all=True,
                session=None,
                json_output=True,
            )
        )

    assert "Cannot combine --page with --all" in str(exc.value)


def test_funcs_list_rejects_page_with_all(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")

    with pytest.raises(SystemExit) as exc:
        cli._dispatch(
            SimpleNamespace(
                command="funcs",
                subcommand="list",
                limit=50,
                offset=0,
                page=2,
                all=True,
                query=None,
                select=None,
                sort=None,
                name_regex=None,
                min_size=None,
                max_size=None,
                has_type=None,
                calls=[],
                call_match="any",
                session=None,
                json_output=True,
            )
        )

    assert "Cannot combine --page with --all" in str(exc.value)


def test_types_declare_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="types",
            subcommand="declare",
            decl="typedef struct foo { int x; } foo;",
            from_json=None,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "types.declare"
    assert called["payload"]["decls"].startswith("typedef struct foo")


def test_types_struct_search_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="types",
            subcommand="structs",
            structs_subcommand="search",
            filter="resolver",
            limit=25,
            offset=0,
            page=None,
            query=None,
            select="name,size",
            sort="name",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "types.structs.search"
    assert called["payload"]["filter"] == "resolver"
    assert called["payload"]["select"] == ["name", "size"]


def test_memory_int_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="memory",
            subcommand="int",
            addr="0x401000",
            width=8,
            signed=True,
            endian="be",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "memory.int"
    assert called["payload"] == {"addr": "0x401000", "ty": "i64be"}


def test_convert_int_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="convert",
            subcommand="int",
            value="0x41",
            size=4,
            input_format="auto",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "convert.int"
    assert called["payload"] == {"value": "0x41", "size": 4, "input_format": "auto"}


def test_memory_string_dispatches_max_len(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="memory",
            subcommand="string",
            addr="0x1234",
            max_len=32,
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "memory.string"
    assert called["payload"] == {"addr": "0x1234", "max_len": 32}


def test_raw_schema_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="raw",
            subcommand="schema",
            tool_name="set_type",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "raw.schema"
    assert called["payload"] == {"tool_name": "set_type"}


def test_funcs_export_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="funcs",
            subcommand="export",
            queries=["main", "helper"],
            export_format="prototypes",
            limit=10,
            offset=0,
            page=None,
            query=None,
            select=None,
            sort=None,
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "funcs.export"
    assert called["payload"]["addrs"] == ["main", "helper"]
    assert called["payload"]["format"] == "prototypes"


def test_funcs_callgraph_dispatches_direction(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="funcs",
            subcommand="callgraph",
            queries=["main"],
            max_depth=2,
            max_nodes=100,
            max_edges=200,
            direction="both",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "funcs.callgraph"
    assert called["payload"]["direction"] == "both"


def test_types_list_dispatches_richer_flags(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="types",
            subcommand="list",
            filter="foo",
            kind="struct",
            limit=25,
            offset=0,
            page=None,
            query=None,
            select=None,
            sort=None,
            include_members=True,
            no_include_decl=False,
            max_members=12,
            include_relationships=True,
            all=False,
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "types.list"
    assert called["payload"]["max_members"] == 12
    assert called["payload"]["include_relationships"] is True


def test_types_list_dispatches_all_as_zero_limit_and_count(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="types",
            subcommand="list",
            filter="",
            kind="any",
            limit=100,
            offset=0,
            page=None,
            query=None,
            select=None,
            sort=None,
            include_members=False,
            no_include_decl=False,
            max_members=64,
            include_relationships=False,
            all=True,
            session=None,
            json_output=True,
        )
    )

    assert called["payload"]["limit"] == 0
    assert called["payload"]["count"] == 0


def test_types_infer_dispatches_depth(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="types",
            subcommand="infer",
            target="0x1234",
            from_json=None,
            depth=3,
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "types.infer"
    assert called["payload"]["depth"] == 3


def test_patch_asm_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="patch",
            subcommand="asm",
            from_json=None,
            addr="0x1234",
            asm="nop",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "patch.asm"
    assert called["payload"] == {"items": {"addr": "0x1234", "asm": "nop"}}


def test_funcs_list_calls_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    cli._dispatch(
        SimpleNamespace(
            command="funcs",
            subcommand="list",
            limit=0,
            offset=0,
            page=None,
            query=None,
            select=None,
            sort=None,
            name_regex=None,
            min_size=None,
            max_size=None,
            has_type=None,
            calls=["recv", "send"],
            call_match="all",
            session=None,
            json_output=True,
        )
    )

    assert called["command"] == "funcs.list"
    assert called["payload"]["calls"] == ["recv", "send"]
    assert called["payload"]["call_match"] == "all"


def test_rename_from_json_dispatches(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    payload_path = tmp_path / "rename.json"
    payload_path.write_text('{"func":[{"addr":"0x1234","name":"main2"}],"dry_run":true}', encoding="utf-8")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="rename",
            from_json=str(payload_path),
            target=None,
            new_name=None,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "rename"
    assert called["payload"]["dry_run"] is True


def test_comment_from_json_dispatches(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    payload_path = tmp_path / "comment.json"
    payload_path.write_text('[{"addr":"0x1234","comment":"hello"}]', encoding="utf-8")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="comment",
            subcommand="set",
            from_json=str(payload_path),
            target=None,
            comment=None,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "comment.set"
    assert called["payload"][0]["comment"] == "hello"


def test_comment_append_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="comment",
            subcommand="append",
            from_json=None,
            target="0x1234",
            comment="hello",
            scope="func",
            allow_duplicate=False,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "comment.append"
    assert called["payload"] == {
        "target": "0x1234",
        "comment": "hello",
        "scope": "func",
        "dedupe": True,
    }


def test_types_enums_upsert_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_invoke(command, context_id, args, payload):
        called["command"] = command
        called["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(cli, "_invoke", fake_invoke)

    result = cli._dispatch(
        SimpleNamespace(
            command="types",
            subcommand="enums",
            enums_subcommand="upsert",
            from_json=None,
            name="WCAppMsgInnerType",
            member=["WC_APPMSG_INNER_BRAND_MP_VIDEO=54", "WC_APPMSG_INNER_TING_CATEGORY=93"],
            bitfield=False,
            session=None,
            json_output=True,
        )
    )

    assert result == {"ok": True}
    assert called["command"] == "types.enums.upsert"
    assert called["payload"] == {
        "queries": {
            "name": "WCAppMsgInnerType",
            "members": [
                {"name": "WC_APPMSG_INNER_BRAND_MP_VIDEO", "value": 54},
                {"name": "WC_APPMSG_INNER_TING_CATEGORY", "value": 93},
            ],
            "bitfield": False,
        }
    }


def test_integrations_aliases_share_generic_bootstrap():
    for provider in ("generic", "codex", "opencode", "pi"):
        result = cli._integrations_dispatch(
            SimpleNamespace(provider=provider, format="text")
        )
        assert 'idap context ensure --shell' in result


def test_integrations_aliases_support_json():
    result = cli._integrations_dispatch(
        SimpleNamespace(provider="codex", format="json")
    )

    assert result["parent"] == 'eval "$(idap context ensure --shell)"'
    assert result["subagent"] == 'eval "$(idap context ensure --shell --force-new)"'


def test_integrations_install_dispatches_for_codex(monkeypatch):
    monkeypatch.setattr(cli, "install_codex_skill", lambda: {"ok": True})

    result = cli._integrations_dispatch(
        SimpleNamespace(provider="codex", subcommand="install", format="text")
    )

    assert result == {"ok": True}


def test_integrations_install_skill_dispatches_for_claude(monkeypatch):
    monkeypatch.setattr(cli, "install_claude_skill", lambda: {"ok": True})

    result = cli._integrations_dispatch(
        SimpleNamespace(provider="claude", subcommand="install-skill", format="text")
    )

    assert result == {"ok": True}


def test_integrations_skill_show_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "skill_show", lambda agent: {"agent": agent})

    result = cli._integrations_dispatch(
        SimpleNamespace(provider="skill", subcommand="show", agent="codex", format="json")
    )

    assert result == {"agent": "codex"}


def test_integrations_skill_doctor_dispatches(monkeypatch):
    monkeypatch.setattr(cli, "skill_doctor", lambda: {"ok": True})

    result = cli._integrations_dispatch(
        SimpleNamespace(provider="skill", subcommand="doctor", format="json")
    )

    assert result == {"ok": True}


def test_resolve_context_uses_cached_manual_context(monkeypatch):
    monkeypatch.setattr(cli, "_cached_context_id", lambda: "ctx_cached")

    result = cli._resolve_context(SimpleNamespace(context=None))

    assert result == "ctx_cached"


def test_context_ensure_reuses_cached_context(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "")
    monkeypatch.setattr(cli, "_cached_context_id", lambda: "ctx_cached")
    stored = {}

    def fake_daemon_request(method, path, payload):
        stored["method"] = method
        stored["path"] = path
        stored["payload"] = payload
        return {"context_id": "ctx_cached"}

    monkeypatch.setattr(cli, "daemon_request", fake_daemon_request)
    monkeypatch.setattr(cli, "_store_cached_context_id", lambda context_id: stored.setdefault("stored", context_id))

    result = cli._dispatch(
        SimpleNamespace(command="context", subcommand="ensure", shell=False, force_new=False, json_output=True)
    )

    assert result == {"context_id": "ctx_cached"}
    assert stored["payload"]["current_context_id"] == "ctx_cached"
    assert stored["stored"] == "ctx_cached"


def test_sessions_open_dispatches_async_job(monkeypatch):
    monkeypatch.setattr(cli, "_resolve_context", lambda _args: "ctx_test")
    called = {}

    def fake_daemon_request(method, path, payload):
        called["method"] = method
        called["path"] = path
        called["payload"] = payload
        return {"job_id": "job_123", "status": "queued", "job": {"job_id": "job_123", "status": "queued"}}

    monkeypatch.setattr(cli, "daemon_request", fake_daemon_request)

    result = cli._dispatch(
        SimpleNamespace(
            command="sessions",
            subcommand="open",
            path="/tmp/sample.bin",
            alias="sample",
            session_id=None,
            database_path="/tmp/sample.i64",
            no_analysis=True,
            wait=False,
            timeout=None,
            session=None,
            json_output=True,
        )
    )

    assert result["job_id"] == "job_123"
    assert called["method"] == "POST"
    assert called["path"] == "/v1/jobs/open-session"
    assert called["payload"]["context_id"] == "ctx_test"


def test_jobs_wait_polls_until_success(monkeypatch):
    responses = iter(
        [
            {"job": {"job_id": "job_123", "status": "running"}},
            {"job": {"job_id": "job_123", "status": "succeeded", "session_id": "sess1"}},
        ]
    )

    monkeypatch.setattr(cli, "daemon_request", lambda method, path, payload: next(responses))
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    result = cli._dispatch(
        SimpleNamespace(command="jobs", subcommand="wait", job_id="job_123", timeout=1.0, json_output=True)
    )

    assert result["job"]["status"] == "succeeded"


def test_render_output_supports_jsonl_for_items():
    rendered = cli._render_output(
        {
            "items": [{"name": "main"}, {"name": "helper"}],
            "count": 2,
        },
        fmt="jsonl",
    )

    assert rendered.splitlines() == ['{"name": "main"}', '{"name": "helper"}']


def test_render_output_rejects_jsonl_for_non_collections():
    with pytest.raises(SystemExit):
        cli._render_output({"text": "hello"}, fmt="jsonl")


def test_render_output_text_uses_body_for_text_results():
    rendered = cli._render_output(
        {"text": "line one\nline two", "line_count": 2, "truncated": False},
        fmt="text",
    )

    assert rendered == "line one\nline two"


def test_render_output_text_renders_collection_table():
    rendered = cli._render_output(
        {
            "items": [
                {"name": "main", "addr": "0x401000"},
                {"name": "helper", "addr": "0x401100"},
            ],
            "count": 2,
            "paged": True,
            "offset": 0,
            "has_more": True,
            "remaining": 3,
        },
        fmt="text",
    )

    assert rendered.splitlines() == [
        "name    addr",
        "------  --------",
        "main    0x401000",
        "helper  0x401100",
        "Paged: showing 2 item(s) at offset 0; 3 remaining.",
    ]


def test_render_output_text_renders_item_collection_table():
    rendered = cli._render_output(
        {
            "item": [
                {"query": "main", "fn": {"addr": "0x401000", "name": "main"}, "error": None},
            ]
        },
        fmt="text",
    )

    assert rendered.splitlines() == [
        "query  fn                                    error",
        "-----  ------------------------------------  -----",
        'main   {"addr": "0x401000", "name": "main"}',
    ]


def test_render_output_text_renders_unknown_remaining_footer():
    rendered = cli._render_output(
        {
            "items": [{"name": "main", "addr": "0x401000"}],
            "count": 1,
            "paged": True,
            "offset": 25,
            "has_more": True,
            "remaining": None,
        },
        fmt="text",
    )

    assert rendered.splitlines() == [
        "name  addr",
        "----  --------",
        "main  0x401000",
        "Paged: showing 1 item(s) at offset 25; more items remain.",
    ]


def test_render_output_text_discovers_columns_across_rows():
    rendered = cli._render_output(
        {
            "items": [
                {"name": "main"},
                {"name": "helper", "addr": "0x401100", "is_thunk": False},
            ],
        },
        fmt="text",
    )

    assert rendered.splitlines() == [
        "name    addr      is_thunk",
        "------  --------  --------",
        "main",
        "helper  0x401100  false",
    ]


def test_render_output_text_renders_simple_mapping_as_key_values():
    rendered = cli._render_output(
        {"context_id": "ctx_test", "session": None},
        fmt="text",
    )

    assert rendered.splitlines() == [
        "context_id: ctx_test",
        "session:",
    ]


def test_render_output_text_renders_nested_mapping_as_block():
    rendered = cli._render_output(
        {
            "context_id": "ctx_test",
            "session": {
                "session_id": "sess1",
                "filename": "ls",
                "metadata": {},
            },
        },
        fmt="text",
    )

    assert rendered.splitlines() == [
        "context_id: ctx_test",
        "session:",
        "  session_id: sess1",
        "  filename: ls",
        "  metadata: {}",
    ]


def test_render_output_text_renders_list_values_as_block():
    rendered = cli._render_output(
        {
            "log_path": "/tmp/idap.log",
            "lines": ["one", "two"],
        },
        fmt="text",
    )

    assert rendered.splitlines() == [
        "log_path: /tmp/idap.log",
        "lines:",
        "  - one",
        "  - two",
    ]
