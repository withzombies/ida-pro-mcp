import sys

import pytest

from ida_pro_mcp import cli


@pytest.mark.fast
def test_main_renders_jsonl_collection(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_dispatch",
        lambda _args: {"items": [{"name": "main"}, {"name": "helper"}]},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["idap", "--format", "jsonl", "funcs", "list"],
    )

    cli.main()

    assert capsys.readouterr().out.splitlines() == [
        '{"name": "main"}',
        '{"name": "helper"}',
    ]


@pytest.mark.fast
def test_main_renders_text_collection(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_dispatch",
        lambda _args: {"items": [{"name": "main", "addr": "0x401000"}]},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["idap", "funcs", "list"],
    )

    cli.main()

    assert capsys.readouterr().out.splitlines() == [
        "name  addr",
        "----  --------",
        "main  0x401000",
    ]


@pytest.mark.fast
def test_main_json_flag_forces_json(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_dispatch",
        lambda _args: {"context_id": "ctx_test"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["idap", "--json", "context", "ensure"],
    )

    cli.main()

    assert capsys.readouterr().out == '{\n  "context_id": "ctx_test"\n}\n'


@pytest.mark.fast
def test_main_renders_text_body(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_dispatch",
        lambda _args: {"text": "line one\nline two", "line_count": 2, "truncated": False},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["idap", "funcs", "decompile", "main"],
    )

    cli.main()

    assert capsys.readouterr().out == "line one\nline two\n"


@pytest.mark.fast
def test_main_accepts_format_after_subcommand(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_dispatch",
        lambda _args: {"items": [{"name": "main"}]},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["idap", "funcs", "list", "--format", "jsonl"],
    )

    cli.main()

    assert capsys.readouterr().out == '{"name": "main"}\n'


@pytest.mark.fast
def test_root_help_includes_command_descriptions(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "Headless IDA Pro workflows through the local idap daemon." in output
    assert "sessions" in output
    assert "Open, bind, inspect, save, and close IDA sessions." in output
    assert "funcs" in output
    assert "Inspect functions, decompilation, disassembly, callers, and constants." in output
    assert "Prefer --json or --format jsonl for structured output." in output


@pytest.mark.fast
def test_funcs_help_includes_subcommand_descriptions(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "funcs", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "Function-level analysis commands." in output
    assert "callers" in output
    assert "List callers of a function by name or address." in output
    assert "basic-blocks" in output
    assert "disassemble" in output
    assert "Explicit alias for 'disasm'." in output


@pytest.mark.fast
def test_functions_alias_help_includes_subcommand_descriptions(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "functions", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "Function-level analysis commands." in output
    assert "callers" in output
    assert "disassemble" in output


@pytest.mark.fast
def test_xrefs_help_includes_flag_based_interface(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "xrefs", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "Cross-reference inspection commands." in output
    assert "--direction {to,from,both}" in output
    assert "--type {any,code,data}" in output
    assert "Compatibility aliases: idap xrefs to <query>" in output
    assert "Field xrefs: idap xrefs field <struct> <field>" in output


@pytest.mark.fast
def test_search_help_includes_subcommands(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "search", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "Search and matching helpers." in output
    assert "regex" in output
    assert "bytes" in output


@pytest.mark.fast
def test_trace_help_includes_codex_summary_command(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "trace", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "Codex trace analysis helpers" in output
    assert "codex" in output
    assert "Summarize Codex session traces" in output


@pytest.mark.fast
def test_trace_help_includes_claude_summary_command(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "trace", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "claude" in output
    assert "Summarize Claude session traces" in output


@pytest.mark.fast
def test_funcs_list_parser_defaults_to_bounded_page():
    parser = cli._build_parser()

    args = parser.parse_args(["funcs", "list"])

    assert args.limit == 50
    assert args.all is False


@pytest.mark.fast
def test_funcs_list_parser_accepts_all_flag():
    parser = cli._build_parser()

    args = parser.parse_args(["funcs", "list", "--all"])

    assert args.all is True


@pytest.mark.fast
def test_types_help_includes_subcommands(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "types", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "Type declaration, application, and struct helpers." in output
    assert "declare" in output
    assert "set" in output
    assert "structs" in output


@pytest.mark.fast
def test_patch_help_includes_subcommands(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "patch", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "bytes" in output
    assert "asm" in output


@pytest.mark.fast
def test_raw_help_includes_introspection_subcommands(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "raw", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "list" in output
    assert "schema" in output
    assert "call" in output


@pytest.mark.fast
def test_main_translates_no_session_bound_error(monkeypatch, capsys):
    def fail(_args):
        raise cli.DaemonClientError(
            "No session bound for this context. Use idalib_switch(session_id) or idalib_open(...) first."
        )

    monkeypatch.setattr(cli, "_dispatch", fail)
    monkeypatch.setattr(sys, "argv", ["idap", "xrefs", "0x1234"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert (
        str(exc.value)
        == "No idap session is active. Use 'idap sessions open <binary>' or 'idap sessions use <session>'."
    )


@pytest.mark.fast
def test_invalid_subcommand_shows_ranked_suggestions(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "funcs", "disassemblee"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
    output = capsys.readouterr().err
    assert "unknown subcommand 'disassemblee'" in output
    assert "Did you mean:" in output
    assert "  - disassemble" in output
    assert "  - disasm" in output
    assert "Run 'idap funcs --help'" in output


@pytest.mark.fast
def test_invalid_flag_shows_ranked_suggestions(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["idap", "sessions", "open", "sample", "--databse-path", "/tmp/a.i64"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
    output = capsys.readouterr().err
    assert "unknown option '--databse-path'" in output
    assert "  - --database-path" in output
    assert "Run 'idap sessions open --help'" in output
