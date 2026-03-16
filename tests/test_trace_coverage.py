import json
from pathlib import Path

from ida_pro_mcp.trace_coverage import (
    MCP_TOOL_TO_CLI,
    PY_EVAL_CATEGORY_TO_CLI,
    build_report,
    classify_py_eval,
)


def _write_trace(path: Path, entries: list[dict]) -> None:
    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")


def test_classify_py_eval_categories():
    assert classify_py_eval("import ida_hexrays\nc=ida_hexrays.decompile(0x1000)\nc.get_pseudocode()") == "decompile_context_search"
    assert classify_py_eval("import idautils\nfor s in idautils.Strings(): print(s)") == "string_inventory"
    assert classify_py_eval("import idautils\nfor f in idautils.Functions():\n  pass") == "ad_hoc_python"
    assert classify_py_eval("import idautils\nfor x in idautils.CodeRefsFrom(0x1000, False):\n  target=x") == "callee_scan"


def test_trace_coverage_report_maps_observed_tools_and_py_eval(tmp_path):
    trace_path = tmp_path / "trace.jsonl"
    _write_trace(
        trace_path,
        [
            {
                "payload": {
                    "type": "function_call",
                    "name": "mcp__ida-pro-mcp__decompile",
                    "arguments": "{}",
                }
            },
            {
                "payload": {
                    "type": "function_call",
                    "name": "mcp__ida-pro-mcp__search_structs",
                    "arguments": "{}",
                }
            },
            {
                "payload": {
                    "type": "function_call",
                    "name": "mcp__ida-pro-mcp__py_eval",
                    "arguments": json.dumps(
                        {
                            "code": (
                                "import ida_hexrays\n"
                                "cfunc=ida_hexrays.decompile(0x1234)\n"
                                "cfunc.get_pseudocode()\n"
                            )
                        }
                    ),
                }
            },
            {
                "payload": {
                    "type": "function_call",
                    "name": "mcp__ida-pro-mcp__py_eval",
                    "arguments": json.dumps(
                        {
                            "code": (
                                "import idautils\n"
                                "for s in idautils.Strings():\n"
                                "    print(s)\n"
                            )
                        }
                    ),
                }
            },
        ],
    )

    report = build_report([trace_path])

    assert report.unmapped_tools == set()
    assert report.unmapped_py_eval_categories == set()
    assert report.tools == {"decompile", "search_structs", "py_eval"}
    assert report.py_eval_categories == {"decompile_context_search", "string_inventory"}


def test_coverage_maps_include_long_tail_trace_tools():
    for tool_name in ("basic_blocks", "patch", "patch_asm", "put_int", "list_imports", "metadata"):
        assert tool_name in MCP_TOOL_TO_CLI
    for category in ("bulk_function_inventory", "callee_scan", "ad_hoc_python"):
        assert category in PY_EVAL_CATEGORY_TO_CLI
