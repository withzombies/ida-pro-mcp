import pytest

from ida_pro_mcp.core.errors import IDAPError
from ida_pro_mcp.core.querying import (
    apply_collection_options,
    normalize_text_payload,
    parse_query_terms,
    resolve_collection_window,
    resolve_function_query,
    shape_paged_collection,
    shape_text_output,
)


pytestmark = pytest.mark.fast


def test_apply_collection_options_filters_projects_and_pages():
    items = [
        {"name": "alpha", "addr": "0x10", "size": 4},
        {"name": "beta", "addr": "0x20", "size": 8},
        {"name": "alphabet", "addr": "0x30", "size": 2},
    ]

    result = apply_collection_options(
        items,
        limit=1,
        offset=0,
        query_terms=parse_query_terms(["name:alp*"]),
        select_fields=["name", "addr"],
        sort_spec="name:asc",
    )

    assert result["count"] == 1
    assert result["total"] == 2
    assert result["has_more"] is True
    assert result["next_offset"] == 1
    assert result["paged"] is True
    assert result["remaining"] == 1
    assert result["remaining_estimate"] == "exact"
    assert result["page_status"] == "partial_exact_remaining"
    assert result["items"] == [{"name": "alpha", "addr": "0x10"}]


def test_apply_collection_options_limit_zero_returns_all_up_to_cap():
    items = [{"name": f"fn{i}"} for i in range(3)]

    result = apply_collection_options(items, limit=0)

    assert result["count"] == 3
    assert result["total"] == 3
    assert result["has_more"] is False
    assert result["paged"] is False
    assert result["remaining"] == 0
    assert result["remaining_estimate"] == "exact"
    assert result["page_status"] == "complete"


def test_resolve_collection_window_supports_page_and_limit_zero():
    requested_limit, effective_limit, effective_offset = resolve_collection_window(
        limit=0,
        offset=0,
        page=None,
    )

    assert requested_limit == 0
    assert effective_limit == 0
    assert effective_offset == 0


def test_resolve_collection_window_rejects_page_with_limit_zero():
    with pytest.raises(IDAPError, match="Cannot combine --page with --all"):
        resolve_collection_window(limit=0, offset=0, page=2)


def test_resolve_collection_window_rejects_limits_above_max():
    with pytest.raises(IDAPError, match="less than or equal to 500"):
        resolve_collection_window(limit=501, offset=0, page=None)


def test_shape_paged_collection_preserves_requested_limit_and_next_offset():
    result = shape_paged_collection(
        [{"addr": "0x10", "name": "alpha", "size": 4}],
        limit=25,
        offset=50,
        next_offset=75,
        total=None,
        select_fields=["addr", "name"],
    )

    assert result == {
        "items": [{"addr": "0x10", "name": "alpha"}],
        "count": 1,
        "total": None,
        "limit": 25,
        "offset": 50,
        "next_offset": 75,
        "has_more": True,
        "paged": True,
        "remaining": None,
        "remaining_estimate": "unknown_more",
        "page_status": "partial_unknown_remaining",
    }


def test_shape_paged_collection_reports_final_window_with_exact_remaining():
    result = shape_paged_collection(
        [{"addr": "0x30", "name": "omega"}],
        limit=25,
        offset=50,
        next_offset=None,
        total=51,
    )

    assert result["paged"] is True
    assert result["remaining"] == 0
    assert result["remaining_estimate"] == "exact"
    assert result["page_status"] == "complete"


def test_shape_text_output_supports_summary_and_line_ranges():
    text = "\n".join(f"line {i}" for i in range(1, 31))

    sliced = shape_text_output(text, line_range="5:8")
    assert sliced["text"] == "line 5\nline 6\nline 7\nline 8"
    assert sliced["truncated"] is False

    summary = shape_text_output(text, summary=True)
    assert "line 1" in summary["text"]
    assert summary["line_count"] == 30
    assert summary["truncated"] is True


def test_normalize_text_payload_extracts_disasm_lines_from_dict():
    payload = {
        "name": "calloc",
        "start_ea": "0x41740",
        "lines": "calloc (.plt @ 0x41740):\n41740  b 0x1000",
    }

    assert normalize_text_payload(payload) == "calloc (.plt @ 0x41740):\n41740  b 0x1000"


def test_resolve_function_query_uses_lookup_for_names():
    def resolver(query):
        assert query == "main"
        return [{"query": "main", "fn": {"addr": "0x3120"}, "error": None}]

    assert resolve_function_query("main", resolver) == "0x3120"


def test_resolve_function_query_keeps_addresses_unchanged():
    assert resolve_function_query("0x41740", lambda _query: []) == "0x41740"
