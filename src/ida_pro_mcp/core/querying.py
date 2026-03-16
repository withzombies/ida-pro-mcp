"""Shared output shaping helpers for collection and text responses."""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from .errors import IDAPError

DEFAULT_LIMIT = 50
MAX_LIMIT = 500


def parse_query_terms(raw_terms: list[str] | None) -> list[tuple[str, str]]:
    terms: list[tuple[str, str]] = []
    for term in raw_terms or []:
        if ":" not in term:
            raise IDAPError("INVALID_QUERY_FIELD", f"Invalid query term: {term}")
        field, value = term.split(":", 1)
        field = field.strip()
        value = value.strip()
        if not field:
            raise IDAPError("INVALID_QUERY_FIELD", f"Invalid query term: {term}")
        terms.append((field, value))
    return terms


def apply_collection_options(
    items: list[dict[str, Any]],
    *,
    limit: int | None = None,
    offset: int = 0,
    page: int | None = None,
    query_terms: list[tuple[str, str]] | None = None,
    select_fields: list[str] | None = None,
    sort_spec: str | None = None,
    aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    aliases = aliases or {}
    requested_limit, effective_limit, effective_offset = resolve_collection_window(
        limit=limit,
        offset=offset,
        page=page,
    )

    filtered = list(items)
    for field, value in query_terms or []:
        key = aliases.get(field, field)
        if filtered and key not in filtered[0]:
            raise IDAPError("INVALID_QUERY_FIELD", f"Unsupported query field: {field}")
        filtered = [item for item in filtered if _matches_query(item.get(key), value)]

    if sort_spec:
        sort_field, descending = _parse_sort(sort_spec)
        sort_key = aliases.get(sort_field, sort_field)
        if filtered and sort_key not in filtered[0]:
            raise IDAPError("INVALID_SORT_FIELD", f"Unsupported sort field: {sort_field}")
        filtered.sort(key=lambda item: _sort_value(item.get(sort_key)), reverse=descending)

    total = len(filtered)
    if requested_limit == 0:
        paged = filtered[effective_offset:]
    else:
        paged = filtered[effective_offset : effective_offset + effective_limit]

    if select_fields:
        normalized_fields = [aliases.get(field, field) for field in select_fields]
        for field in normalized_fields:
            if paged and field not in paged[0]:
                raise IDAPError("INVALID_QUERY_FIELD", f"Unsupported select field: {field}")
        paged = [{field: item.get(field) for field in normalized_fields} for item in paged]

    if requested_limit == 0:
        next_offset = None
    else:
        next_offset = effective_offset + effective_limit
        if next_offset >= total:
            next_offset = None

    return shape_collection_result(
        items=paged,
        limit=requested_limit,
        offset=effective_offset,
        next_offset=next_offset,
        total=total,
    )


def resolve_collection_window(
    *,
    limit: int | None = None,
    offset: int = 0,
    page: int | None = None,
) -> tuple[int, int, int]:
    if page is not None and offset:
        raise IDAPError("INVALID_PAGINATION", "Cannot combine --page with --offset")

    requested_limit = DEFAULT_LIMIT if limit is None else int(limit)
    if requested_limit < 0:
        raise IDAPError("INVALID_PAGINATION", "--limit must be greater than zero")
    if requested_limit > MAX_LIMIT:
        raise IDAPError("INVALID_PAGINATION", f"--limit must be less than or equal to {MAX_LIMIT}")
    if page is not None and requested_limit == 0:
        raise IDAPError("INVALID_PAGINATION", "Cannot combine --page with --all")

    effective_limit = requested_limit

    effective_offset = int(offset or 0)
    if page is not None:
        if page <= 0:
            raise IDAPError("INVALID_PAGINATION", "--page must be greater than zero")
        effective_offset = (page - 1) * effective_limit

    return requested_limit, effective_limit, effective_offset


def shape_paged_collection(
    items: list[dict[str, Any]],
    *,
    limit: int | None = None,
    offset: int = 0,
    page: int | None = None,
    next_offset: int | None = None,
    total: int | None = None,
    select_fields: list[str] | None = None,
    aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    aliases = aliases or {}
    requested_limit, _effective_limit, effective_offset = resolve_collection_window(
        limit=limit,
        offset=offset,
        page=page,
    )

    paged = list(items)
    if select_fields:
        normalized_fields = [aliases.get(field, field) for field in select_fields]
        for field in normalized_fields:
            if paged and field not in paged[0]:
                raise IDAPError("INVALID_QUERY_FIELD", f"Unsupported select field: {field}")
        paged = [{field: item.get(field) for field in normalized_fields} for item in paged]

    return shape_collection_result(
        items=paged,
        limit=requested_limit,
        offset=effective_offset,
        next_offset=next_offset,
        total=total,
    )


def shape_collection_result(
    *,
    items: list[dict[str, Any]],
    limit: int,
    offset: int,
    next_offset: int | None,
    total: int | None,
) -> dict[str, Any]:
    has_more = next_offset is not None
    remaining, remaining_estimate = _remaining_metadata(
        count=len(items),
        offset=offset,
        total=total,
        has_more=has_more,
    )
    return {
        "items": items,
        "count": len(items),
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
        "has_more": has_more,
        "paged": _is_paged_result(
            count=len(items),
            limit=limit,
            offset=offset,
            total=total,
            has_more=has_more,
        ),
        "remaining": remaining,
        "remaining_estimate": remaining_estimate,
        "page_status": _page_status(has_more=has_more, remaining_estimate=remaining_estimate),
    }


def _remaining_metadata(
    *,
    count: int,
    offset: int,
    total: int | None,
    has_more: bool,
) -> tuple[int | None, str]:
    if total is not None:
        return max(total - (offset + count), 0), "exact"
    if has_more:
        return None, "unknown_more"
    return None, "none"


def _is_paged_result(
    *,
    count: int,
    limit: int,
    offset: int,
    total: int | None,
    has_more: bool,
) -> bool:
    if has_more or offset > 0:
        return True
    if total is None or limit == 0:
        return False
    return count < total


def _page_status(*, has_more: bool, remaining_estimate: str) -> str:
    if not has_more:
        return "complete"
    if remaining_estimate == "exact":
        return "partial_exact_remaining"
    return "partial_unknown_remaining"


def shape_text_output(
    text: str,
    *,
    full: bool = False,
    contains: str | None = None,
    around: str | None = None,
    context_lines: int = 3,
    line_range: str | None = None,
    summary: bool = False,
) -> dict[str, Any]:
    if line_range and around:
        raise IDAPError("INVALID_SLICE_ARGS", "--lines and --around are mutually exclusive")

    lines = text.splitlines()
    truncated = False

    if line_range:
        start_str, end_str = (line_range.split(":", 1) + [""])[:2]
        start = max(1, int(start_str))
        end = len(lines) if not end_str else int(end_str)
        lines = lines[start - 1 : end]
    elif around:
        idx = next((i for i, line in enumerate(lines) if around in line), None)
        if idx is None:
            lines = []
        else:
            start = max(0, idx - context_lines)
            end = idx + context_lines + 1
            lines = lines[start:end]
    elif contains:
        lines = [line for line in lines if contains in line]

    if summary:
        preview = lines[:20]
        truncated = len(lines) > len(preview)
        return {
            "text": "\n".join(preview),
            "line_count": len(lines),
            "truncated": truncated,
        }

    if not full and len(lines) > 200:
        lines = lines[:200]
        truncated = True

    return {
        "text": "\n".join(lines),
        "line_count": len(lines),
        "truncated": truncated,
    }


def normalize_text_payload(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("lines", "text", "code", "result"):
            payload = value.get(key)
            if isinstance(payload, str):
                return payload
    return str(value)


def resolve_function_query(
    query: str,
    resolver: Any,
) -> str:
    stripped = query.strip()
    if not stripped:
        return stripped
    if stripped.startswith("0x"):
        return stripped
    try:
        int(stripped, 10)
        return stripped
    except ValueError:
        pass

    resolved = resolver(stripped)
    if not isinstance(resolved, list) or not resolved:
        return stripped
    first = resolved[0]
    if not isinstance(first, dict) or first.get("error"):
        return stripped
    fn = first.get("fn")
    if not isinstance(fn, dict):
        return stripped
    addr = fn.get("addr")
    return addr if isinstance(addr, str) and addr else stripped


def _matches_query(value: Any, pattern: str) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return str(value).lower() == pattern.lower()
    text = str(value)
    if "*" in pattern:
        return fnmatch(text.lower(), pattern.lower())
    return pattern.lower() in text.lower()


def _parse_sort(spec: str) -> tuple[str, bool]:
    field, _, direction = spec.partition(":")
    return field, direction.lower() == "desc"


def _sort_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    return value
