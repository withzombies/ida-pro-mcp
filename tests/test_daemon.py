import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

from ida_pro_mcp import client, idap_daemon


pytestmark = pytest.mark.fast


@dataclass
class _FakeSession:
    session_id: str

    def to_dict(self):
        return {"session_id": self.session_id}


@dataclass
class _FakeJob:
    job_id: str
    input_path: str
    context_id: str | None = None
    requested_alias: str | None = None
    requested_session_id: str | None = None
    database_path: str | None = None
    run_auto_analysis: bool = True
    status: str = "queued"
    session_id: str | None = None
    error: str | None = None

    def to_dict(self):
        return {
            "job_id": self.job_id,
            "input_path": self.input_path,
            "context_id": self.context_id,
            "requested_alias": self.requested_alias,
            "requested_session_id": self.requested_session_id,
            "database_path": self.database_path,
            "run_auto_analysis": self.run_auto_analysis,
            "status": self.status,
            "session_id": self.session_id,
            "error": self.error,
        }


class _FakeManager:
    def __init__(self):
        self.released: list[str] = []
        self.open_calls: list[dict] = []
        self.activated_contexts: list[str] = []
        self.saved_binds: list[tuple[str, str, bool]] = []
        self.jobs: dict[str, _FakeJob] = {}

    def ensure_context(self, *args, **kwargs):
        return type(
            "Context",
            (),
            {
                "to_dict": lambda self: {
                    "context_id": "ctx_test",
                    "parent_context_id": None,
                    "created_at": "2026-03-05T00:00:00",
                    "last_seen_at": "2026-03-05T00:00:00",
                    "label": None,
                    "metadata": {},
                }
            },
        )()

    def release_context(self, context_id: str) -> bool:
        self.released.append(context_id)
        return True

    def get_context(self, context_id: str):
        return type(
            "Context",
            (),
            {
                "to_dict": lambda self: {
                    "context_id": context_id,
                    "parent_context_id": None,
                    "created_at": "2026-03-05T00:00:00",
                    "last_seen_at": "2026-03-05T00:00:01",
                    "label": "test",
                    "metadata": {"launcher": "test"},
                }
            },
        )()

    def get_context_session(self, context_id: str):
        return _FakeSession("sess1")

    def list_contexts(self):
        return [
            {
                "context_id": "ctx_test",
                "parent_context_id": None,
                "created_at": "2026-03-05T00:00:00",
                "last_seen_at": "2026-03-05T00:00:01",
                "label": "test",
                "metadata": {"launcher": "test"},
                "session_id": "sess1",
            }
        ]

    def status(self):
        return {
            "active_session_id": "sess1",
            "session_count": 1,
            "context_count": 1,
            "job_count": len(self.jobs),
        }

    def list_sessions(self, context_id=None):
        return []

    def open_binary(
        self,
        input_path,
        run_auto_analysis=True,
        session_id=None,
        alias=None,
        database_path=None,
    ):
        self.open_calls.append(
            {
                "input_path": str(input_path),
                "run_auto_analysis": run_auto_analysis,
                "session_id": session_id,
                "alias": alias,
                "database_path": database_path,
            }
        )
        return "sess1"

    def submit_open_job(
        self,
        input_path,
        *,
        context_id=None,
        run_auto_analysis=True,
        session_id=None,
        alias=None,
        database_path=None,
    ):
        self.open_calls.append(
            {
                "input_path": str(input_path),
                "run_auto_analysis": run_auto_analysis,
                "session_id": session_id,
                "alias": alias,
                "database_path": database_path,
                "context_id": context_id,
            }
        )
        job = _FakeJob(
            job_id="job_123",
            input_path=str(input_path),
            context_id=context_id,
            requested_alias=alias,
            requested_session_id=session_id,
            database_path=str(database_path) if database_path else None,
            run_auto_analysis=run_auto_analysis,
        )
        self.jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str):
        return self.jobs.get(job_id)

    def list_jobs(self):
        return [job.to_dict() for job in self.jobs.values()]

    def bind_context(self, context_id: str, session_id: str, activate: bool = False):
        self.saved_binds.append((context_id, session_id, activate))
        return _FakeSession(session_id)

    def get_session(self, session_id: str):
        return _FakeSession(session_id)

    def resolve_session_id(self, session_ref: str) -> str:
        return session_ref

    def unbind_context(self, context_id: str) -> bool:
        return True

    def close_session(self, session_id: str) -> bool:
        return True

    def activate_context(self, context_id: str):
        self.activated_contexts.append(context_id)
        return _FakeSession("sess1")

    def close_all_sessions(self):
        return None


class _InlineExecutor:
    def submit_sync(self, _kind, func, *, job_id=None, timeout=None):
        return func()

    def submit_async(self, _kind, _func, *, job_id=None):
        return None

    def status(self):
        return {
            "executor_busy": False,
            "current_task_kind": None,
            "current_job_id": None,
            "executor_queue_depth": 0,
        }


class _TimeoutExecutor:
    def submit_sync(self, _kind, _func, *, job_id=None, timeout=None):
        raise TimeoutError("Timed out waiting for executor task: invoke")

    def submit_async(self, _kind, _func, *, job_id=None):
        return None

    def status(self):
        return {
            "executor_busy": True,
            "current_task_kind": "invoke",
            "current_job_id": None,
            "executor_queue_depth": 1,
        }


def _start_server(monkeypatch, manager: _FakeManager):
    monkeypatch.setattr(idap_daemon, "get_session_manager", lambda: manager)
    server = idap_daemon._DaemonServer(("127.0.0.1", 0), idap_daemon._Handler)
    server.executor = _InlineExecutor()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    info = {
        "host": server.server_address[0],
        "port": server.server_address[1],
        "token": server.token,
    }
    return server, thread, info


def test_daemon_release_context_endpoint(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        result = client.daemon_request(
            "POST",
            "/v1/contexts/release",
            {"context_id": "ctx_123"},
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result == {"released": True, "context_id": "ctx_123"}
    assert manager.released == ["ctx_123"]


def test_daemon_context_get_returns_context_and_bound_session(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        result = client.daemon_request(
            "GET",
            "/v1/contexts/ctx_123",
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["context"]["context_id"] == "ctx_123"
    assert result["session"]["session_id"] == "sess1"


def test_daemon_context_list_returns_contexts(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        result = client.daemon_request(
            "GET",
            "/v1/contexts",
            None,
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["count"] == 1
    assert result["items"][0]["context_id"] == "ctx_test"


def test_daemon_health_includes_status_fields(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        result = client.daemon_request(
            "GET",
            "/v1/health",
            None,
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["status"] == "ok"
    assert result["active_session_id"] == "sess1"
    assert result["session_count"] == 1
    assert result["context_count"] == 1


def test_daemon_session_get_returns_session(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        result = client.daemon_request(
            "GET",
            "/v1/sessions/sess1",
            None,
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["session"]["session_id"] == "sess1"


def test_daemon_sessions_open_creates_job(monkeypatch, tmp_path):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        result = client.daemon_request(
            "POST",
            "/v1/sessions/open",
            {
                "context_id": "ctx_abc",
                "input_path": str(tmp_path / "sample.bin"),
                "database_path": str(tmp_path / "sample.i64"),
                "alias": "sample",
                "run_auto_analysis": False,
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["job_id"] == "job_123"
    assert result["status"] == "queued"
    assert result["job"]["job_id"] == "job_123"
    assert manager.open_calls == [
        {
            "input_path": str(tmp_path / "sample.bin"),
            "run_auto_analysis": False,
            "session_id": None,
            "alias": "sample",
            "database_path": str(tmp_path / "sample.i64"),
            "context_id": "ctx_abc",
        }
    ]


def test_daemon_jobs_get_returns_job(monkeypatch):
    manager = _FakeManager()
    manager.submit_open_job(Path("/tmp/sample.bin"), context_id="ctx_abc", alias="sample")
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        result = client.daemon_request(
            "GET",
            "/v1/jobs/job_123",
            None,
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["job"]["job_id"] == "job_123"


def test_daemon_jobs_list_returns_jobs(monkeypatch):
    manager = _FakeManager()
    manager.submit_open_job(Path("/tmp/sample.bin"), context_id="ctx_abc", alias="sample")
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        result = client.daemon_request(
            "GET",
            "/v1/jobs",
            None,
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["count"] == 1
    assert result["items"][0]["job_id"] == "job_123"


def test_daemon_funcs_disasm_resolves_name_and_normalizes_dict_output(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(
        idap_daemon,
        "lookup_funcs",
        lambda query: [
            {
                "query": query,
                "fn": {"addr": "0x401000", "name": "main", "size": "0x10"},
                "error": None,
            }
        ],
    )
    monkeypatch.setattr(
        idap_daemon,
        "disasm",
        lambda query, max_instructions=0, offset=0, include_total=False: {
            "asm": {"text": f"disasm for {query}"},
            "error": None,
        },
    )
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "funcs.disasm",
                "args": {"query": "main", "limit": 10, "offset": 0},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert manager.activated_contexts == ["ctx_abc"]
    assert result["text"] == "disasm for 0x401000"
    assert result["line_count"] == 1
    assert result["truncated"] is False


def test_daemon_funcs_callers_returns_collection(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(
        idap_daemon,
        "lookup_funcs",
        lambda query: [
            {
                "query": query,
                "fn": {"addr": "0x401000", "name": "main", "size": "0x10"},
                "error": None,
            }
        ],
    )
    monkeypatch.setattr(
        idap_daemon,
        "get_callers",
        lambda query, limit=50: [{"addr": "0x402000", "name": "caller"}],
    )
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "funcs.callers",
                "args": {"query": "main", "limit": 10, "offset": 0},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["count"] == 1
    assert result["items"][0]["name"] == "caller"


def test_daemon_funcs_list_preserves_backend_paging(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(
        idap_daemon,
        "func_query",
        lambda query: [
            {
                "data": [{"addr": "0x401000", "name": "main", "size": "0x10", "has_type": True}],
                "next_offset": 25,
                "total": None,
            }
        ],
    )
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "funcs.list",
                "args": {"limit": 25, "offset": 0, "page": None, "select": ["addr", "name"]},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["count"] == 1
    assert result["limit"] == 25
    assert result["next_offset"] == 25
    assert result["total"] is None
    assert result["paged"] is True
    assert result["remaining"] is None
    assert result["remaining_estimate"] == "unknown_more"
    assert result["page_status"] == "partial_unknown_remaining"
    assert result["items"] == [{"addr": "0x401000", "name": "main"}]


def test_daemon_funcs_list_calls_filter_uses_full_result_set(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    calls: list[dict] = []

    def fake_func_query(query):
        calls.append(dict(query))
        if query["count"] == 0:
            return [
                {
                    "data": [
                        {"addr": "0x402000", "name": "target", "size": "0x10", "has_type": True},
                        {"addr": "0x401000", "name": "other", "size": "0x10", "has_type": True},
                    ],
                    "next_offset": None,
                    "total": 2,
                }
            ]
        return [{"data": [], "next_offset": None, "total": None}]

    monkeypatch.setattr(idap_daemon, "func_query", fake_func_query)
    monkeypatch.setattr(
        idap_daemon,
        "lookup_funcs",
        lambda query: [{"query": query, "fn": {"addr": "0x500000"}, "error": None}],
    )
    monkeypatch.setattr(
        idap_daemon._Handler,
        "_filter_funcs_by_calls",
        lambda self, items, calls, call_match: [item for item in items if item["name"] == "target"],
    )
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "funcs.list",
                "args": {"limit": 25, "offset": 0, "calls": ["recv"], "call_match": "any"},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert calls == [{"offset": 0, "count": 0}]
    assert result["count"] == 1
    assert result["items"][0]["name"] == "target"


def test_daemon_types_list_query_uses_full_result_set(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    calls: list[dict] = []

    def fake_type_query(query):
        calls.append(dict(query))
        if query["count"] == 0:
            return [
                {
                    "data": [
                        {"name": "alpha_struct", "kind": "struct", "size": 8},
                        {"name": "target_struct", "kind": "struct", "size": 16},
                    ],
                    "next_offset": None,
                    "total": 2,
                }
            ]
        return [{"data": [{"name": "alpha_struct", "kind": "struct", "size": 8}], "next_offset": 25, "total": None}]

    monkeypatch.setattr(idap_daemon, "type_query", fake_type_query)
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "types.list",
                "args": {"count": 25, "offset": 0, "query_terms": ["name:target*"]},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert calls[0]["count"] == 0
    assert result["count"] == 1
    assert result["items"][0]["name"] == "target_struct"


def test_daemon_globals_list_query_uses_full_result_set(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    calls: list[dict] = []

    def fake_entity_query(query):
        calls.append(dict(query))
        if query["count"] == 0:
            return [
                {
                    "data": [
                        {"addr": "0x10", "name": "alpha"},
                        {"addr": "0x20", "name": "target_global"},
                    ],
                    "next_offset": None,
                    "total": 2,
                }
            ]
        return [{"data": [{"addr": "0x10", "name": "alpha"}], "next_offset": 25, "total": None}]

    monkeypatch.setattr(idap_daemon, "entity_query", fake_entity_query)
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "globals.list",
                "args": {"limit": 25, "offset": 0, "query": ["name:target*"]},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert calls[0]["count"] == 0
    assert result["count"] == 1
    assert result["items"][0]["name"] == "target_global"


def test_daemon_search_regex_forwards_limit_and_offset(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    captured = {}

    def fake_find_regex(pattern, limit, offset):
        captured.update({"pattern": pattern, "limit": limit, "offset": offset})
        return {
            "matches": [{"addr": "0x401000", "string": "hello"}],
            "cursor": {"next": 230},
        }

    monkeypatch.setattr(idap_daemon, "find_regex", fake_find_regex)
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "search.regex",
                "args": {"pattern": "hello", "limit": 30, "offset": 200},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert captured == {"pattern": "hello", "limit": 30, "offset": 200}
    assert result["limit"] == 30
    assert result["offset"] == 200
    assert result["next_offset"] == 230
    assert result["paged"] is True
    assert result["remaining"] is None
    assert result["remaining_estimate"] == "unknown_more"


def test_daemon_search_refs_preserves_zero_limit(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(
        idap_daemon,
        "find",
        lambda ref_type, target, limit=1000, offset=0: [
            {"query": target, "matches": ["0x10", "0x20", "0x30"], "cursor": {"done": True}},
        ],
    )
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "search.refs",
                "args": {"ref_type": "code_ref", "target": "main", "limit": 0, "offset": 0},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["limit"] == 0
    assert result["count"] == 3
    assert result["next_offset"] is None


def test_daemon_search_refs_forwards_limit_and_offset(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    captured = {}

    def fake_find(ref_type, target, limit=1000, offset=0):
        captured.update({"ref_type": ref_type, "target": target, "limit": limit, "offset": offset})
        return [
            {
                "query": target,
                "matches": ["0x20", "0x30"],
                "cursor": {"next": 3},
            }
        ]

    monkeypatch.setattr(idap_daemon, "find", fake_find)
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "search.refs",
                "args": {"ref_type": "code_ref", "target": "main", "limit": 2, "offset": 1},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert captured == {"ref_type": "code_ref", "target": "main", "limit": 2, "offset": 1}
    assert result["offset"] == 1
    assert result["count"] == 2
    assert result["next_offset"] == 3


def test_daemon_search_bytes_reports_more(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(
        idap_daemon._Handler,
        "_search_bytes",
        lambda self, pattern, *, limit, offset: (
            [{"pattern": pattern, "addr": "0x10"}, {"pattern": pattern, "addr": "0x20"}],
            True,
        ),
    )
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "search.bytes",
                "args": {"pattern": "48 8B ??", "limit": 2, "offset": 4},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["offset"] == 4
    assert result["count"] == 2
    assert result["next_offset"] == 6
    assert result["has_more"] is True
    assert result["paged"] is True
    assert result["remaining"] is None
    assert result["remaining_estimate"] == "unknown_more"


def test_daemon_funcs_callers_applies_offset_after_full_result(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(
        idap_daemon,
        "lookup_funcs",
        lambda query: [{"query": query, "fn": {"addr": "0x401000"}, "error": None}],
    )
    captured = {}

    def fake_get_callers(query, limit=50):
        captured.update({"query": query, "limit": limit})
        return [
            {"addr": "0x10", "name": "a"},
            {"addr": "0x20", "name": "b"},
            {"addr": "0x30", "name": "c"},
        ]

    monkeypatch.setattr(idap_daemon, "get_callers", fake_get_callers)
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "funcs.callers",
                "args": {"query": "main", "limit": 1, "offset": 1},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert captured == {"query": "0x401000", "limit": 0}
    assert result["items"] == [{"addr": "0x20", "name": "b"}]
    assert result["next_offset"] == 2


def test_daemon_imports_list_supports_imported_name_select_and_name_query(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(
        idap_daemon,
        "entity_query",
        lambda query: [
            {
                "data": [
                    {"addr": "0x10", "name": "puts", "imported_name": "puts", "module": "libc.so"},
                    {"addr": "0x20", "name": "printf", "imported_name": "printf", "module": "libc.so"},
                ],
                "next_offset": None,
                "total": 2,
            }
        ],
    )
    try:
        result = client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "imports.list",
                "args": {
                    "limit": 20,
                    "offset": 0,
                    "query": ["name:put*"],
                    "select": ["imported_name", "module"],
                },
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result["items"] == [{"imported_name": "puts", "module": "libc.so"}]
    assert result["count"] == 1
def test_daemon_session_save_endpoint_binds_requested_session(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(idap_daemon.ida_loader, "save_database", lambda path, flags: True)
    monkeypatch.setattr(idap_daemon.ida_loader, "get_path", lambda _kind: "/tmp/default.i64")
    try:
        result = client.daemon_request(
            "POST",
            "/v1/sessions/sess9/save",
            {"context_id": "ctx_abc", "path": "/tmp/out.i64"},
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert result == {"ok": True, "path": "/tmp/out.i64"}
    assert manager.saved_binds == [("ctx_abc", "sess9", True)]


def test_daemon_rename_maps_target_and_new_name(monkeypatch):
    manager = _FakeManager()
    server, thread, info = _start_server(monkeypatch, manager)
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    captured = {}
    monkeypatch.setattr(
        idap_daemon,
        "rename",
        lambda batch: captured.setdefault("batch", batch) or {"ok": True},
    )
    try:
        client.daemon_request(
            "POST",
            "/v1/invoke",
            {
                "context_id": "ctx_abc",
                "command": "rename",
                "args": {"target": "0x1234", "new_name": "renamed_main"},
            },
            autostart=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert captured["batch"] == {
        "func": [{"addr": "0x1234", "name": "renamed_main"}]
    }


def test_daemon_returns_timeout_error_for_executor_timeout(monkeypatch):
    manager = _FakeManager()
    monkeypatch.setattr(idap_daemon, "get_session_manager", lambda: manager)
    server = idap_daemon._DaemonServer(("127.0.0.1", 0), idap_daemon._Handler)
    server.executor = _TimeoutExecutor()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    info = {
        "host": server.server_address[0],
        "port": server.server_address[1],
        "token": server.token,
    }
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    try:
        with pytest.raises(client.DaemonClientError, match="Timed out waiting for executor task"):
            client.daemon_request(
                "POST",
                "/v1/invoke",
                {
                    "context_id": "ctx_abc",
                    "command": "sessions.current",
                    "args": {},
                },
                autostart=False,
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)


def test_main_thread_executor_cancels_queued_task_before_start():
    executor = idap_daemon._MainThreadExecutor()
    started = threading.Event()

    def task():
        started.set()
        return "ok"

    with pytest.raises(TimeoutError, match="Timed out waiting for executor task"):
        executor.submit_sync("test", task, timeout=0.01)

    queued_task = executor._queue.get_nowait()
    assert queued_task.cancelled.is_set() is True
    assert started.is_set() is False
