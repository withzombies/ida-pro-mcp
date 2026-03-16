import importlib
import sys

import pytest


pytestmark = pytest.mark.fast


def test_session_manager_contexts_and_aliases(monkeypatch, tmp_path):
    class FakeIDAPro:
        def __init__(self):
            self.opened = []

        def open_database(self, path, run_auto_analysis=True, args=None):
            self.opened.append((path, run_auto_analysis, args))
            return False

        def close_database(self):
            self.opened.append(("close", False))

    fake_idapro = FakeIDAPro()

    monkeypatch.setitem(sys.modules, "idapro", fake_idapro)
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        type("FakeIDAAuto", (), {"auto_wait": staticmethod(lambda: None)}),
    )
    sys.modules.pop("ida_pro_mcp.idalib_session_manager", None)
    manager_module = importlib.import_module("ida_pro_mcp.idalib_session_manager")

    manager = manager_module.IDASessionManager()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")

    context = manager.ensure_context(force_new=True)
    session_id = manager.open_binary(sample, alias="sample")
    assert session_id == manager.resolve_session_id("sample")

    manager.bind_context(context.context_id, session_id, activate=True)
    sessions = manager.list_sessions(context.context_id)

    assert sessions[0]["alias"] == "sample"
    assert sessions[0]["is_current_context"] is True
    assert sessions[0]["bound_contexts"] == 1


def test_session_manager_open_job_creates_session(monkeypatch, tmp_path):
    class FakeIDAPro:
        def __init__(self):
            self.opened = []

        def open_database(self, path, run_auto_analysis=True, args=None):
            self.opened.append((path, run_auto_analysis, args))
            return False

        def close_database(self):
            self.opened.append(("close", False))

    fake_idapro = FakeIDAPro()

    monkeypatch.setitem(sys.modules, "idapro", fake_idapro)
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        type("FakeIDAAuto", (), {"auto_wait": staticmethod(lambda: None)}),
    )
    sys.modules.pop("ida_pro_mcp.idalib_session_manager", None)
    manager_module = importlib.import_module("ida_pro_mcp.idalib_session_manager")

    manager = manager_module.IDASessionManager()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")

    job = manager.submit_open_job(sample, context_id="ctx_test", alias="sample", run_auto_analysis=False)
    queued_job, plan = manager.prepare_open_job(job.job_id)
    assert queued_job.status == "queued"
    manager.mark_job_running(job.job_id)
    session = manager._execute_open_plan(plan)
    manager.bind_context("ctx_test", session.session_id, activate=False)
    completed = manager.mark_job_succeeded(job.job_id, session.session_id)

    assert completed.status == "succeeded"
    assert completed.session_id is not None
    assert manager.get_session(completed.session_id) is not None
    assert manager.get_context_session_id("ctx_test") == completed.session_id


def test_session_manager_stages_read_only_inputs(monkeypatch, tmp_path):
    class FakeIDAPro:
        def __init__(self):
            self.opened = []

        def open_database(self, path, run_auto_analysis=True, args=None):
            self.opened.append((path, run_auto_analysis, args))
            return False

        def close_database(self):
            return None

    fake_idapro = FakeIDAPro()

    monkeypatch.setitem(sys.modules, "idapro", fake_idapro)
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        type("FakeIDAAuto", (), {"auto_wait": staticmethod(lambda: None)}),
    )
    sys.modules.pop("ida_pro_mcp.idalib_session_manager", None)
    manager_module = importlib.import_module("ida_pro_mcp.idalib_session_manager")
    monkeypatch.setattr(manager_module, "ensure_state_dir", lambda: tmp_path)
    monkeypatch.setattr(manager_module.os, "access", lambda *_args: False)

    manager = manager_module.IDASessionManager()
    sample = tmp_path / "ro.bin"
    sample.write_bytes(b"MZ")

    session_id = manager.open_binary(sample, run_auto_analysis=False)
    session = manager.get_session(session_id)

    assert session is not None
    assert session.working_input_path != sample.resolve()
    assert session.working_input_path.exists()
    assert fake_idapro.opened[0][0] == str(session.working_input_path)


def test_session_manager_respects_database_path(monkeypatch, tmp_path):
    class FakeIDAPro:
        def __init__(self):
            self.calls = []

        def open_database(self, path, run_auto_analysis=True, args=None):
            self.calls.append((path, run_auto_analysis, args))
            return False

        def close_database(self):
            return None

    fake_idapro = FakeIDAPro()

    monkeypatch.setitem(sys.modules, "idapro", fake_idapro)
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        type("FakeIDAAuto", (), {"auto_wait": staticmethod(lambda: None)}),
    )
    sys.modules.pop("ida_pro_mcp.idalib_session_manager", None)
    manager_module = importlib.import_module("ida_pro_mcp.idalib_session_manager")

    manager = manager_module.IDASessionManager()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    database_path = tmp_path / "custom" / "sample.i64"

    session_id = manager.open_binary(
        sample,
        run_auto_analysis=False,
        database_path=database_path,
    )
    session = manager.get_session(session_id)

    assert session is not None
    assert session.database_path == database_path.resolve()
    assert fake_idapro.calls[0][0] == str(sample.resolve())
    assert fake_idapro.calls[0][2] == f"-o{database_path.resolve()}"


def test_session_manager_reopens_existing_database_path(monkeypatch, tmp_path):
    class FakeIDAPro:
        def __init__(self):
            self.calls = []

        def open_database(self, path, run_auto_analysis=True, args=None):
            self.calls.append((path, run_auto_analysis, args))
            return False

        def close_database(self):
            return None

    fake_idapro = FakeIDAPro()

    monkeypatch.setitem(sys.modules, "idapro", fake_idapro)
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        type("FakeIDAAuto", (), {"auto_wait": staticmethod(lambda: None)}),
    )
    sys.modules.pop("ida_pro_mcp.idalib_session_manager", None)
    manager_module = importlib.import_module("ida_pro_mcp.idalib_session_manager")

    manager = manager_module.IDASessionManager()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    database_path = tmp_path / "existing.i64"
    database_path.write_bytes(b"IDA")

    session_id = manager.open_binary(
        sample,
        run_auto_analysis=False,
        database_path=database_path,
    )
    session = manager.get_session(session_id)

    assert session is not None
    assert session.database_path == database_path.resolve()
    assert fake_idapro.calls[0][0] == str(database_path.resolve())
    assert fake_idapro.calls[0][2] is None


def test_release_context_removes_binding(monkeypatch, tmp_path):
    class FakeIDAPro:
        def open_database(self, path, run_auto_analysis=True, args=None):
            return False

        def close_database(self):
            return None

    monkeypatch.setitem(sys.modules, "idapro", FakeIDAPro())
    monkeypatch.setitem(
        sys.modules,
        "ida_auto",
        type("FakeIDAAuto", (), {"auto_wait": staticmethod(lambda: None)}),
    )
    sys.modules.pop("ida_pro_mcp.idalib_session_manager", None)
    manager_module = importlib.import_module("ida_pro_mcp.idalib_session_manager")

    manager = manager_module.IDASessionManager()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")

    context = manager.ensure_context(force_new=True)
    session_id = manager.open_binary(sample, run_auto_analysis=False)
    manager.bind_context(context.context_id, session_id)

    assert manager.get_context(context.context_id) is not None
    assert manager.get_context_session_id(context.context_id) == session_id
    assert manager.release_context(context.context_id) is True
    assert manager.get_context(context.context_id) is None
    assert manager.get_context_session_id(context.context_id) is None
    assert manager.release_context(context.context_id) is False
