from pathlib import Path

import pytest

from ida_pro_mcp import state


pytestmark = pytest.mark.fast


def test_daemon_log_path_lives_in_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))

    expected = tmp_path / "idap" / "daemon.log"

    assert state.daemon_log_path() == expected
    assert state.daemon_log_path().parent == state.ensure_state_dir()
    assert state.daemon_log_path().name == "daemon.log"
    assert isinstance(state.daemon_log_path(), Path)


def test_current_context_path_lives_in_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))

    expected = tmp_path / "idap" / "current-context.json"

    assert state.current_context_path() == expected
    assert state.current_context_path().parent == state.ensure_state_dir()


def test_write_json_replaces_file_atomically(tmp_path):
    path = tmp_path / "state.json"

    state.write_json(path, {"value": 1})

    assert path.exists()
    assert state.read_json(path) == {"value": 1}
    assert list(tmp_path.glob(".*.tmp")) == []


def test_read_json_returns_none_for_invalid_json(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{broken", encoding="utf-8")

    assert state.read_json(path) is None
