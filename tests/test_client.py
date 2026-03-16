import pytest

from ida_pro_mcp import client


pytestmark = pytest.mark.fast

def test_daemon_matches_client_checks_fingerprint(monkeypatch):
    monkeypatch.setattr(client, "code_fingerprint", lambda: "abc123")
    assert client._daemon_matches_client({"fingerprint": "abc123"}) is True
    assert client._daemon_matches_client({"fingerprint": "zzz"}) is False


def test_ensure_daemon_running_rejects_live_fingerprint_mismatch(monkeypatch):
    info = {"pid": 123, "fingerprint": "old", "host": "127.0.0.1", "port": 1}
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(client, "_daemon_alive", lambda loaded: loaded is info)
    monkeypatch.setattr(client, "code_fingerprint", lambda: "new")

    with pytest.raises(client.DaemonClientError, match="different code fingerprint"):
        client.ensure_daemon_running()


def test_ensure_daemon_running_removes_stale_mismatched_state(monkeypatch):
    info = {"pid": 123, "fingerprint": "old", "host": "127.0.0.1", "port": 1}
    removed = []
    monkeypatch.setattr(client, "load_daemon_info", lambda: info)
    monkeypatch.setattr(client, "_daemon_alive", lambda loaded: False)
    monkeypatch.setattr(client, "code_fingerprint", lambda: "new")
    monkeypatch.setattr(client, "remove_file", lambda path: removed.append(path))
    monkeypatch.setattr(client.subprocess, "Popen", lambda *args, **kwargs: None)
    monkeypatch.setattr(client.time, "sleep", lambda _secs: None)
    started = {"value": False}

    def load_after_start():
        if started["value"]:
            return {"pid": 999, "fingerprint": "new", "host": "127.0.0.1", "port": 9}
        started["value"] = True
        return info

    monkeypatch.setattr(client, "load_daemon_info", load_after_start)
    monkeypatch.setattr(client, "_daemon_alive", lambda loaded: loaded.get("pid") == 999)

    result = client.ensure_daemon_running(timeout=0.1)

    assert result["pid"] == 999
    assert removed == [client.daemon_state_path()]


def test_resolve_request_timeout_defaults_to_none(monkeypatch):
    monkeypatch.delenv("IDAP_DAEMON_HTTP_TIMEOUT_SEC", raising=False)
    assert client._resolve_request_timeout(None) is None


def test_resolve_request_timeout_uses_positive_override(monkeypatch):
    monkeypatch.setenv("IDAP_DAEMON_HTTP_TIMEOUT_SEC", "15")
    assert client._resolve_request_timeout(None) == 15.0
    assert client._resolve_request_timeout(3.5) == 3.5
