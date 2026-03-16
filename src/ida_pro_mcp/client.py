"""Client helpers for talking to the local idap daemon."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .state import code_fingerprint, daemon_state_path, read_json, remove_file


class DaemonClientError(RuntimeError):
    pass


def ensure_daemon_running(timeout: float = 20.0) -> dict[str, Any]:
    info = load_daemon_info()
    if info and not _daemon_matches_client(info):
        if _daemon_alive(info):
            raise DaemonClientError(
                "idap daemon is running with a different code fingerprint. "
                "Stop it explicitly with 'idap daemon stop' before starting this checkout."
            )
        remove_file(daemon_state_path())
        info = None
    if info and _daemon_alive(info):
        return info
    if info is not None:
        remove_file(daemon_state_path())

    cmd = [sys.executable, "-m", "ida_pro_mcp.idap_daemon"]
    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        env=os.environ.copy(),
    )

    deadline = time.time() + timeout
    while time.time() < deadline:
        info = load_daemon_info()
        if info and _daemon_alive(info):
            return info
        time.sleep(0.2)
    raise DaemonClientError("Timed out waiting for idap daemon to start")


def load_daemon_info() -> dict[str, Any] | None:
    return read_json(daemon_state_path())


def daemon_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    autostart: bool = True,
    timeout: float | None = None,
) -> dict[str, Any]:
    info = ensure_daemon_running() if autostart else load_daemon_info()
    if info is None:
        raise DaemonClientError("idap daemon is not running")

    url = f"http://{info['host']}:{info['port']}{path}"
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {info['token']}",
            "Content-Type": "application/json",
        },
    )
    request_timeout = _resolve_request_timeout(timeout)
    try:
        with urllib.request.urlopen(req, timeout=request_timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            payload = json.loads(body)
        except Exception as parse_exc:
            raise DaemonClientError(body) from parse_exc
        raise DaemonClientError(payload.get("error", body))
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise DaemonClientError(
                f"idap daemon request timed out for {method} {path}"
            ) from exc
        raise DaemonClientError(str(exc.reason)) from exc
    except TimeoutError as exc:
        raise DaemonClientError(
            f"idap daemon request timed out for {method} {path}"
        ) from exc


def _resolve_request_timeout(timeout: float | None) -> float | None:
    if timeout is not None:
        return timeout if timeout > 0 else None
    raw = os.environ.get("IDAP_DAEMON_HTTP_TIMEOUT_SEC", "").strip()
    if raw == "":
        return None
    try:
        parsed = float(raw)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def _daemon_alive(info: dict[str, Any]) -> bool:
    try:
        with socket.create_connection((info["host"], int(info["port"])), timeout=0.5):
            return True
    except OSError:
        return False


def stop_daemon(*, stop_all: bool = False, timeout: float = 15.0) -> dict[str, Any]:
    info = load_daemon_info()
    stopped_pids: list[int] = []
    failed_pids: list[int] = []

    target_pids: list[int] = []
    if info is not None:
        target_pids.append(int(info["pid"]))
    if stop_all:
        for pid in _find_daemon_pids():
            if pid not in target_pids:
                target_pids.append(pid)

    for pid in target_pids:
        if _terminate_pid(pid, timeout=timeout):
            stopped_pids.append(pid)
        else:
            failed_pids.append(pid)

    if info is not None and (not failed_pids or int(info["pid"]) not in failed_pids):
        remove_file(daemon_state_path())

    return {
        "stopped": len(stopped_pids) > 0 and not failed_pids,
        "stopped_pids": stopped_pids,
        "failed_pids": failed_pids,
    }


def _terminate_pid(pid: int, *, timeout: float) -> bool:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_exists(pid):
            return True
        time.sleep(0.1)

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except OSError:
        return False

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_exists(pid):
            return True
        time.sleep(0.1)
    return False


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True


def _find_daemon_pids() -> list[int]:
    if os.name == "posix":
        try:
            output = subprocess.check_output(["ps", "-eo", "pid=,args="], text=True)
        except Exception:
            return []
        pids: list[int] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or "ida_pro_mcp.idap_daemon" not in line:
                continue
            pid_text, _, _cmd = line.partition(" ")
            try:
                pids.append(int(pid_text))
            except ValueError:
                continue
        return pids
    return []


def _daemon_matches_client(info: dict[str, Any]) -> bool:
    return info.get("fingerprint") == code_fingerprint()
