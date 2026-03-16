"""Filesystem state helpers for idap."""

from __future__ import annotations

import json
import os
import hashlib
from pathlib import Path
from typing import Any


def state_dir() -> Path:
    root = os.environ.get("XDG_STATE_HOME")
    if root:
        return Path(root) / "idap"
    return Path.home() / ".local" / "state" / "idap"


def ensure_state_dir() -> Path:
    path = state_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def daemon_state_path() -> Path:
    return ensure_state_dir() / "daemon.json"


def daemon_log_path() -> Path:
    return ensure_state_dir() / "daemon.log"


def current_context_path() -> Path:
    return ensure_state_dir() / "current-context.json"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None


def remove_file(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def code_fingerprint() -> str:
    package_dir = Path(__file__).resolve().parent
    hasher = hashlib.sha256()
    for path in sorted(package_dir.rglob("*.py")):
        rel = path.relative_to(package_dir)
        stat = path.stat()
        hasher.update(str(rel).encode("utf-8"))
        hasher.update(str(stat.st_mtime_ns).encode("utf-8"))
        hasher.update(str(stat.st_size).encode("utf-8"))
    return hasher.hexdigest()[:16]
