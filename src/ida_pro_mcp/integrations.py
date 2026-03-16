"""Helpers for agent integration snippets and config installation."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any


def claude_config_path() -> Path:
    return Path.home() / ".claude.json"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def repo_skill_dir() -> Path:
    return repo_root() / "skills" / "idap"


def claude_project_skill_path(project_dir: Path | None = None) -> Path:
    root = project_dir or repo_root()
    return root / ".claude" / "skills" / "idap"


def claude_hooks_payload() -> dict[str, Any]:
    return {
        "hooks": {
            "SessionStart": [
                {
                    "type": "command",
                    "command": 'eval "$(idap context ensure --shell)"',
                }
            ],
            "SubagentStart": [
                {
                    "type": "command",
                    "command": 'eval "$(idap context ensure --shell --force-new)"',
                }
            ],
        }
    }


def generic_bootstrap_text() -> str:
    payload = generic_bootstrap_payload()
    return "\n".join(
        [
            "# parent agent bootstrap",
            payload["parent"],
            "",
            "# subagent bootstrap",
            payload["subagent"],
        ]
    )


def generic_bootstrap_payload() -> dict[str, str]:
    return {
        "parent": 'eval "$(idap context ensure --shell)"',
        "subagent": 'eval "$(idap context ensure --shell --force-new)"',
    }


def install_claude_hooks(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or claude_config_path()
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {}

    desired = claude_hooks_payload()["hooks"]
    hooks = data.setdefault("hooks", {})
    changed = False

    for event_name, commands in desired.items():
        event_list = hooks.setdefault(event_name, [])
        for command in commands:
            if command not in event_list:
                event_list.append(command)
                changed = True

    if changed or not path.exists():
        path.write_text(json.dumps(data, indent=2) + os.linesep, encoding="utf-8")

    return {
        "path": str(path),
        "changed": changed,
        "hooks": desired,
    }


def codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))


def skill_show(agent: str = "all") -> dict[str, Any]:
    source = repo_skill_dir()
    payload = {
        "source": str(source),
        "bootstrap": generic_bootstrap_payload(),
        "agents": {},
    }
    if agent in {"claude", "all"}:
        payload["agents"]["claude"] = {
            "target": str(claude_project_skill_path()),
            "mode": "project-local-skill",
        }
    if agent in {"codex", "all"}:
        payload["agents"]["codex"] = {
            "target": str(codex_home() / "skills" / "idap"),
            "mode": "codex-home-skill",
            "bridge": str(repo_root() / "AGENTS.md"),
        }
    return payload


def skill_doctor() -> dict[str, Any]:
    source = repo_skill_dir()
    required = {
        "skill": source / "SKILL.md",
        "openai_yaml": source / "agents" / "openai.yaml",
        "cli_reference": source / "references" / "cli.md",
        "context_reference": source / "references" / "context-and-sessions.md",
        "workflow_reference": source / "references" / "workflows.md",
        "troubleshooting_reference": source / "references" / "troubleshooting.md",
        "bootstrap_script": source / "scripts" / "idap-bootstrap.sh",
        "codex_bridge": repo_root() / "AGENTS.md",
    }
    checks = {
        name: {"path": str(path), "exists": path.exists()}
        for name, path in required.items()
    }
    return {
        "source": str(source),
        "ok": all(item["exists"] for item in checks.values()),
        "checks": checks,
    }


def codex_skill_payload() -> str:
    bootstrap = generic_bootstrap_payload()
    return "\n".join(
        [
            "# idap bootstrap",
            "",
            "Before using `idap` in a parent agent session:",
            f"- Run `{bootstrap['parent']}` once, then reuse that context across later commands.",
            "",
            "Before using `idap` in a subagent session:",
            f"- `{bootstrap['subagent']}`",
            "",
            "Use the shared daemon and rely on the per-agent context binding.",
            "Fresh Codex shells will reuse the cached parent context unless `--force-new` is used.",
        ]
    ) + os.linesep


def install_claude_skill(project_dir: Path | None = None, *, prefer_link: bool = True) -> dict[str, Any]:
    source = repo_skill_dir()
    target = claude_project_skill_path(project_dir)
    changed, mode = _install_tree(source, target, prefer_link=prefer_link)
    return _installer_result(
        provider="claude-skill",
        mode=mode,
        detected=True,
        path=target,
        changed=changed,
        source=source,
    )


def install_codex_skill(base_dir: Path | None = None, *, prefer_link: bool = True) -> dict[str, Any]:
    root = base_dir or codex_home()
    target = root / "skills" / "idap"
    source = repo_skill_dir()
    changed, mode = _install_tree(source, target, prefer_link=prefer_link)
    return _installer_result(
        provider="codex",
        mode=mode,
        detected=True,
        path=target,
        changed=changed,
        source=source,
    )


def install_opencode_bootstrap(config_dir: Path | None = None) -> dict[str, Any]:
    root = config_dir or _first_existing_path(
        [Path.home() / ".config" / "opencode", Path.home() / ".opencode"]
    )
    if root is None:
        return _installer_result(
            provider="opencode",
            mode="not-found",
            detected=False,
            path=Path.home() / ".config" / "opencode" / "idap-bootstrap.sh",
        )
    target = root / "idap-bootstrap.sh"
    changed = _write_text_if_changed(target, _shell_bootstrap_script("opencode"))
    return _installer_result(
        provider="opencode",
        mode="patched",
        detected=True,
        path=target,
        changed=changed,
    )


def install_pi_bootstrap(config_dir: Path | None = None) -> dict[str, Any]:
    root = config_dir or _first_existing_path(
        [Path.home() / ".config" / "pi", Path.home() / ".pi"]
    )
    if root is None:
        return _installer_result(
            provider="pi",
            mode="not-found",
            detected=False,
            path=Path.home() / ".config" / "pi" / "idap-bootstrap.sh",
        )
    target = root / "idap-bootstrap.sh"
    changed = _write_text_if_changed(target, _shell_bootstrap_script("pi"))
    return _installer_result(
        provider="pi",
        mode="patched",
        detected=True,
        path=target,
        changed=changed,
    )


def install_generic_provider(provider: str) -> dict[str, Any]:
    return _installer_result(
        provider=provider,
        mode="template-only",
        detected=False,
        path=None,
    )


def _shell_bootstrap_script(provider: str) -> str:
    bootstrap = generic_bootstrap_payload()
    return "\n".join(
        [
            "#!/usr/bin/env sh",
            f"# {provider} idap bootstrap",
            bootstrap["parent"],
        ]
    ) + os.linesep


def _write_text_if_changed(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def _install_tree(source: Path, target: Path, *, prefer_link: bool) -> tuple[bool, str]:
    if not source.exists():
        raise FileNotFoundError(f"Skill source does not exist: {source}")

    target.parent.mkdir(parents=True, exist_ok=True)
    if prefer_link:
        try:
            if target.is_symlink() and target.resolve() == source.resolve():
                return False, "symlink"
            if target.exists() or target.is_symlink():
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            target.symlink_to(source, target_is_directory=True)
            return True, "symlink"
        except OSError:
            pass

    changed = _copy_tree_if_changed(source, target)
    return changed, "copy"


def _copy_tree_if_changed(source: Path, target: Path) -> bool:
    if target.exists():
        same = True
        for path in source.rglob("*"):
            rel = path.relative_to(source)
            target_path = target / rel
            if path.is_dir():
                if not target_path.exists() or not target_path.is_dir():
                    same = False
                    break
                continue
            if not target_path.exists() or target_path.read_bytes() != path.read_bytes():
                same = False
                break
        if same:
            for path in target.rglob("*"):
                if not (source / path.relative_to(target)).exists():
                    same = False
                    break
        if same:
            return False
        shutil.rmtree(target)
    shutil.copytree(source, target)
    return True


def _first_existing_path(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def _installer_result(
    *,
    provider: str,
    mode: str,
    detected: bool,
    path: Path | None,
    source: Path | None = None,
    changed: bool = False,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "mode": mode,
        "detected": detected,
        "changed": changed,
        "source": str(source) if source is not None else "",
        "path": str(path) if path is not None else "",
        "bootstrap": generic_bootstrap_payload(),
        "instructions": generic_bootstrap_text(),
    }
