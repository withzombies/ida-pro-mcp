import json

import pytest

from ida_pro_mcp.integrations import (
    claude_hooks_payload,
    generic_bootstrap_payload,
    generic_bootstrap_text,
    install_claude_skill,
    install_codex_skill,
    install_claude_hooks,
    install_opencode_bootstrap,
    install_pi_bootstrap,
    skill_doctor,
    skill_show,
)


pytestmark = pytest.mark.fast


def test_install_claude_hooks_creates_and_merges(tmp_path):
    config_path = tmp_path / ".claude.json"
    config_path.write_text(json.dumps({"numStartups": 1}), encoding="utf-8")

    result = install_claude_hooks(config_path)
    data = json.loads(config_path.read_text(encoding="utf-8"))

    assert result["changed"] is True
    assert data["numStartups"] == 1
    assert data["hooks"]["SessionStart"] == claude_hooks_payload()["hooks"]["SessionStart"]
    assert data["hooks"]["SubagentStart"] == claude_hooks_payload()["hooks"]["SubagentStart"]


def test_install_claude_hooks_is_idempotent(tmp_path):
    config_path = tmp_path / ".claude.json"
    install_claude_hooks(config_path)

    result = install_claude_hooks(config_path)
    data = json.loads(config_path.read_text(encoding="utf-8"))

    assert result["changed"] is False
    assert "hooks" in data


def test_generic_bootstrap_text_mentions_parent_and_subagent():
    text = generic_bootstrap_text()
    assert "force-new" in text
    assert "parent agent" in text


def test_generic_bootstrap_payload_is_machine_readable():
    payload = generic_bootstrap_payload()

    assert payload["parent"] == 'eval "$(idap context ensure --shell)"'
    assert payload["subagent"] == 'eval "$(idap context ensure --shell --force-new)"'


def test_install_codex_skill_writes_when_home_exists(tmp_path):
    codex_home = tmp_path / ".codex"

    result = install_codex_skill(codex_home)

    assert result["mode"] in {"symlink", "copy"}
    assert result["detected"] is True
    assert (codex_home / "skills" / "idap" / "SKILL.md").exists()
    assert result["source"].endswith("skills/idap")


def test_install_claude_skill_writes_project_local_skill(tmp_path):
    result = install_claude_skill(tmp_path)

    assert result["mode"] in {"symlink", "copy"}
    assert result["detected"] is True
    assert (tmp_path / ".claude" / "skills" / "idap" / "SKILL.md").exists()


def test_install_opencode_bootstrap_returns_not_found_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))

    result = install_opencode_bootstrap()

    assert result["mode"] == "not-found"
    assert result["detected"] is False


def test_install_pi_bootstrap_writes_when_config_exists(tmp_path):
    config_dir = tmp_path / "pi"
    config_dir.mkdir()

    result = install_pi_bootstrap(config_dir)

    assert result["mode"] == "patched"
    assert result["detected"] is True
    assert (config_dir / "idap-bootstrap.sh").exists()


def test_skill_show_reports_agent_targets():
    result = skill_show("all")

    assert result["source"].endswith("skills/idap")
    assert result["agents"]["claude"]["target"].endswith(".claude/skills/idap")
    assert result["agents"]["codex"]["target"].endswith(".codex/skills/idap")


def test_skill_doctor_checks_expected_files():
    result = skill_doctor()

    assert result["checks"]["skill"]["exists"] is True
    assert result["checks"]["openai_yaml"]["exists"] is True
    assert result["checks"]["codex_bridge"]["exists"] is True
