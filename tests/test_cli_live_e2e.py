import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEST_BINARY = ROOT / "tests" / "crackme03.elf"
SYSTEM_BINARY = Path("/bin/ls")


def _run_idap(args: list[str], *, env: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ida_pro_mcp.cli", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=True,
    )


@pytest.mark.live_idap
@pytest.mark.skipif(not TEST_BINARY.exists(), reason="live test binary not present")
def test_cli_live_e2e_against_test_elf(tmp_path):
    env = os.environ.copy()
    env["XDG_STATE_HOME"] = str(tmp_path)

    crackme_database_path = tmp_path / "crackme03.i64"
    ls_database_path = tmp_path / "ls.i64"
    saved_database_path = tmp_path / "crackme_saved.i64"

    try:
        _run_idap(["daemon", "stop", "--all"], env=env, timeout=30)

        open_result = json.loads(
            _run_idap(
                [
                    "--json",
                    "sessions",
                    "open",
                    str(TEST_BINARY),
                    "--wait",
                    "--database-path",
                    str(crackme_database_path),
                    "--alias",
                    "crackme",
                ],
                env=env,
            ).stdout
        )
        assert open_result["job"]["status"] == "succeeded"
        assert open_result["job"]["database_path"] == str(crackme_database_path)
        assert open_result["job"]["session_id"]

        daemon_status = json.loads(_run_idap(["--json", "daemon", "status"], env=env).stdout)
        assert daemon_status["session_count"] >= 1
        assert daemon_status["context_count"] >= 1

        if SYSTEM_BINARY.exists():
            ls_open_result = json.loads(
                _run_idap(
                    [
                        "--json",
                        "sessions",
                        "open",
                        str(SYSTEM_BINARY),
                        "--wait",
                        "--database-path",
                        str(ls_database_path),
                        "--alias",
                        "ls",
                        "--no-analysis",
                    ],
                    env=env,
                ).stdout
            )
            assert ls_open_result["job"]["status"] == "succeeded"
            assert ls_open_result["job"]["database_path"] == str(ls_database_path)
            assert ls_open_result["job"]["session_id"]

        sessions_result = json.loads(
            _run_idap(["--json", "sessions", "list"], env=env).stdout
        )
        assert sessions_result["count"] >= 1
        assert any(item["is_current_context"] for item in sessions_result["items"])

        contexts_result = json.loads(
            _run_idap(["--json", "context", "list"], env=env).stdout
        )
        assert contexts_result["count"] >= 1
        assert contexts_result["items"][0]["context_id"].startswith("ctx_")

        session_info = json.loads(
            _run_idap(["--json", "sessions", "info", "crackme"], env=env).stdout
        )
        assert session_info["session"]["alias"] == "crackme"

        if SYSTEM_BINARY.exists():
            use_result = _run_idap(["sessions", "use", "crackme"], env=env).stdout
            assert "context_id:" in use_result

        show_result = _run_idap(["funcs", "show", "main"], env=env).stdout
        assert "main" in show_result
        assert "0x123e" in show_result

        funcs_list_result = json.loads(
            _run_idap(
                ["--json", "funcs", "list", "--name-regex", "main|check_pw", "--min-size", "1"],
                env=env,
            ).stdout
        )
        assert funcs_list_result["count"] >= 1

        disasm_result = json.loads(
            _run_idap(["--json", "funcs", "disasm", "main", "--summary"], env=env).stdout
        )
        assert "main (.text @ 0x123e):" in disasm_result["text"]
        assert disasm_result["truncated"] is True

        callers_result = json.loads(
            _run_idap(["--json", "funcs", "callers", "check_pw"], env=env).stdout
        )
        assert callers_result["count"] >= 1

        xrefs_result = json.loads(
            _run_idap(
                ["--json", "xrefs", "check_pw", "--direction", "to", "--type", "code"],
                env=env,
            ).stdout
        )
        assert xrefs_result["count"] >= 1
        assert all(item["direction"] == "to" for item in xrefs_result["items"])
        assert all(item["type"] == "code" for item in xrefs_result["items"])
        check_pw_addr = xrefs_result["items"][0]["to"]

        xrefs_alias_result = json.loads(
            _run_idap(["--json", "xrefs", "to", "check_pw"], env=env).stdout
        )
        assert xrefs_alias_result["count"] >= 1

        imports_result = json.loads(
            _run_idap(
                ["--json", "imports", "list", "--module", "*", "--regex", ".*"],
                env=env,
            ).stdout
        )
        assert imports_result["count"] >= 1

        decompile_result = json.loads(
            _run_idap(["--json", "funcs", "decompile", "main", "--summary"], env=env).stdout
        )
        assert "int __fastcall main" in decompile_result["text"]
        assert decompile_result["truncated"] is True

        warmup_result = _run_idap(
            ["sessions", "warmup", "--no-build-caches", "--no-init-hexrays"],
            env=env,
        ).stdout
        assert "warmup:" in warmup_result

        jsonl_result = _run_idap(
            ["funcs", "list", "--limit", "3", "--format", "jsonl"],
            env=env,
        ).stdout.splitlines()
        assert len(jsonl_result) == 3
        first_row = json.loads(jsonl_result[0])
        assert "name" in first_row
        assert "addr" in first_row

        rename_result = _run_idap(["rename", "0x123e", "crackme_main"], env=env).stdout
        assert "crackme_main" in rename_result
        assert "ok: true" in rename_result.lower()

        rename_batch_path = tmp_path / "rename-batch.json"
        rename_batch_path.write_text(
            json.dumps({"func": [{"addr": "0x123e", "name": "crackme_main2"}], "dry_run": True}),
            encoding="utf-8",
        )
        rename_batch_result = _run_idap(
            ["rename", "--from-json", str(rename_batch_path)],
            env=env,
        ).stdout
        assert "dry_run: true" in rename_batch_result.lower()

        renamed_show_result = _run_idap(["funcs", "show", "crackme_main"], env=env).stdout
        assert "crackme_main" in renamed_show_result
        assert "0x123e" in renamed_show_result

        comment_result = _run_idap(
            ["comment", "set", "0x123e", "stage2-comment"],
            env=env,
        ).stdout
        assert "0x123e" in comment_result
        assert "true" in comment_result

        comment_batch_path = tmp_path / "comment-batch.json"
        comment_batch_path.write_text(
            json.dumps([{"addr": "0x123e", "comment": "stage2-comment-batch"}]),
            encoding="utf-8",
        )
        comment_batch_result = _run_idap(
            ["comment", "set", "--from-json", str(comment_batch_path)],
            env=env,
        ).stdout
        assert "0x123e" in comment_batch_result

        py_eval_result = _run_idap(
            ["py", "eval", "import idc; print(idc.get_cmt(0x123e, 0))"],
            env=env,
        ).stdout
        assert "stage2-comment-batch" in py_eval_result

        search_regex_result = json.loads(
            _run_idap(["--json", "search", "regex", "."], env=env).stdout
        )
        assert search_regex_result["count"] >= 1

        search_bytes_result = json.loads(
            _run_idap(["--json", "search", "bytes", "7F 45 4C 46", "--limit", "1"], env=env).stdout
        )
        assert search_bytes_result["count"] >= 1

        search_refs_result = json.loads(
            _run_idap(["--json", "search", "refs", "code_ref", check_pw_addr, "--limit", "10"], env=env).stdout
        )
        assert search_refs_result["count"] >= 1

        save_result = _run_idap(
            [
                "sessions",
                "save",
                str(saved_database_path),
                "--session-ref",
                "crackme",
            ],
            env=env,
        ).stdout
        assert "ok: true" in save_result
        assert saved_database_path.exists()

        log_tail_result = json.loads(
            _run_idap(["--json", "daemon", "logs", "--tail", "5"], env=env).stdout
        )
        assert log_tail_result["log_path"]
        assert isinstance(log_tail_result["lines"], list)
    finally:
        _run_idap(["daemon", "stop", "--all"], env=env, timeout=30)
