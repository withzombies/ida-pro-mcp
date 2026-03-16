#!/usr/bin/env sh
set -eu

mode="${1:-all}"

fast_args="tests/test_cli_main.py tests/test_cli_helpers.py tests/test_daemon.py tests/test_client.py tests/test_querying.py tests/test_idalib_session_manager.py tests/test_integrations.py tests/test_state.py"
live_args="tests/test_cli_live_e2e.py"

case "$mode" in
  fast)
    exec uv run --with pytest pytest -q $fast_args
    ;;
  live)
    exec uv run --with pytest pytest -q $live_args
    ;;
  all)
    exec uv run --with pytest pytest -q $fast_args $live_args
    ;;
  *)
    echo "usage: scripts/test-idap.sh [fast|live|all]" >&2
    exit 2
    ;;
esac
