#!/usr/bin/env sh
set -eu

mode="${1:-parent}"

case "$mode" in
  parent)
    printf '%s\n' 'eval "$(idap context ensure --shell)"'
    ;;
  subagent)
    printf '%s\n' 'eval "$(idap context ensure --shell --force-new)"'
    ;;
  *)
    echo "usage: idap-bootstrap.sh [parent|subagent]" >&2
    exit 2
    ;;
esac
