#!/usr/bin/env bash
# ATT-2 /proc leg: emulate the action's env handling.
# This script stands in for run.ts's process env (which RETAINS
# ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN — parse-sdk-options.ts deletes them only
# from the copy handed to the Claude CLI subprocess).
# It spawns a child with the SAME strip the shipped code applies
# (parse-sdk-options.ts:289-290) and the child (standing in for the model's
# Bash tool under the CLI) tries to recover the vars from /proc ancestors.
set -u
echo "=== ATT2 /proc strip-bypass leg ==="
echo "parent(pid=$$) has ACTIONS_ID_TOKEN_REQUEST_TOKEN: $([ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] && echo YES || echo NO) len=${#ACTIONS_ID_TOKEN_REQUEST_TOKEN}"
echo "parent pid: $$"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Faithful strip: identical to parse-sdk-options.ts:289-290 (delete from the
# env COPY given to the child; parent keeps them).
env -u ACTIONS_ID_TOKEN_REQUEST_URL -u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  bash "$SCRIPT_DIR/att2-strip-child.sh"
