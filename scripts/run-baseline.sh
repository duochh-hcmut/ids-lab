#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
assert_lab_target "$TARGET_IP"

begin_run E1 "$RULES_REV3"
attacker ping -c 3 -W 2 "$TARGET_IP" >"$RUN_DIR/ping.txt" 2>&1 || true
status="$(attacker bash -lc "curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://${TARGET_IP}/" || true)"
printf '%s\n' "$status" >"$RUN_DIR/curl-status.txt"
finish_run "ping -c 3 -W 2 ${TARGET_IP}; curl http://${TARGET_IP}/"
echo "E1 done"
