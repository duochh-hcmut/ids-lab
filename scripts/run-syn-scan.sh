#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
assert_lab_target "$TARGET_IP"

begin_run E2 "$RULES_REV3"
attacker nmap -sS -Pn --max-retries 0 --min-rate 100 -p 1-1000 "$TARGET_IP" \
  >"$RUN_DIR/nmap.txt" 2>&1 || true
finish_run "nmap -sS -Pn --max-retries 0 --min-rate 100 -p 1-1000 ${TARGET_IP}"
echo "E2 done"
