#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
assert_lab_target "$TARGET_IP"

begin_run E3 "$RULES_REV3"
attacker nmap -sS -Pn --max-retries 0 --scan-delay 2s -p 1-40 "$TARGET_IP" \
  >"$RUN_DIR/nmap.txt" 2>&1 || true
finish_run "nmap -sS -Pn --max-retries 0 --scan-delay 2s -p 1-40 ${TARGET_IP}"
echo "E3 done"
