#!/usr/bin/env bash
# Usage: ./scripts/run-http.sh admin|traversal|encoded
set -euo pipefail
source "$(dirname "$0")/lib.sh"
assert_lab_target "$TARGET_IP"

mode="${1:-}"
case "$mode" in
  admin)
    run_id="E4"
    url="http://${TARGET_IP}/admin/config.php"
    ;;
  traversal)
    run_id="E5"
    url="http://${TARGET_IP}/../../etc/passwd"
    ;;
  encoded)
    run_id="E6"
    url="http://${TARGET_IP}/%2e%2e/%2e%2e/etc/passwd"
    ;;
  *)
    echo "usage: $0 admin|traversal|encoded" >&2
    exit 1
    ;;
esac

begin_run "$run_id" "$RULES_REV3"
status="$(attacker bash -lc "curl -s -o /dev/null -w '%{http_code}' --path-as-is --max-time 10 '$url'" || true)"
printf '%s\n' "$status" >"$RUN_DIR/curl-status.txt"
finish_run "curl --path-as-is ${url}"
echo "${run_id} done"
