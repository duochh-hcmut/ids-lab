#!/usr/bin/env bash
# Copy the current sensor scratch logs into suricata/logs/runs/<ID>/.
# Usage: ./scripts/collect.sh E2
set -euo pipefail
source "$(dirname "$0")/lib.sh"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <run-id>" >&2
  exit 1
fi

id="$1"
dest="$RUNS/$id"
mkdir -p "$dest"
cp -f "$ROOT/suricata/logs/fast.log" "$dest/fast.log"
cp -f "$ROOT/suricata/logs/eve.json" "$dest/eve.json"
cp -f "$RULES_ACTIVE" "$dest/rules-used.rules"
echo "collected scratch logs into $dest"
