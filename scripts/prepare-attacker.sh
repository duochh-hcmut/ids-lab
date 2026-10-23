#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"
assert_lab_target "$TARGET_IP"

if attacker bash -lc 'command -v nmap >/dev/null && command -v curl >/dev/null && command -v ping >/dev/null'; then
  echo "attacker already has nmap, curl, and ping"
else
  attacker bash -lc 'export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y nmap curl iputils-ping'
fi

attacker ping -c 1 -W 3 "$TARGET_IP"
echo "attacker can reach ${TARGET_IP}"
