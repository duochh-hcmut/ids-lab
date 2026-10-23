#!/usr/bin/env bash
# Shared helpers for the isolated lab on 172.20.0.0/16.
# Traffic helpers refuse any destination other than the lab target.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="$ROOT/suricata/logs/runs"
TARGET_IP="172.20.0.20"
ATTACKER_IP="172.20.0.10"
RULES_REV3="$ROOT/suricata/rules/local.rules.rev3"
RULES_REV2="$ROOT/suricata/rules/local.rules.rev2"
RULES_ACTIVE="$ROOT/suricata/rules/local.rules"

hash_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  else
    sha256sum "$1"
  fi
}

assert_lab_target() {
  if [[ "$1" != "$TARGET_IP" ]]; then
    echo "refusing destination outside the lab: $1" >&2
    exit 1
  fi
}

restore_rev3_rules() {
  cp "$RULES_REV3" "$RULES_ACTIVE"
}

activate_rules() {
  local src="$1"
  cp "$src" "$RULES_ACTIVE"
}

wait_ids() {
  local since="$1"
  local i
  for i in $(seq 1 90); do
    if docker logs --since "$since" lab_ids 2>&1 | grep -E -q "engine started|Engine started"; then
      return 0
    fi
    sleep 1
  done
  echo "suricata did not report engine started" >&2
  docker logs --since "$since" lab_ids >&2 || true
  docker logs --tail 80 lab_ids >&2 || true
  return 1
}

reset_sensor() {
  docker stop lab_ids >/dev/null
  rm -f \
    "$ROOT/suricata/logs/fast.log" \
    "$ROOT/suricata/logs/eve.json" \
    "$ROOT/suricata/logs/stats.log" \
    "$ROOT/suricata/logs/suricata.log"
  local since
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  docker start lab_ids >/dev/null
  wait_ids "$since"
  mkdir -p "$RUN_DIR"
  docker logs --since "$since" lab_ids >"$RUN_DIR/sensor-start.txt" 2>&1 || true
}

start_pcap() {
  mkdir -p "$RUN_DIR"
  : >"$RUN_DIR/tcpdump.err"
  docker exec lab_pcap tcpdump -i eth0 -n -U -w - \
    >"$RUN_DIR/evidence.pcap" 2>"$RUN_DIR/tcpdump.err" &
  echo $! >"$RUN_DIR/tcpdump.hostpid"
  sleep 1
}

stop_pcap() {
  local pid
  pid="$(cat "$RUN_DIR/tcpdump.hostpid" 2>/dev/null || true)"
  if [[ -n "${pid}" ]]; then
    kill -INT "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

begin_run() {
  local id="$1"
  local rules_src="$2"
  RUN_ID="$id"
  RUN_DIR="$RUNS/$id"
  mkdir -p "$RUN_DIR"
  activate_rules "$rules_src"
  reset_sensor
  cp "$RULES_ACTIVE" "$RUN_DIR/rules-used.rules"
  hash_file "$RULES_ACTIVE" >"$RUN_DIR/rules.sha256"
  date -u +%Y-%m-%dT%H:%M:%SZ >"$RUN_DIR/started.txt"
  start_pcap
}

finish_run() {
  local cmd_text="$1"
  sleep 3
  stop_pcap
  cp -f "$ROOT/suricata/logs/fast.log" "$RUN_DIR/fast.log" 2>/dev/null || : >"$RUN_DIR/fast.log"
  cp -f "$ROOT/suricata/logs/eve.json" "$RUN_DIR/eve.json" 2>/dev/null || : >"$RUN_DIR/eve.json"
  date -u +%Y-%m-%dT%H:%M:%SZ >"$RUN_DIR/ended.txt"
  cat >"$RUN_DIR/notes.md" <<EOF
# ${RUN_ID}

- Started: $(cat "$RUN_DIR/started.txt")
- Ended: $(cat "$RUN_DIR/ended.txt")
- Command: \`${cmd_text}\`
- Rules SHA-256: $(awk '{print $1}' "$RUN_DIR/rules.sha256")

EOF
  if [[ -f "$RUN_DIR/curl-status.txt" ]]; then
    echo "- HTTP status: $(cat "$RUN_DIR/curl-status.txt")" >>"$RUN_DIR/notes.md"
  fi
}

attacker() {
  docker exec lab_attacker "$@"
}
