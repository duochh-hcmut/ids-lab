#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

mkdir -p "$ROOT/suricata/logs/runs"
chmod -R a+rwx "$ROOT/suricata/logs" || true

cd "$ROOT"
docker compose up -d target attacker ids_sensor pcap_recorder

echo "waiting for tcpdump inside lab_pcap"
ready=0
for _ in $(seq 1 90); do
  if docker exec lab_pcap tcpdump --version >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" != "1" ]]; then
  echo "tcpdump was not installed in lab_pcap" >&2
  docker logs --tail 40 lab_pcap >&2 || true
  exit 1
fi

docker exec lab_pcap ls /sys/class/net >"$RUNS/interfaces.txt"

since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if ! docker logs --since "$since" lab_ids 2>&1 | grep -E -q "engine started|Engine started"; then
  # Container may already have been up before --since. Accept a recent start line.
  if ! docker logs --tail 40 lab_ids 2>&1 | grep -E -q "engine started|Engine started"; then
    echo "lab_ids is up; engine-started check deferred to E0" >&2
  fi
fi

echo "lab containers are up"
