#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

cleanup() {
  restore_rev3_rules || true
  if docker ps --format '{{.Names}}' | grep -q '^lab_ids$'; then
    docker start lab_ids >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"$(dirname "$0")/up.sh"
"$(dirname "$0")/prepare-attacker.sh"

mkdir -p "$RUNS/E0"
docker exec lab_ids suricata -T \
  -c /etc/suricata/suricata.yaml \
  -S /var/lib/suricata/rules/local.rules \
  >"$RUNS/E0/suricata-T.txt" 2>&1
cp "$RULES_REV3" "$RUNS/E0/rules-used.rules"
hash_file "$RULES_REV3" >"$RUNS/E0/rules.sha256"
date -u +%Y-%m-%dT%H:%M:%SZ | tee "$RUNS/E0/started.txt" >"$RUNS/E0/ended.txt"
cat >"$RUNS/E0/notes.md" <<EOF
# E0

- Config test only. No lab traffic.
- Command: \`suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/local.rules\`
- Exit recorded by the shell redirection in \`suricata-T.txt\`.
- Rules SHA-256: $(awk '{print $1}' "$RUNS/E0/rules.sha256")
EOF
echo "E0 config test passed"

"$(dirname "$0")/run-baseline.sh"
"$(dirname "$0")/run-syn-scan.sh"
"$(dirname "$0")/run-syn-slow.sh"
"$(dirname "$0")/run-http.sh" admin
"$(dirname "$0")/run-http.sh" traversal
"$(dirname "$0")/run-http.sh" encoded

# E7 — rev 2 false-positive check on a normal homepage GET.
begin_run E7 "$RULES_REV2"
status="$(attacker bash -lc "curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://${TARGET_IP}/" || true)"
printf '%s\n' "$status" >"$RUN_DIR/curl-status.txt"
finish_run "curl http://${TARGET_IP}/ with rev 2 rules"
echo "E7 done"

# E8 — same admin request with SID 1000003 action changed to drop.
drop_rules="$RUNS/E8-rules.rules"
mkdir -p "$RUNS"
sed 's/^alert http 172.20.0.10 any -> 172.20.0.20 80 (msg:"LAB DETECT: HTTP Admin Path Probe"/drop http 172.20.0.10 any -> 172.20.0.20 80 (msg:"LAB DETECT: HTTP Admin Path Probe"/' \
  "$RULES_REV3" >"$drop_rules"
begin_run E8 "$drop_rules"
docker logs lab_target >"$RUN_DIR/nginx-before.txt" 2>&1 || true
status="$(attacker bash -lc "curl -s -o /dev/null -w '%{http_code}' --path-as-is --max-time 10 http://${TARGET_IP}/admin/config.php" || true)"
printf '%s\n' "$status" >"$RUN_DIR/curl-status.txt"
sleep 1
docker logs lab_target >"$RUN_DIR/nginx-after.txt" 2>&1 || true
finish_run "curl --path-as-is http://${TARGET_IP}/admin/config.php with SID 1000003 action drop"
echo "E8 done"

echo "all runs finished; rev 3 rules restored by EXIT trap"
