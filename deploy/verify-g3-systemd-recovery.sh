#!/usr/bin/env bash
# G3.3 live isolated-executor failure drill, manual root SSH ONLY.
# Never run while an MCP command has side effects or is in progress.
set -Eeuo pipefail
umask 077
BASE=/opt/vps-commander/code
WORKER=vps-commander-executor.service
GATEWAY=vps-commander.service
VERIFIER=$BASE/deploy/verify-g3-recovery-events.py
if [[ $EUID -ne 0 || "${1:-}" != '--accept-controlled-executor-restart' ]]; then
  echo 'Requires root SSH and explicit --accept-controlled-executor-restart' >&2
  exit 2
fi
[[ "$(git -c safe.directory="$BASE" -C "$BASE" branch --show-current)" == 'feat/g3-recovery' ]] || { echo WRONG_BRANCH; exit 3; }
[[ -f "$VERIFIER" ]] || { echo VERIFIER_NOT_FOUND; exit 4; }
python3 -c 'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$VERIFIER"
for unit in "$GATEWAY" "$WORKER" cloudflared-vps-commander.service cloudflared.service; do
  systemctl is-active --quiet "$unit" || { echo "SERVICE_NOT_ACTIVE=$unit"; exit 5; }
done
[[ "$(systemctl show -P User "$GATEWAY")" == 'vpsc-gateway' ]] || exit 6
[[ "$(systemctl show -P User "$WORKER")" == 'vpscommander' ]] || exit 6
[[ "$(systemctl show -P Environment "$GATEWAY")" == *VPS_COMMANDER_AUDIT_ENABLED=1* ]] || exit 6
before_gateway=$(systemctl show -P MainPID "$GATEWAY")
before_worker=$(systemctl show -P MainPID "$WORKER")
[[ "$before_gateway" -gt 1 && "$before_worker" -gt 1 ]] || exit 7
stamp=$(date '+%Y-%m-%d %H:%M:%S')
out=$(mktemp)
cleanup() { rm -f "$out"; }
recover() {
  echo 'G3_3_REAL_SYSTEMD_DRILL=RED; attempting safe service recovery' >&2
  if ! systemctl is-active --quiet "$WORKER"; then
    systemctl reset-failed "$WORKER" || true
    systemctl restart "$WORKER" || true
  fi
  if ! systemctl is-active --quiet "$GATEWAY"; then
    systemctl restart "$GATEWAY" || true
  fi
  if ! systemctl is-active --quiet cloudflared-vps-commander.service; then
    systemctl restart cloudflared-vps-commander.service || true
  fi
}
trap cleanup EXIT
trap recover ERR
echo 'G3_3_DRILL_START=CONTROLLED_SINGLE_EXECUTOR_MAIN_SIGKILL'
systemctl kill --kill-whom=main --signal=SIGKILL "$WORKER"
success=0
for i in {1..120}; do
  if systemctl is-active --quiet "$WORKER" && systemctl is-active --quiet "$GATEWAY"; then
    after_gateway=$(systemctl show -P MainPID "$GATEWAY")
    after_worker=$(systemctl show -P MainPID "$WORKER")
    if [[ "$after_gateway" != "$before_gateway" ]]; then
      echo 'G3_3_GATEWAY_PID_CHANGED=RED (do not certify transparent recovery)' >&2
      false
    fi
    if [[ "$after_worker" != "$before_worker" && "$after_worker" -gt 1 ]]; then
      if journalctl -u "$GATEWAY" --since "$stamp" --no-pager -o cat | python3 "$VERIFIER" > "$out"; then
        success=1
        break
      fi
    fi
  fi
  sleep 0.25
done
[[ "$success" == 1 ]] || { echo 'Recovery not proven within 30 seconds' >&2; false; }
systemctl is-active --quiet cloudflared-vps-commander.service
systemctl is-active --quiet cloudflared.service
cat "$out"
echo 'G3_3_GATEWAY_PID_UNCHANGED=PASS'
echo 'G3_3_EXECUTOR_PID_ROTATED=PASS'
echo 'G3_3_BOTH_TUNNELS_ACTIVE=PASS'
echo 'G3_3_REAL_SYSTEMD_DRILL=GREEN'
trap - ERR
