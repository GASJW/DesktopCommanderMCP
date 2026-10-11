#!/usr/bin/env bash
# G3.4 gateway-only release. Manual direct root SSH, never through unprivileged MCP.
set -Eeuo pipefail
umask 077
BASE=/opt/vps-commander/code
BACKUP=/root/vps-commander-g3-limits-backup
GW=vps-commander.service
WK=vps-commander-executor.service
if [[ "$EUID" -ne 0 ]]; then echo 'Requires root SSH'; exit 2; fi
g=(git -c safe.directory="$BASE" -C "$BASE")
[[ "$("${g[@]}" branch --show-current)" = feat/g3-operational-limits ]] || { echo 'Wrong branch'; exit 3; }
[[ -z "$("${g[@]}" status --porcelain)" ]] || { echo 'Dirty checkout'; exit 3; }
[[ ! -e "$BACKUP" ]] || { echo 'Backup already exists; reconcile manually'; exit 4; }
for unit in "$GW" "$WK" cloudflared-vps-commander.service cloudflared.service; do
  systemctl is-active --quiet "$unit" || { echo "Inactive $unit"; exit 5; }
done
[[ "$(systemctl show -P User "$GW")" = vpsc-gateway ]] || exit 6
[[ "$(systemctl show -P User "$WK")" = vpscommander ]] || exit 6
[[ " $(systemctl show -P Wants "$GW") " = *" $WK "* ]] || exit 7
[[ " $(systemctl show -P Requires "$GW") " != *" $WK "* ]] || exit 7
[[ "$(systemctl show -P Environment "$GW")" = *VPS_COMMANDER_AUDIT_ENABLED=1* ]] || exit 7
cd "$BASE"
/opt/vps-commander/bin/node --check gateway/server.mjs
/opt/vps-commander/bin/node --test gateway/test/*.test.mjs deploy/test/*.test.mjs
install -d -o root -g root -m 0700 "$BACKUP"
"${g[@]}" rev-parse --verify origin/feat/g3-recovery > "$BACKUP/previous-commit"
chmod 0600 "$BACKUP/previous-commit"
rollback() {
  echo 'G3.4 gate RED, restoring prior gateway release' >&2
  "${g[@]}" switch feat/g3-recovery || true
  systemctl restart "$GW" || true
  if ! systemctl is-active --quiet cloudflared-vps-commander.service; then
    systemctl restart cloudflared-vps-commander.service || true
  fi
}
trap rollback ERR
wk_pid_before=$(systemctl show -P MainPID "$WK")
systemctl restart "$GW"
status=000
for _ in {1..40}; do
  status=$(curl -sS --max-time 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz || true)
  [[ "$status" = 401 ]] && break
  sleep 0.25
done
[[ "$status" = 401 ]]
systemctl is-active --quiet "$GW"
systemctl is-active --quiet "$WK"
[[ "$(systemctl show -P User "$GW")" = vpsc-gateway ]]
[[ "$(systemctl show -P MainPID "$WK")" = "$wk_pid_before" ]]
[[ " $(systemctl show -P Wants "$GW") " = *" $WK "* ]]
[[ "$(systemctl show -P Environment "$GW")" = *VPS_COMMANDER_AUDIT_ENABLED=1* ]]
systemctl is-active --quiet cloudflared-vps-commander.service
systemctl is-active --quiet cloudflared.service
trap - ERR
echo G3_4_GATEWAY_DEPLOY=BOOTSTRAP_GREEN
echo G3_4_EXECUTOR_PID_UNCHANGED=PASS
echo G3_4_ANONYMOUS_ORIGIN_HTTP=401
echo 'NEXT: authenticated ChatGPT Commander smoke; production load tests are forbidden.'
