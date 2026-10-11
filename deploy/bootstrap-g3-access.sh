#!/usr/bin/env bash
# G3.5 owner-only JWT / method-surface hardening; root-SSH gateway-only release with rollback.
set -Eeuo pipefail
umask 077
BASE=/opt/vps-commander/code
BACKUP=''
GW=vps-commander.service
WK=vps-commander-executor.service
if [[ "$EUID" -ne 0 ]]; then echo 'Requires root SSH'; exit 2; fi
g=(git -c safe.directory="$BASE" -C "$BASE")
[[ "$("${g[@]}" branch --show-current)" = feat/g3-access-hardening ]] || { echo 'Wrong branch'; exit 3; }
[[ -z "$("${g[@]}" status --porcelain)" ]] || { echo 'Dirty checkout'; exit 3; }
for unit in "$GW" "$WK" cloudflared-vps-commander.service cloudflared.service; do
  systemctl is-active --quiet "$unit" || { echo "Inactive $unit"; exit 5; }
done
[[ "$(systemctl show -P User "$GW")" = vpsc-gateway ]] || exit 6
[[ "$(systemctl show -P User "$WK")" = vpscommander ]] || exit 6
[[ " $(systemctl show -P Wants "$GW") " = *" $WK "* ]] || exit 7
[[ " $(systemctl show -P Requires "$GW") " != *" $WK "* ]] || exit 7
[[ "$(systemctl show -P Environment "$GW")" = *VPS_COMMANDER_AUDIT_ENABLED=1* ]] || exit 7
cd "$BASE"
[[ "$(systemctl show -P Environment "$GW")" = *VPS_COMMANDER_AUTH_MODE=access* ]] || { echo 'Access mode not enabled'; exit 7; }
# Root's umask 077 may create tracked 100644 modules as mode 0600 during git switch.
# Repair ONLY the three public-source runtime modules. Never chmod a secret or a directory.
ensure_gateway_sources_readable() {
  local p expected
  for p in gateway/server.mjs gateway/audit.mjs gateway/access-auth.mjs; do
    expected=$("${g[@]}" ls-files --stage -- "$p" | awk '{print $1}')
    [[ "$expected" = 100644 && -f "$BASE/$p" && ! -L "$BASE/$p" ]] || {
      echo "Refused unexpected source entry: $p" >&2
      return 1
    }
    chmod 0644 "$BASE/$p"
    runuser -u vpsc-gateway -- test -r "$BASE/$p" || {
      echo "Gateway cannot read module $p" >&2
      return 1
    }
  done
}
ensure_gateway_sources_readable
# The dedicated tunnel Requires=the gateway, so systemctl restart gateway also
# brings the tunnel through activating. Poll its state rather than immediately
# declaring the release RED on the first transient activating result.
wait_commander_tunnel_ready() {
  local attempts="${1:-120}" delay="${2:-0.25}" i
  for ((i=0; i<attempts; i++)); do
    if systemctl is-active --quiet cloudflared-vps-commander.service; then
      return 0
    fi
    sleep "$delay"
  done
  return 1
}
/opt/vps-commander/bin/node --check gateway/server.mjs
/opt/vps-commander/bin/node --check gateway/access-auth.mjs
/opt/vps-commander/bin/node --test gateway/test/*.test.mjs deploy/test/*.test.mjs
BACKUP=$(mktemp -d /root/vps-commander-g3-access-backup.XXXXXXXX)
"${g[@]}" rev-parse --verify origin/feat/g3-operational-limits > "$BACKUP/previous-commit"
chmod 0600 "$BACKUP/previous-commit"
rollback() {
  trap - ERR
  echo 'G3.5 gate RED, restoring prior gateway release' >&2
  if ! "${g[@]}" switch feat/g3-operational-limits; then
    echo 'G3_5_ROLLBACK=RED_BRANCH_RESTORE_FAILED' >&2
    return 1
  fi
  if ! ensure_gateway_sources_readable; then
    echo 'G3_5_ROLLBACK=RED_SOURCE_PERMISSIONS' >&2
    return 1
  fi
  systemctl reset-failed "$GW" || true
  if ! systemctl restart "$GW"; then
    echo 'G3_5_ROLLBACK=RED_RESTART_FAILED' >&2
    return 1
  fi
  local status=000
  for _ in {1..120}; do
    status=$(curl -s --max-time 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz || true)
    [[ "$status" = 401 ]] && break
    sleep 0.25
  done
  if [[ "$status" != 401 ]] || ! systemctl is-active --quiet "$GW"; then
    echo 'G3_5_ROLLBACK=RED_NOT_HEALTHY' >&2
    return 1
  fi
  if ! wait_commander_tunnel_ready; then
    # Single best-effort tunnel restart only if ordinary dependency recovery
    # did not stabilize; never touch the unrelated cofre tunnel.
    systemctl restart cloudflared-vps-commander.service || true
    if ! wait_commander_tunnel_ready; then
      echo 'G3_5_ROLLBACK=RED_TUNNEL_UNAVAILABLE' >&2
      return 1
    fi
  fi
  echo 'G3_5_ROLLBACK=GREEN_G3_3_RESTORED'
}
trap rollback ERR
wk_pid_before=$(systemctl show -P MainPID "$WK")
systemctl restart "$GW"
status=000
for _ in {1..120}; do
  status=$(curl -s --max-time 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz || true)
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
if ! wait_commander_tunnel_ready; then
  echo 'G3_5_GATE=RED_TUNNEL_NOT_READY_AFTER_WAIT' >&2
  false
fi
systemctl is-active --quiet cloudflared.service
trap - ERR
echo G3_5_TUNNEL_STABILIZATION=PASS
echo G3_5_GATEWAY_DEPLOY=BOOTSTRAP_GREEN
echo G3_5_EXECUTOR_PID_UNCHANGED=PASS
echo G3_5_ANONYMOUS_ORIGIN_HTTP=401
echo 'NEXT: certify real ChatGPT OAuth / read-only tools immediately; no public negative-auth fuzzing.'
