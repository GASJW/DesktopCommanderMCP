#!/usr/bin/env bash
# Confirm permanent development elevation ONLY after owner verifies Commander root.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root console required' >&2; exit 77; }
[[ ${VPSC_OWNER_ROOT_CONSENT:-} == I_ACCEPT_FULL_ROOT_MCP ]] ||
  { echo 'Owner confirmation missing' >&2; exit 77; }
BASE=/root/vpsc-g6-root-dev
OVERRIDE=/etc/systemd/system/vps-commander-executor.service.d/40-owner-root-dev.conf
[[ -f "$BASE/expected-override.conf" && -f "$BASE/revert.sh" ]]
/usr/bin/cmp -s "$OVERRIDE" "$BASE/expected-override.conf"
[[ $(/usr/bin/systemctl show -P User vps-commander-executor.service) == root ]]
[[ $(/usr/bin/systemctl show -P User vps-commander.service) == vpsc-gateway ]]
[[ $(/usr/bin/systemctl is-active vps-commander-executor.service) == active ]]
[[ $(/usr/bin/systemctl is-active vps-commander.service) == active ]]
[[ $(/usr/bin/systemctl is-active cloudflared-vps-commander.service) == active ]]
[[ $(/usr/bin/curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/mcp) == 401 ]]
# This confirmation is an explicit cancellation of a one-time watchdog.
# Operator must already have independently tested "id -u" as 0 via Commander.
if /usr/bin/systemctl is-active --quiet vpsc-g6-root-dev-watchdog.timer; then
  /usr/bin/systemctl stop vpsc-g6-root-dev-watchdog.timer
else
  echo 'Watchdog not armed; operator must reconcile before confirmation' >&2
  exit 78
fi
echo 'VPSC_G6_ROOT_DEV_CONFIRMED_UNTIL_MANUAL_REVERSION'
echo 'Undo using /usr/bin/bash /root/vpsc-g6-root-dev/revert.sh'
