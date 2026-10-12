#!/usr/bin/env bash
# Revert the explicitly owner-approved G6 root developer pilot.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run from a root-owned console" >&2; exit 77; }
BASE=/root/vpsc-g6-root-dev
DROPIN=/etc/systemd/system/vps-commander-executor.service.d/40-owner-root-dev.conf
if [[ -e "$DROPIN" ]]; then
  [[ -f "$BASE/expected-override.conf" ]] &&
    /usr/bin/cmp -s "$DROPIN" "$BASE/expected-override.conf" ||
      { echo "Override differs: manual reconciliation required" >&2; exit 78; }
  /usr/bin/rm -- "$DROPIN"
  /usr/bin/systemctl daemon-reload
  /usr/bin/systemctl restart vps-commander-executor.service
fi
[[ $(/usr/bin/systemctl show -P User vps-commander-executor.service) == vpscommander ]]
[[ $(/usr/bin/systemctl is-active vps-commander-executor.service) == active ]]
[[ $(/usr/bin/systemctl show -P User vps-commander.service) == vpsc-gateway ]]
[[ $(/usr/bin/systemctl is-active vps-commander.service) == active ]]
echo 'VPSC_G6_ROOT_DEV_ROLLBACK=GREEN'
