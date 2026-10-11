#!/usr/bin/env bash
# G3.2 owner-operated, direct SSH activation. Changes only VPS Commander gateway unit.
set -Eeuo pipefail
if [[ "$EUID" -ne 0 ]]; then echo 'Requires root via direct SSH' >&2; exit 2; fi
BASE=/opt/vps-commander/code
UNIT=vps-commander.service
GW_UNIT=/etc/systemd/system/$UNIT
NEW_UNIT=$BASE/deploy/systemd/vps-commander-g3.service
BACKUP=/root/vps-commander-g3-audit-backup
[[ -f "$NEW_UNIT" && -f "$BASE/gateway/audit.mjs" ]] || { echo 'Fetch G3 audit branch first' >&2; exit 3; }
[[ "$(git -c safe.directory="$BASE" -C "$BASE" branch --show-current)" = feat/g3-audit-trail ]] || { echo 'Wrong deployment branch' >&2; exit 4; }
[[ "$(systemctl is-active vps-commander.service)" = active ]] || exit 5
[[ "$(systemctl is-active vps-commander-executor.service)" = active ]] || exit 5
[[ "$(systemctl is-active cloudflared-vps-commander.service)" = active ]] || exit 5
[[ "$(systemctl show -P User vps-commander.service)" = vpsc-gateway ]] || exit 6
[[ "$(systemctl show -P User vps-commander-executor.service)" = vpscommander ]] || exit 6
[[ ! -f "$BACKUP/vps-commander.service" ]] || { echo 'Audit backup already exists: manual review required' >&2; exit 7; }
cd "$BASE"
/opt/vps-commander/bin/node --check gateway/server.mjs
/opt/vps-commander/bin/node --check gateway/access-auth.mjs
/opt/vps-commander/bin/node --check gateway/audit.mjs
/opt/vps-commander/bin/node --test gateway/test/*.test.mjs deploy/test/*.test.mjs
install -d -o root -g root -m 0700 "$BACKUP"
install -o root -g root -m 0600 "$GW_UNIT" "$BACKUP/vps-commander.service"
rollback() {
  echo 'G3.2 audit activation failed: restoring previous gateway unit' >&2
  install -o root -g root -m 0644 "$BACKUP/vps-commander.service" "$GW_UNIT"
  systemctl daemon-reload
  systemctl restart vps-commander.service || true
  if ! systemctl is-active --quiet cloudflared-vps-commander.service; then
    systemctl restart cloudflared-vps-commander.service || true
  fi
}
trap rollback ERR
install -o root -g root -m 0644 "$NEW_UNIT" "$GW_UNIT"
systemd-analyze verify "$GW_UNIT"
systemctl daemon-reload
stamp=$(date -u '+%Y-%m-%d %H:%M:%S')
systemctl restart vps-commander.service
for i in {1..40}; do
  status=$(curl -s --max-time 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz || true)
  [[ "$status" = 401 ]] && break
  sleep 0.25
done
[[ "${status:-000}" = 401 ]]
[[ "$(systemctl is-active "$UNIT")" = active ]]
[[ "$(systemctl show -P User "$UNIT")" = vpsc-gateway ]]
[[ "$(systemctl is-active vps-commander-executor.service)" = active ]]
if ! systemctl is-active --quiet cloudflared-vps-commander.service; then
  systemctl restart cloudflared-vps-commander.service
fi
systemctl is-active --quiet cloudflared-vps-commander.service
audit_found=0
for i in {1..10}; do
  if journalctl -u vps-commander.service --since "$stamp" -o cat --no-pager | grep -F '"event":"vps_commander_audit"' >/dev/null; then
    audit_found=1; break
  fi
  sleep 0.2
done
[[ "$audit_found" = 1 ]] || { echo 'No structured audit event reached journald' >&2; false; }
trap - ERR
echo G3_2_AUDIT_SYSTEMD=BOOTSTRAP_GREEN
echo 'Unauthenticated local HTTP 401 was journaled; run real authenticated Commander smoke to finish G3.2.'
