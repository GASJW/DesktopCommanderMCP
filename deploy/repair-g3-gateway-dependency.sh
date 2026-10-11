#!/usr/bin/env bash
# G3.3 minimal systemd dependency repair. Run from direct root SSH.
# Changes only Requires= -> Wants= in the existing gateway unit, without restarting any services.
set -Eeuo pipefail
umask 077
BASE=/opt/vps-commander/code
UNIT=/etc/systemd/system/vps-commander.service
CANDIDATE=$BASE/deploy/systemd/vps-commander-g3.service
BACKUP_DIR=/root/vps-commander-g3-dependency-repair
WORKER=vps-commander-executor.service
if [[ $EUID -ne 0 ]]; then echo 'Must run as root via direct SSH' >&2; exit 2; fi
[[ "$(git -c safe.directory="$BASE" -C "$BASE" branch --show-current)" == feat/g3-recovery ]] || { echo 'Wrong branch' >&2; exit 3; }
[[ -z "$(git -c safe.directory="$BASE" -C "$BASE" status --porcelain)" ]] || { echo 'Dirty repository; abort' >&2; exit 3; }
for u in vps-commander.service "$WORKER" cloudflared-vps-commander.service cloudflared.service; do
  systemctl is-active --quiet "$u" || { echo "Inactive precondition: $u" >&2; exit 4; }
done
[[ "$(systemctl show -P User vps-commander.service)" == vpsc-gateway ]] || exit 5
[[ "$(systemctl show -P User "$WORKER")" == vpscommander ]] || exit 5
if cmp -s "$UNIT" "$CANDIDATE"; then
  echo G3_3_DEPENDENCY_REPAIR=ALREADY_APPLIED
  exit 0
fi
grep -qx 'Requires=vps-commander-executor.service' "$UNIT" || { echo 'Original dependency not found' >&2; exit 6; }
grep -qx 'Wants=vps-commander-executor.service' "$CANDIDATE" || { echo 'New dependency not found' >&2; exit 6; }
! grep -q '^Requires=vps-commander-executor.service$' "$CANDIDATE" || exit 6
# Reject every other config difference. Do not replace an unrelated/different systemd unit.
sed 's/^Requires=vps-commander-executor.service$/Wants=vps-commander-executor.service/' "$UNIT" | cmp -s - "$CANDIDATE" || {
  echo 'Unit diverges beyond minimal Requires->Wants change' >&2; exit 7;
}
[[ ! -e "$BACKUP_DIR" ]] || { echo 'Prior repair backup exists; review before retry' >&2; exit 8; }
gw_before=$(systemctl show -P MainPID vps-commander.service)
wk_before=$(systemctl show -P MainPID "$WORKER")
[[ "$gw_before" -gt 1 && "$wk_before" -gt 1 ]] || exit 9
install -d -o root -g root -m 0700 "$BACKUP_DIR"
install -o root -g root -m 0600 "$UNIT" "$BACKUP_DIR/vps-commander.service"
rollback() {
  echo 'G3_3_DEPENDENCY_REPAIR=RED; restoring original unit' >&2
  install -o root -g root -m 0644 "$BACKUP_DIR/vps-commander.service" "$UNIT" || true
  systemctl daemon-reload || true
}
trap rollback ERR
install -o root -g root -m 0644 "$CANDIDATE" "$UNIT"
systemd-analyze verify "$UNIT"
systemctl daemon-reload
deps=$(systemctl show -P Requires vps-commander.service)
wants=$(systemctl show -P Wants vps-commander.service)
[[ " $deps " != *" $WORKER "* ]] || { echo 'Still has hard dependency' >&2; false; }
[[ " $wants " == *" $WORKER "* ]] || { echo 'Soft dependency was not applied' >&2; false; }
[[ "$(systemctl show -P MainPID vps-commander.service)" == "$gw_before" ]] || false
[[ "$(systemctl show -P MainPID "$WORKER")" == "$wk_before" ]] || false
systemctl is-active --quiet vps-commander.service
systemctl is-active --quiet "$WORKER"
status=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz)
[[ "$status" == 401 ]] || false
trap - ERR
echo G3_3_DEPENDENCY_REPAIR=GREEN
echo G3_3_GATEWAY_PID_UNCHANGED=PASS
echo G3_3_EXECUTOR_PID_UNCHANGED=PASS
echo G3_3_ORIGIN_ANONYMOUS_HTTP=401
echo 'Only systemd dependency semantics changed; no service was restarted.'
