#!/usr/bin/env bash
# One-time direct-console activation for owner-approved full root MCP executor.
# NEVER run this script through the Commander or RDC MCP bridge.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root console required' >&2; exit 77; }
[[ ${VPSC_OWNER_ROOT_CONSENT:-} == I_ACCEPT_FULL_ROOT_MCP ]] ||
  { echo 'Missing explicit VPSC_OWNER_ROOT_CONSENT acknowledgment' >&2; exit 77; }

UNIT=vps-commander-executor.service
GW=vps-commander.service
TUNNEL=cloudflared-vps-commander.service
DROPIN_DIR=/etc/systemd/system/vps-commander-executor.service.d
DROPIN="$DROPIN_DIR/40-owner-root-dev.conf"
BASE=/root/vpsc-g6-root-dev
SRC_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ ! -e "$BASE" && ! -e "$DROPIN" ]] ||
  { echo 'Existing activation/backup found: reconcile before proceeding' >&2; exit 78; }

[[ $(/usr/bin/systemctl show -P User "$UNIT") == vpscommander ]]
[[ $(/usr/bin/systemctl show -P User "$GW") == vpsc-gateway ]]
[[ -z $(/usr/bin/systemctl show -P DropInPaths "$UNIT") ]]
for svc in "$UNIT" "$GW" "$TUNNEL"; do
  [[ $(/usr/bin/systemctl is-active "$svc") == active ]]
done
[[ $(/usr/bin/git -c safe.directory=/opt/vps-commander/code -C /opt/vps-commander/code rev-parse HEAD) == e599678fcec71725ff16303e99b87db236746f02 ]]
[[ $(/usr/bin/curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/mcp) == 401 ]]
[[ -f "$SRC_DIR/g6-owner-root-revert.sh" ]]

# Root-private copies keep rollback independent of any editable Git worktree.
install -d -o root -g root -m 0700 "$BASE"
install -o root -g root -m 0700 "$SRC_DIR/g6-owner-root-revert.sh" "$BASE/revert.sh"
install -o root -g root -m 0600 /etc/systemd/system/"$UNIT" "$BASE/original-unit.txt"
/usr/bin/systemctl cat "$GW" > "$BASE/original-gateway-unit.txt"
chmod 0600 "$BASE/original-gateway-unit.txt"

# Only the Unix-socket MCP executor becomes root. Gateway stays separate.
cat > "$BASE/expected-override.conf" <<'SERVICE'
[Service]
User=root
Group=vpsc-ipc
Environment=HOME=/root
NoNewPrivileges=false
ProtectHome=false
ProtectSystem=false
ProtectProc=default
PrivateTmp=false
ProtectKernelTunables=false
ProtectKernelModules=false
ProtectControlGroups=false
RestrictSUIDSGID=false
CapabilityBoundingSet=~
SERVICE
chmod 0600 "$BASE/expected-override.conf"
install -d -o root -g root -m 0755 "$DROPIN_DIR"
install -o root -g root -m 0644 "$BASE/expected-override.conf" "$DROPIN"

rollback_on_failure(){
  echo 'Activation failed; requesting safe rollback' >&2
  /usr/bin/bash "$BASE/revert.sh" || true
}
trap rollback_on_failure ERR
/usr/bin/systemd-analyze verify /etc/systemd/system/"$UNIT"
/usr/bin/systemctl daemon-reload
[[ $(/usr/bin/systemctl show -P User "$UNIT") == root ]]
[[ $(/usr/bin/systemctl show -P User "$GW") == vpsc-gateway ]]

# The pilot MUST automatically revert if the operator cannot verify it.
# Explicit confirmation may later cancel this rollback timer.
systemd-run --unit=vpsc-g6-root-dev-watchdog --on-active=7m \
  --timer-property=AccuracySec=1s \
  /usr/bin/bash "$BASE/revert.sh"

/usr/bin/systemctl restart "$UNIT"
for _ in $(seq 1 40); do
  if [[ $(/usr/bin/systemctl is-active "$UNIT") == active ]] &&
    [[ -S /run/vps-commander-ipc/mcp.sock ]]; then break; fi
  sleep 0.25
done
[[ $(/usr/bin/systemctl is-active "$UNIT") == active ]]
[[ $(/usr/bin/stat -c '%a %G' /run/vps-commander-ipc/mcp.sock) == '660 vpsc-ipc' ]]
PID=$(/usr/bin/systemctl show -P MainPID "$UNIT")
[[ "$PID" =~ ^[0-9]+$ && "$PID" -gt 1 ]]
[[ $(/usr/bin/awk '/^Uid:/{print $2}' "/proc/$PID/status") == 0 ]]
[[ $(/usr/bin/systemctl show -P User "$GW") == vpsc-gateway ]]
[[ $(/usr/bin/systemctl is-active "$GW") == active ]]
[[ $(/usr/bin/systemctl is-active "$TUNNEL") == active ]]
[[ $(/usr/bin/curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/mcp) == 401 ]]
trap - ERR
printf '%s\n' \
  'ROOT_EXECUTOR=GREEN' \
  'GATEWAY_OWNER_ACCESS=UNCHANGED' \
  'WATCHDOG_AUTO_ROLLBACK=7_MINUTES' \
  'Verify through Commander before confirming permanent activation.'
