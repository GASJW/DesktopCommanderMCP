#!/usr/bin/env bash
# G3.1 owner-governed direct SSH cutover. No Cloudflare/DNS changes.
set -Eeuo pipefail
if [[ "$EUID" != 0 ]]; then echo 'Run as root over direct SSH' >&2; exit 2; fi
BASE=/opt/vps-commander/code
BACKUP=/root/vps-commander-g3-backup
GW_UNIT=/etc/systemd/system/vps-commander.service
WORKER_UNIT=/etc/systemd/system/vps-commander-executor.service
TOKEN=/var/lib/vps-commander/.config/vps-commander/gateway.env
SOCKET=/run/vps-commander-ipc/mcp.sock
test -f "$BASE/gateway/executor-socket.mjs" || { echo 'Pull G3 branch first' >&2; exit 3; }
test -f "$BASE/deploy/systemd/vps-commander-executor.service" || exit 4
test -f "$BASE/deploy/systemd/vps-commander-g3.service" || exit 4
test "$(systemctl is-active vps-commander.service)" = active || { echo 'Existing gateway not active' >&2; exit 5; }
test "$(systemctl is-active cloudflared-vps-commander.service)" = active || { echo 'Cloudflare tunnel not active' >&2; exit 6; }
test ! -e "$WORKER_UNIT" || { echo 'Worker unit already exists: manual reconcile required' >&2; exit 7; }
test ! -e "$BACKUP/vps-commander.service" || { echo 'Existing G3 backup: manual reconcile required' >&2; exit 8; }
cd "$BASE"
/opt/vps-commander/bin/node --check gateway/server.mjs
/opt/vps-commander/bin/node --check gateway/executor-socket.mjs
/opt/vps-commander/bin/node --test gateway/test/*.test.mjs deploy/test/*.test.mjs
groupadd --system vpsc-ipc
useradd --system --gid vpsc-ipc --home-dir /var/lib/vps-commander-gateway --create-home --shell /usr/sbin/nologin vpsc-gateway
install -d -m 0700 "$BACKUP"
install -m 0600 "$GW_UNIT" "$BACKUP/vps-commander.service"
if test -f "$TOKEN"; then install -m 0600 "$TOKEN" "$BACKUP/gateway.env"; fi
install -m 0644 "$BASE/deploy/systemd/vps-commander-executor.service" "$WORKER_UNIT"
install -m 0644 "$BASE/deploy/systemd/vps-commander-g3.service" "$GW_UNIT"
systemd-analyze verify "$GW_UNIT" "$WORKER_UNIT"
systemctl daemon-reload
rollback() {
  echo 'G3 cutover failure: restoring gateway unit' >&2
  systemctl stop vps-commander.service || true
  systemctl stop vps-commander-executor.service || true
  install -m 0644 "$BACKUP/vps-commander.service" "$GW_UNIT"
  if test -f "$BACKUP/gateway.env"; then
    install -o vpscommander -g vpscommander -m 0600 "$BACKUP/gateway.env" "$TOKEN"
  fi
  systemctl daemon-reload
  systemctl restart vps-commander.service || true
}
trap rollback ERR
systemctl stop vps-commander.service
systemctl enable --now vps-commander-executor.service
for i in {1..40}; do test -S "$SOCKET" && break; sleep 0.25; done
test -S "$SOCKET"
test "$(stat -c '%a %G' "$SOCKET")" = '660 vpsc-ipc'
systemctl restart vps-commander.service
for i in {1..40}; do
  status=$(curl -s --max-time 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz || true)
  test "$status" = 401 && break
  sleep 0.25
done
test "${status:-000}" = 401
test "$(systemctl show -P User vps-commander.service)" = vpsc-gateway
test "$(systemctl show -P User vps-commander-executor.service)" = vpscommander
gw_pid=$(systemctl show -P MainPID vps-commander.service)
if runuser -u vpscommander -- test -r "/proc/$gw_pid/environ"; then
  echo 'G3 FAIL: executor can read gateway process environment' >&2; false
fi
# Legacy bearer file is no longer consumed in Access mode; preserve root-only rollback copy.
if test -f "$TOKEN"; then rm -- "$TOKEN"; fi
trap - ERR
echo G3_EXECUTOR_ISOLATION=BOOTSTRAP_GREEN
echo 'Run authenticated ChatGPT Commander tools/list + shell + filesystem smoke before certifying G3.1.'
