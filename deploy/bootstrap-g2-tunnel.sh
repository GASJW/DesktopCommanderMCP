#!/usr/bin/env bash
# Owner-run direct SSH bootstrap. Does not publish a hostname.
set -Eeuo pipefail

if [[ "$EUID" -ne 0 ]]; then echo 'Requires root over direct SSH' >&2; exit 2; fi
BASE=/opt/vps-commander/code
TOKEN=/etc/cloudflared/vps-commander-private/token
UNIT=cloudflared-vps-commander.service
USER_NAME=vpscommander-tunnel
test -s "$TOKEN" || { echo 'Tunnel credential missing' >&2; exit 3; }
test -f "$BASE/deploy/systemd/$UNIT" || { echo 'Pull reviewed branch first' >&2; exit 4; }
test "$(systemctl is-active vps-commander.service)" = active || { echo 'Origin inactive' >&2; exit 5; }
ss -ltn '( sport = :8787 )' | grep -q '127.0.0.1:8787' || { echo 'No loopback MCP origin' >&2; exit 6; }
test -x /usr/local/bin/cloudflared || { echo 'cloudflared not installed' >&2; exit 7; }
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/vps-commander-tunnel --create-home --shell /usr/sbin/nologin "$USER_NAME"
fi
chown root:"$USER_NAME" "$(dirname "$TOKEN")" "$TOKEN"
chmod 0750 "$(dirname "$TOKEN")"
chmod 0640 "$TOKEN"
install -o root -g root -m 0644 "$BASE/deploy/systemd/$UNIT" "/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemctl enable --now "$UNIT"
test "$(systemctl is-active "$UNIT")" = active || { echo 'Tunnel service failed: do not create DNS' >&2; exit 8; }
echo G2_TUNNEL_SYSTEMD=ACTIVE
echo MCP_ORIGIN=127.0.0.1:8787
echo 'No DNS was changed, no credentials printed.'
