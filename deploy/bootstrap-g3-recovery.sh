#!/usr/bin/env bash
# G3.3 controlled release: gateway code only; requires owner direct SSH root.
set -Eeuo pipefail
if [[ "$EUID" -ne 0 ]]; then echo 'Requires direct root SSH' >&2; exit 2; fi
BASE=/opt/vps-commander/code
BACKUP=/root/vps-commander-g3-recovery-backup
cd "$BASE"
git_safe=(git -c safe.directory="$BASE" -C "$BASE")
[[ "$("${git_safe[@]}" branch --show-current)" = feat/g3-recovery ]] || { echo 'Wrong branch'; exit 3; }
[[ -z "$("${git_safe[@]}" status --porcelain)" ]] || { echo 'Dirty source; abort'; exit 3; }
[[ -f gateway/test/recovery.test.mjs ]] || { echo 'Missing G3.3 tests'; exit 4; }
[[ -f deploy/manual-smoke-g3-recovery.mjs ]] || { echo 'Missing real smoke test'; exit 4; }
[[ "$(systemctl is-active vps-commander.service)" = active ]] || exit 5
[[ "$(systemctl is-active vps-commander-executor.service)" = active ]] || exit 5
[[ "$(systemctl is-active cloudflared-vps-commander.service)" = active ]] || exit 5
[[ "$(systemctl show -P User vps-commander.service)" = vpsc-gateway ]] || exit 6
[[ "$(systemctl show -P User vps-commander-executor.service)" = vpscommander ]] || exit 6
[[ ! -e "$BACKUP" ]] || { echo 'Backup already present; manual review required'; exit 7; }
echo 'G3.3 preflight: no production service has been restarted yet.'
/opt/vps-commander/bin/node --check gateway/server.mjs
/opt/vps-commander/bin/node --test gateway/test/*.test.mjs deploy/test/*.test.mjs
install -d -o root -g root -m 0700 "$BACKUP"
"${git_safe[@]}" rev-parse --verify origin/feat/g3-audit-trail > "$BACKUP/previous-commit"
chmod 0600 "$BACKUP/previous-commit"
rollback() {
  echo 'G3.3 restart failed; restoring G3.2 source' >&2
  "${git_safe[@]}" switch feat/g3-audit-trail || true
  systemctl restart vps-commander.service || true
  if ! systemctl is-active --quiet cloudflared-vps-commander.service; then
    systemctl restart cloudflared-vps-commander.service || true
  fi
}
trap rollback ERR
systemctl restart vps-commander.service
status='000'
for i in {1..40}; do
  status=$(curl -s --max-time 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz || true)
  [[ "$status" = 401 ]] && break
  sleep 0.25
done
[[ "$status" = 401 ]]
[[ "$(systemctl is-active vps-commander.service)" = active ]]
[[ "$(systemctl show -P User vps-commander.service)" = vpsc-gateway ]]
[[ "$(systemctl is-active vps-commander-executor.service)" = active ]]
if ! systemctl is-active --quiet cloudflared-vps-commander.service; then
  systemctl restart cloudflared-vps-commander.service
fi
systemctl is-active --quiet cloudflared-vps-commander.service
trap - ERR
echo G3_3_GATEWAY_DEPLOY=BOOTSTRAP_GREEN
echo 'NEXT: certify ChatGPT Commander tools and controlled root-only executor restart.'
