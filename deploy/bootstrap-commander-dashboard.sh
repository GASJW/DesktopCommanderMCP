#!/usr/bin/env bash
# G6 Commander Dashboard: owner-authorized release of tested protected main.
# Must be executed as root from the pinned, clean /opt/vps-commander/code checkout.
set -Eeuo pipefail
umask 077
BASE=/opt/vps-commander/code
UNIT=vps-commander.service
WORKER=vps-commander-executor.service
TUNNEL=cloudflared-vps-commander.service
COFRE=cloudflared.service
g=(git -c safe.directory="$BASE" -C "$BASE")
[[ "$EUID" -eq 0 && ! -L "$BASE" && -d "$BASE/.git" ]] || exit 2
[[ "$("${g[@]}" branch --show-current)" = main ]] || { echo 'DASH_DEPLOY=RED_MAIN_REQUIRED'; exit 3; }
[[ -z "$("${g[@]}" status --porcelain)" ]] || { echo 'DASH_DEPLOY=RED_DIRTY'; exit 3; }
SHA=$("${g[@]}" rev-parse HEAD)
[[ "$(gh api repos/GASJW/DesktopCommanderMCP/branches/main --jq .protected)" = true ]] || exit 4
[[ "$(gh api repos/GASJW/DesktopCommanderMCP/branches/main --jq .commit.sha)" = "$SHA" ]] || exit 4
CHECKS=$(gh api "repos/GASJW/DesktopCommanderMCP/commits/$SHA/check-runs" --jq '[.check_runs[] | select(.app.slug=="github-actions" and .conclusion=="success" and (.name=="gateway-tests" or .name=="Check for spelling errors"))|.name]|unique|length')
[[ "$CHECKS" = 2 ]] || { echo 'DASH_DEPLOY=RED_CI'; exit 5; }
for unit in "$UNIT" "$WORKER" "$TUNNEL" "$COFRE"; do systemctl is-active --quiet "$unit" || exit 6; done
[[ "$(systemctl show -P User "$UNIT")" = vpsc-gateway ]] || exit 7
[[ "$(systemctl show -P User "$WORKER")" = vpscommander ]] || exit 7
case "$(systemctl show -P Environment "$UNIT")" in *VPS_COMMANDER_AUTH_MODE=access*) :;; *) exit 7;; esac
if systemctl show -P Requires "$UNIT" | grep -qw "$WORKER"; then echo 'DASH_DEPLOY=RED_HARD_DEPENDENCY';exit 7;fi
BASELINE=$("${g[@]}" rev-parse refs/heads/feat/g3-access-hardening)
# No unreviewed mutation to the runtime outside this narrow dashboard integration.
while IFS= read -r changed;do
  [[ -z "$changed" ]] && continue
  case "$changed" in
    gateway/server.mjs|gateway/audit.mjs|gateway/dashboard/*|gateway/test/dashboard.test.mjs) :;;
    *) echo "DASH_DEPLOY=RED_UNEXPECTED_RUNTIME_DELTA";exit 8;;
  esac
done < <("${g[@]}" diff --name-only "$BASELINE" "$SHA" -- gateway/ src/ deploy/systemd/ package.json package-lock.json tsconfig.json)
ensure_readable(){
  local item mode
  for item in gateway/server.mjs gateway/audit.mjs gateway/access-auth.mjs gateway/dashboard/http.mjs gateway/dashboard/metrics.mjs gateway/dashboard/index.html gateway/dashboard/app.js gateway/dashboard/style.css;do
    mode=$("${g[@]}" ls-files --stage -- "$item" | awk '{print $1}')
    [[ "$mode" = 100644 && -f "$BASE/$item" && ! -L "$BASE/$item" ]] || return 1
    chmod 0644 "$BASE/$item"
    runuser -u vpsc-gateway -- test -r "$BASE/$item" || return 1
  done
}
ensure_readable || { echo 'DASH_DEPLOY=RED_SOURCE_READABILITY';exit 9; }
/opt/vps-commander/bin/node --check "$BASE/gateway/server.mjs"
/opt/vps-commander/bin/node --check "$BASE/gateway/dashboard/app.js"
CHECK_DIR=$(mktemp -d /root/vpsc-dashboard-check.XXXXXXXX)
chmod 0700 "$CHECK_DIR"
if ! /opt/vps-commander/bin/node --test "$BASE"/gateway/test/*.test.mjs "$BASE"/deploy/test/*.test.mjs > "$CHECK_DIR/tests.log" 2>&1; then
  echo 'DASH_DEPLOY=RED_TESTS'
  rm -rf -- "$CHECK_DIR"
  exit 10
fi
rm -rf -- "$CHECK_DIR"
WORKER_PID=$(systemctl show -P MainPID "$WORKER")
wait_tunnel(){ for i in {1..120};do systemctl is-active --quiet "$TUNNEL" && return 0;sleep .25;done;return 1; }
wait_origin(){ local status;for i in {1..120};do
  status=$(curl -s --max-time 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/dashboard || true)
  [[ "$status" = 401 ]] && return 0
  sleep .25
done;return 1; }
rollback(){
  trap - ERR
  echo 'DASH_DEPLOY=RED_ROLLING_BACK' >&2
  "${g[@]}" switch feat/g3-access-hardening || return 1
  # The previous baseline is made of non-secret Git 100644 modules.
  for item in gateway/server.mjs gateway/audit.mjs gateway/access-auth.mjs;do
    [[ "$("${g[@]}" ls-files --stage -- "$item" | awk '{print $1}')" = 100644 ]] || return 1
    chmod 0644 "$BASE/$item"
    runuser -u vpsc-gateway -- test -r "$BASE/$item" || return 1
  done
  systemctl reset-failed "$UNIT" || true
  systemctl restart "$UNIT" || return 1
  local http=000
  for i in {1..120};do
    http=$(curl -s --max-time 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz || true)
    [[ "$http" = 401 ]] && break
    sleep .25
  done
  [[ "$http" = 401 ]] && wait_tunnel && systemctl is-active --quiet "$COFRE" || return 1
  echo 'DASH_ROLLBACK=GREEN_G3_5'
}
trap rollback ERR
systemctl restart "$UNIT"
wait_origin
wait_tunnel
systemctl is-active --quiet "$UNIT"
systemctl is-active --quiet "$WORKER"
systemctl is-active --quiet "$COFRE"
[[ "$(systemctl show -P MainPID "$WORKER")" = "$WORKER_PID" ]]
[[ "$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/mcp)" = 401 ]]
trap - ERR
echo 'DASH_DEPLOY=BOOTSTRAP_GREEN'
echo 'DASH_ROUTE_ANONYMOUS=401'
echo 'DASH_WORKER_PID_UNCHANGED=PASS'
echo 'DASH_NEXT=VERIFY_OWNER_CLOUDFLARE_ACCESS_BROWSER_AND_REAL_MCP_CALLS'
