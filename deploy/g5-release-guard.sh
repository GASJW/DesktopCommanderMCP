#!/usr/bin/env bash
# G5 release admission only. READ-ONLY for live code/systemd; git fetch updates refs, never checkout.
set -Eeuo pipefail
umask 077
[[ "$EUID" -eq 0 ]] || { echo 'G5_RELEASE_GUARD=RED_ROOT_REQUIRED'; exit 2; }
SOURCE=/opt/vps-commander/code
REPO=GASJW/DesktopCommanderMCP
[[ -d "$SOURCE/.git" && ! -L "$SOURCE" ]] || { echo 'G5_RELEASE_GUARD=RED_REPO'; exit 3; }
g=(git -c safe.directory="$SOURCE" -C "$SOURCE")
[[ -z "$("${g[@]}" status --porcelain)" ]] || { echo 'G5_RELEASE_GUARD=RED_DIRTY_WORKTREE'; exit 4; }
for unit in vps-commander.service vps-commander-executor.service cloudflared-vps-commander.service cloudflared.service; do
  systemctl is-active --quiet "$unit" || { echo 'G5_RELEASE_GUARD=RED_SERVICE'; exit 5; }
done
[[ "$(systemctl show -P User vps-commander.service)" = vpsc-gateway ]] || exit 5
[[ "$(systemctl show -P User vps-commander-executor.service)" = vpscommander ]] || exit 5
[[ "$(curl --silent --max-time 4 --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8787/healthz)" = 401 ]] || {
  echo 'G5_RELEASE_GUARD=RED_ANONYMOUS_ORIGIN'
  exit 5
}
[[ "$(gh api "repos/$REPO/branches/main" --jq '.protected')" = true ]] || {
  echo 'G5_RELEASE_GUARD=RED_MAIN_UNPROTECTED'; exit 6
}
remote_sha=$(gh api "repos/$REPO/branches/main" --jq '.commit.sha')
[[ "$remote_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'G5_RELEASE_GUARD=RED_REMOTE_SHA'; exit 6; }
# fetch only the current protected main ref; do not switch the live checkout under root umask.
"${g[@]}" fetch --no-tags origin refs/heads/main:refs/remotes/origin/main --quiet
resolved=$("${g[@]}" rev-parse refs/remotes/origin/main)
[[ "$remote_sha" = "$resolved" ]] || { echo 'G5_RELEASE_GUARD=RED_MAIN_MOVED'; exit 7; }
# Both required checks must be completed by GitHub Actions on this exact commit.
passed=$(gh api "repos/$REPO/commits/$remote_sha/check-runs" --jq '[.check_runs[] | select(.app.slug=="github-actions" and .conclusion=="success" and (.name=="gateway-tests" or .name=="Check for spelling errors")) | .name] | unique | length')
[[ "$passed" = 2 ]] || { echo 'G5_RELEASE_GUARD=RED_REQUIRED_CHECKS'; exit 8; }
local_sha=$("${g[@]}" rev-parse HEAD)
[[ "$local_sha" =~ ^[0-9a-f]{40}$ ]] || exit 9
printf 'G5_MAIN_SHA=%s\n' "$remote_sha"
printf 'G5_ACTIVE_SHA=%s\n' "$local_sha"
printf 'G5_MAIN_PROTECTED=PASS\nG5_REQUIRED_CHECKS=PASS\n'
# Code or unit changes demand an isolated candidate, authorized cutover and rollback.
# Documentation/CI-only drift does not justify restarting a healthy production service.
if "${g[@]}" diff --quiet "$local_sha" "$remote_sha" -- gateway/ src/ package.json package-lock.json tsconfig.json deploy/systemd/; then
  printf 'G5_RUNTIME_DELTA=NONE\n'
  printf 'G5_RELEASE_GUARD=GREEN_NO_DEPLOY_NEEDED\n'
else
  printf 'G5_RUNTIME_DELTA=PRESENT\n'
  printf 'G5_RELEASE_GUARD=HOLD_CANDIDATE_BUILD_AND_CUTOVER_REQUIRED\n'
  exit 10
fi
