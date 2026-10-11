#!/usr/bin/env bash
# Root-only local recovery snapshot; never sends credentials off-host or prints their values.
set -Eeuo pipefail
umask 077
[[ "$EUID" -eq 0 ]] || { echo 'G5_BACKUP=RED_ROOT_REQUIRED'; exit 2; }
ROOT=/var/backups/vps-commander
SOURCE=/opt/vps-commander/code
[[ ! -L "$ROOT" && ! -L "$SOURCE" && -d "$SOURCE/.git" ]] || { echo 'G5_BACKUP=RED_SOURCE'; exit 3; }
git_cmd=(git -c safe.directory="$SOURCE" -C "$SOURCE")
[[ -z "$("${git_cmd[@]}" status --porcelain)" ]] || { echo 'G5_BACKUP=RED_DIRTY_SOURCE'; exit 4; }
for unit in vps-commander.service vps-commander-executor.service cloudflared-vps-commander.service cloudflared.service; do
  systemctl is-active --quiet "$unit" || { echo 'G5_BACKUP=RED_INACTIVE_UNIT'; exit 5; }
done
files=(
  etc/systemd/system/vps-commander.service
  etc/systemd/system/vps-commander-executor.service
  etc/systemd/system/cloudflared-vps-commander.service
)
access=etc/systemd/system/vps-commander.service.d/20-access.conf
if [[ -f "/$access" && ! -L "/$access" ]]; then files+=("$access"); else echo 'G5_BACKUP=RED_ACCESS_CONFIG'; exit 6; fi
for p in "${files[@]}"; do
  [[ -f "/$p" && ! -L "/$p" ]] || { echo 'G5_BACKUP=RED_UNEXPECTED_FILE'; exit 6; }
done
install -d -o root -g root -m 0700 "$ROOT"
[[ ! -L "$ROOT" && "$(stat -c '%U:%a' "$ROOT")" = root:700 ]] || { echo 'G5_BACKUP=RED_BACKUP_ROOT'; exit 7; }
snapshot=$(mktemp -d -p "$ROOT" snapshot.XXXXXXXX)
chmod 0700 "$snapshot"
trap 'echo G5_BACKUP=RED_RETAINED_ROOT_ONLY_FOR_DIAGNOSIS >&2' ERR
archive="$snapshot/commander-config.tar.gz"
tar --create --gzip --file "$archive" --directory / --no-recursion -- "${files[@]}"
chmod 0600 "$archive"
{
  printf 'format=1\n'
  printf 'created_at_utc=%s\n' "$(date -u +%FT%TZ)"
  printf 'git_sha=%s\n' "$("${git_cmd[@]}" rev-parse HEAD)"
  printf 'git_branch=%s\n' "$("${git_cmd[@]}" branch --show-current)"
  printf 'archive_sha256=%s\n' "$(sha256sum "$archive" | awk '{print $1}')"
  printf 'offsite_verified=no\n'
  printf 'cloudflared_token_included=no\n'
  printf 'snapshot_scope=commander_units_and_access_config\n'
} > "$snapshot/manifest.txt"
chmod 0600 "$snapshot/manifest.txt"
expected=$(sed -n 's/^archive_sha256=//p' "$snapshot/manifest.txt")
actual=$(sha256sum "$archive" | awk '{print $1}')
[[ "$expected" = "$actual" ]] || { echo 'G5_BACKUP=RED_CHECKSUM'; exit 8; }
tar --list --gzip --file "$archive" > /dev/null
trap - ERR
printf 'G5_BACKUP=GREEN\nG5_BACKUP_SELF_CHECK=PASS\nG5_BACKUP_LOCAL_DIR=%s\nG5_BACKUP_OFFSITE=NO\nG5_BACKUP_CLOUDFLARED_TOKEN=NOT_COPIED\n' "$snapshot"
