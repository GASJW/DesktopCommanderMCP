#!/usr/bin/env bash
# G5.2 — encrypt a verified root-only snapshot. The real private age identity is never stored on this VPS.
set -Eeuo pipefail
umask 077
SNAPSHOT="${1:-}"
RECIPIENTS=/etc/vps-commander-backup/recipients.txt
DEST=/var/backups/vps-commander/offsite
ROOT=/var/backups/vps-commander
[[ "$EUID" -eq 0 ]] || { echo 'G5_2_ENCRYPT=RED_ROOT_REQUIRED' >&2; exit 2; }
command -v age >/dev/null || { echo 'G5_2_ENCRYPT=RED_AGE_MISSING' >&2; exit 3; }
[[ -n "$SNAPSHOT" && "$SNAPSHOT" = "$ROOT"/snapshot.* && "$SNAPSHOT" != *'..'* ]] || { echo 'G5_2_ENCRYPT=RED_SNAPSHOT_PATH' >&2; exit 4; }
[[ -d "$SNAPSHOT" && ! -L "$SNAPSHOT" ]] || exit 4
[[ "$(stat -c '%U:%a' "$SNAPSHOT")" = root:700 ]] || exit 4
[[ -f "$SNAPSHOT/commander-config.tar.gz" && -f "$SNAPSHOT/manifest.txt" ]] || exit 4
[[ "$(stat -c '%U:%a' "$SNAPSHOT/commander-config.tar.gz")" = root:600 ]] || exit 4
[[ ! -L "$SNAPSHOT/commander-config.tar.gz" && ! -L "$SNAPSHOT/manifest.txt" ]] || exit 4
[[ -f "$RECIPIENTS" && ! -L "$RECIPIENTS" ]] || { echo 'G5_2_ENCRYPT=RED_RECIPIENT_MISSING' >&2; exit 5; }
[[ "$(stat -c '%U' "$RECIPIENTS")" = root ]] || exit 5
[[ "$(grep -Evc '^(#|$)' "$RECIPIENTS")" = 1 ]] || { echo 'G5_2_ENCRYPT=RED_RECIPIENT_COUNT' >&2; exit 5; }
grep -Eq '^age1[023456789acdefghjklmnpqrstuvwxyz]{55,}$' "$RECIPIENTS" || { echo 'G5_2_ENCRYPT=RED_RECIPIENT_FORMAT' >&2; exit 5; }
expected=$(sed -n 's/^archive_sha256=//p' "$SNAPSHOT/manifest.txt")
actual=$(sha256sum "$SNAPSHOT/commander-config.tar.gz" | awk '{print $1}')
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$expected" = "$actual" ]] || { echo 'G5_2_ENCRYPT=RED_SOURCE_INTEGRITY' >&2; exit 6; }
tar -tzf "$SNAPSHOT/commander-config.tar.gz" >/dev/null
install -d -o root -g root -m 0700 "$DEST"
[[ ! -L "$DEST" && "$(stat -c '%U:%a' "$DEST")" = root:700 ]] || exit 7
task_dir=$(mktemp -d -p "$DEST" encrypted.XXXXXXXX)
chmod 0700 "$task_dir"
cipher="$task_dir/commander-config.tar.gz.age"
age -R "$RECIPIENTS" -o "$cipher" "$SNAPSHOT/commander-config.tar.gz"
chmod 0600 "$cipher"
[[ -s "$cipher" && "$(stat -c '%U:%a' "$cipher")" = root:600 ]] || exit 8
cipher_sha=$(sha256sum "$cipher" | awk '{print $1}')
{
  printf 'format=1\n'
  printf 'created_at_utc=%s\n' "$(date -u +%FT%TZ)"
  printf 'cipher_sha256=%s\n' "$cipher_sha"
  printf 'plaintext_archive_sha256=%s\n' "$expected"
  printf 'encryption=age_x25519\n'
  printf 'key_private_on_vps=no\n'
  printf 'drive_upload_verified=no\n'
  printf 'restore_offsite_verified=no\n'
} > "$task_dir/receipt.txt"
chmod 0600 "$task_dir/receipt.txt"
printf 'G5_2_ENCRYPT=GREEN\n'
printf 'G5_2_ENCRYPTED_ARCHIVE=%s\n' "$cipher"
printf 'G5_2_CIPHERTEXT_SHA256=%s\n' "$cipher_sha"
printf 'G5_2_DRIVE_UPLOAD=PENDING\nG5_2_RESTORE_VERIFIED=PENDING\n'