#!/usr/bin/env bash
# G5.2 — upload an already-encrypted age snapshot to a dedicated rclone-managed Drive folder.
# Requires separate user-granted OAuth with scope=drive.file; never uses ChatGPT OAuth.
set -Eeuo pipefail
umask 077
CIPHER="${1:-}"
ROOT=/var/backups/vps-commander/offsite
CONF=/etc/vps-commander-backup/rclone.conf
REMOTE=vpscmdbackup
[[ "$EUID" -eq 0 ]] || { echo 'G5_2_UPLOAD=RED_ROOT_REQUIRED' >&2; exit 2; }
command -v rclone >/dev/null || exit 3
[[ -n "$CIPHER" && "$CIPHER" = "$ROOT"/encrypted.*/commander-config.tar.gz.age && "$CIPHER" != *'..'* ]] || exit 4
[[ -f "$CIPHER" && ! -L "$CIPHER" && "$(stat -c '%U:%a' "$CIPHER")" = root:600 ]] || exit 4
[[ -f "$CONF" && ! -L "$CONF" && "$(stat -c '%U:%a' "$CONF")" = root:600 ]] || {
  echo 'G5_2_UPLOAD=RED_RCLONE_OAUTH_NOT_CONFIGURED' >&2; exit 5;
}
# The drive.file scope restricts rclone to files/folders it creates; it cannot access
# the Commander folder created separately by ChatGPT's Google Drive connector.
awk -v name="[$REMOTE]" '
  $0==name {section=1;found=1;next}
  /^\[/ {section=0}
  section && /^type = drive$/ {drive=1}
  section && /^scope = drive.file$/ {scope=1}
  section && /^root_folder_id = [A-Za-z0-9_-]+$/ {folder=1}
  END {exit !(found && drive && scope && folder)}
' "$CONF" || { echo 'G5_2_UPLOAD=RED_SCOPE_OR_FOLDER' >&2; exit 6; }
[[ -f "$(dirname "$CIPHER")/receipt.txt" ]] || exit 4
expected=$(sed -n 's/^cipher_sha256=//p' "$(dirname "$CIPHER")/receipt.txt")
actual=$(sha256sum "$CIPHER" | awk '{print $1}')
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" = "$expected" ]] || { echo 'G5_2_UPLOAD=RED_LOCAL_DIGEST' >&2; exit 7; }
# Do not overwrite or delete remote snapshots. Use a content-addressed unique name.
remote_path="commander-$(date -u +%Y%m%dT%H%M%SZ)-${expected:0:16}.tar.gz.age"
rclone --config "$CONF" copyto --immutable --no-traverse --retries 2 --low-level-retries 2 --transfers 1 -- "$CIPHER" "$REMOTE:$remote_path" >/dev/null
# Byte-for-byte ciphertext verification via Google Drive. No decryption on the VPS.
remote_sha=$(rclone --config "$CONF" cat -- "$REMOTE:$remote_path" | sha256sum | awk '{print $1}')
[[ "$remote_sha" = "$expected" ]] || { echo 'G5_2_UPLOAD=RED_REMOTE_DIGEST' >&2; exit 8; }
printf 'G5_2_DRIVE_UPLOAD=GREEN\nG5_2_DRIVE_SHA256=PASS\n'
printf 'G5_2_DRIVE_REMOTE_FILE=%s\n' "$remote_path"
printf 'G5_2_RESTORE_VERIFIED=PENDING_EXTERNAL_KEY\n'