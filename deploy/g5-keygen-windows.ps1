# G5.2 - Run ONLY on the owner's Windows recovery device (Gui-PC), never on VPS.
# Requires age-keygen installed and available in PATH. Do not paste identity file into chat.
$ErrorActionPreference = 'Stop'
if (-not (Get-Command age-keygen -ErrorAction SilentlyContinue)) {
    throw 'Install age locally before running this script (age-keygen unavailable).'
}
$dir = Join-Path $env:LOCALAPPDATA 'VPS-Commander\Recovery'
$key = Join-Path $dir 'commander-age-identity.txt'
if (Test-Path -LiteralPath $key) {
    throw 'Existing identity found; refusing to rotate or overwrite. Preserve old backups.'
}
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $dir /inheritance:r /grant:r "*${sid}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to restrict recovery directory ACL.' }
& age-keygen -o $key 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Key generation failed.' }
& icacls.exe $key /inheritance:r /grant:r "*${sid}:F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to restrict private identity ACL.' }
Write-Output 'G5_2_OFF_VPS_KEY=CREATED'
Write-Output ('PRIVATE_IDENTITY_PATH=' + $key)
Write-Output 'PUBLIC_RECIPIENT='
& age-keygen -y $key
if ($LASTEXITCODE -ne 0) { throw 'Unable to derive public recipient.' }
Write-Output 'ACTION=Store private identity in a secure password manager or offline storage; do not upload to Drive or paste into ChatGPT.'
