#!/usr/bin/env bash
# G5 read-only diagnostic, safe as unprivileged MCP executor; no credentials or mutation.
set -u
set -o pipefail
failures=0
warnings=0
fail() { printf 'G5_FAIL=%s\n' "$1"; failures=$((failures+1)); }
warn() { printf 'G5_WARN=%s\n' "$1"; warnings=$((warnings+1)); }
for unit in vps-commander.service vps-commander-executor.service cloudflared-vps-commander.service cloudflared.service; do
  if systemctl is-active --quiet "$unit"; then
    printf 'G5_UNIT_%s=active\n' "${unit%.service}"
  else
    fail "inactive_unit_${unit%.service}"
  fi
done
if [[ "$(systemctl show -P User vps-commander.service 2>/dev/null)" != vpsc-gateway ]]; then fail gateway_uid; fi
if [[ "$(systemctl show -P User vps-commander-executor.service 2>/dev/null)" != vpscommander ]]; then fail executor_uid; fi
gw_env=$(systemctl show -P Environment vps-commander.service 2>/dev/null) || gw_env=''
case " $gw_env " in *"VPS_COMMANDER_AUTH_MODE=access"*) printf 'G5_ACCESS_MODE=access\n';; *) fail access_mode;; esac
case " $gw_env " in *"VPS_COMMANDER_AUDIT_ENABLED=1"*) printf 'G5_AUDIT=enabled\n';; *) fail audit_disabled;; esac
unset gw_env
gw_wants=$(systemctl show -P Wants vps-commander.service 2>/dev/null) || gw_wants=''
gw_requires=$(systemctl show -P Requires vps-commander.service 2>/dev/null) || gw_requires=''
case " $gw_wants " in *" vps-commander-executor.service "*) : ;; *) fail missing_worker_wants;; esac
case " $gw_requires " in *" vps-commander-executor.service "*) fail hard_worker_requires;; esac
unset gw_wants gw_requires
status=$(curl --silent --max-time 4 --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8787/healthz 2>/dev/null) || status=000
if [[ "$status" = 401 ]]; then printf 'G5_ANONYMOUS_HTTP=401\n'; else fail origin_anonymous_http; fi
unset status
if [[ -S /run/vps-commander-ipc/mcp.sock ]]; then printf 'G5_EXECUTOR_SOCKET=present\n'; else fail executor_socket_missing; fi
listeners=$(ss -H -lnt '( sport = :8787 )' 2>/dev/null | awk '{print $4}') || listeners=''
if [[ -z "$listeners" ]]; then
  fail mcp_listener_missing
else
  while IFS= read -r addr; do
    [[ -z "$addr" ]] && continue
    if [[ "$addr" != "127.0.0.1:8787" && "$addr" != "[::1]:8787" ]]; then fail non_loopback_mcp_listener; fi
  done <<< "$listeners"
fi
unset listeners
for name in gateway/server.mjs gateway/audit.mjs gateway/access-auth.mjs; do
  file="/opt/vps-commander/code/$name"
  if [[ ! -f "$file" || -L "$file" ]]; then fail missing_gateway_module; continue; fi
  mode=$(stat -c '%a' "$file" 2>/dev/null) || mode=''
  if [[ "$mode" != 644 ]]; then fail gateway_module_mode; fi
done
disk=$(df -P / 2>/dev/null | awk 'NR==2 {gsub(/%/, "", $5); print $5}') || disk=''
if [[ "$disk" =~ ^[0-9]+$ ]]; then
  printf 'G5_ROOT_DISK_USED_PCT=%s\n' "$disk"
  if ((disk >= 85)); then warn disk_over_85pct; fi
else warn disk_unknown; fi
if [[ -r /proc/pressure/memory ]]; then
  psi=$(awk '$1=="some" {sub(/^avg10=/,"",$2); print $2}' /proc/pressure/memory)
  printf 'G5_MEMORY_PSI_SOME_AVG10=%s\n' "${psi:-unknown}"
fi
if (( failures )); then
  printf 'G5_HEALTH=RED\n'
  exit 1
fi
if (( warnings )); then
  printf 'G5_HEALTH=GREEN_WITH_WARNINGS\n'
else
  printf 'G5_HEALTH=GREEN\n'
fi
printf 'G5_HEALTH_LIMITATION=tunnel_systemd_not_edge_oauth_probe\n'
