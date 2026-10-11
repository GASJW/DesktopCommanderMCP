#!/usr/bin/env python3
"""Read-only audit of G3.3 gateway recovery transitions from journald stdin."""
import json
import sys

required = ('disconnected', 'retry_scheduled', 'reconnected')
events = []
invalid = 0
for line in sys.stdin:
    if 'vps_commander_recovery' not in line:
        continue
    try:
        obj = json.loads(line.strip())
        if (not isinstance(obj, dict) or set(obj) !=
                {'event', 'version', 'phase', 'attempt', 'retry_delay_ms'}):
            raise ValueError('fields')
        if obj['event'] != 'vps_commander_recovery' or obj['version'] != 1:
            raise ValueError('version')
        if obj['phase'] not in required or
                not isinstance(obj['attempt'], int) or obj['attempt'] < 0 or
                not isinstance(obj['retry_delay_ms'], int) or
                not 0 <= obj['retry_delay_ms'] <= 8000:
            raise ValueError('value')
        events.append(obj['phase'])
    except (json.JSONDecodeError, ValueError, TypeError, KeyError):
        invalid += 1

idx = 0
for phase in events:
    if idx < len(required) and phase == required[idx]:
        idx += 1
ok = idx == len(required) and invalid == 0
print('G3_3_RECOVERY_EVENTS=' + str(len(events)))
for phase in required:
    print('G3_3_PHASE_' + phase.upper() + '=' + ('PASS' if phase in events else 'MISSING'))
print('G3_3_RECOVERY_SCHEMA_VIOLATIONS=' + str(invalid))
print('G3_3_SYSTEMD_RECOVERY_EVENTS=' + ('GREEN' if ok else 'RED'))
raise SystemExit(0 if ok else 1)
