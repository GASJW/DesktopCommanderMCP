#!/usr/bin/env python3
"""Read-only G3.2 journal certification. Accepts journalctl -o cat on stdin."""
import json
import re
import sys
from collections import Counter

FIELDS = {
    'event', 'version', 'request_id', 'started_at', 'duration_ms',
    'identity', 'route', 'http_method', 'operation', 'tool',
    'http_status', 'outcome',
}
REQUIRED = {'start_process', 'write_file', 'read_file'}
KNOWN_TOOLS = REQUIRED | {'list_directory'}
ALLOWED_ROUTES = {'mcp', 'healthz', 'other'}
ALLOWED_OUTCOMES = {
    'ok', 'denied', 'invalid_request', 'tool_error',
    'rpc_error', 'unavailable', 'disconnected', 'other',
}
counts = Counter()
successes = set()
invalid = 0
lines_seen = 0

for line in sys.stdin:
    if 'vps_commander_audit' not in line:
        continue
    lines_seen += 1
    try:
        entry = json.loads(line.strip())
        if not isinstance(entry, dict) or set(entry) != FIELDS:
            raise ValueError('wrong fields')
        if entry['event'] != 'vps_commander_audit' or entry['version'] != 1:
            raise ValueError('wrong schema')
        if not re.fullmatch(r'[0-9a-f-]{36}', entry['request_id']):
            raise ValueError('bad request id')
        if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d.*Z', entry['started_at']):
            raise ValueError('bad timestamp')
        if not isinstance(entry['duration_ms'], int) or entry['duration_ms'] < 0:
            raise ValueError('bad duration')
        if not isinstance(entry['http_status'], int) or not 100 <= entry['http_status'] <= 599:
            raise ValueError('bad status')
        if not (re.fullmatch(r'cf_[a-f0-9]{24}', entry['identity']) or
                entry['identity'] in ('anonymous', 'local-authenticated')):
            raise ValueError('bad identity')
        if (entry['route'] not in ALLOWED_ROUTES or
                entry['http_method'] not in ('GET', 'POST', 'OPTIONS', 'HEAD', 'DELETE', 'other') or
                entry['outcome'] not in ALLOWED_OUTCOMES):
            raise ValueError('bad metadata')
        if not isinstance(entry['operation'], str) or len(entry['operation']) > 60:
            raise ValueError('bad operation')
        if entry['tool'] is not None and (
                not isinstance(entry['tool'], str) or
                not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,79}', entry['tool'])):
            raise ValueError('bad tool')
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        invalid += 1
        continue
    counts['valid'] += 1
    if entry['outcome'] == 'denied':
        counts['denied'] += 1
    if entry['identity'].startswith('cf_'):
        counts['verified_identity'] += 1
    if (entry['operation'] == 'tools/call' and
            entry['tool'] in REQUIRED and entry['route'] == 'mcp' and
            entry['http_method'] == 'POST' and entry['http_status'] == 200 and
            entry['identity'].startswith('cf_') and entry['outcome'] == 'ok'):
        successes.add(entry['tool'])

print('G3_2_JOURNAL_EVENTS=' + str(lines_seen))
print('G3_2_JOURNAL_VALID=' + str(counts['valid']))
print('G3_2_JOURNAL_VERIFIED_PRINCIPAL=' + str(counts['verified_identity']))
print('G3_2_JOURNAL_DENIED=' + str(counts['denied']))
for name in sorted(REQUIRED):
    print('G3_2_TOOL_' + name.upper() + '=' + ('PASS' if name in successes else 'MISSING'))
print('G3_2_SCHEMA_VIOLATIONS=' + str(invalid))
accepted = not invalid and successes == REQUIRED and counts['verified_identity'] >= 3
print('G3_2_JOURNAL_CERTIFICATION=' + ('GREEN' if accepted else 'RED'))
raise SystemExit(0 if accepted else 1)
