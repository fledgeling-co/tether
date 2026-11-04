#!/usr/bin/env python3
"""Synthetic helper protocol fixture; no network, cryptography or private host configuration."""
import json
import pathlib
import sys
import os
import signal
import time

args = sys.argv[1:]
command = args[1]
app = args[args.index('--expected-app') + 1]
config = pathlib.Path(args[args.index('--config') + 1])

def output(value):
    print(json.dumps(value), flush=True)

def payload(command):
    if command == 'inspect':
        return {'app_id': app, 'host_id': 'a' * 52, 'services': [{'id': 'api', 'kind': 'tcp'}]}
    if command == 'clients':
        return []
    if command == 'pairing-status':
        return {'open': True, 'expires_in_seconds': 299, 'attempts_remaining': 3}
    if command == 'pair-code':
        return {'code': 'ABCDEFGH', 'expires_in_seconds': 299, 'attempts_remaining': 3}
    return {}

if command == 'inspect':
    output(payload(command))
elif command == 'run':
    output({'event': 'listening', 'address': args[args.index('--direct') + 1]})
    if config.name == 'stalled.json' and not config.with_suffix('.graceful').exists():
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        config.with_suffix('.pid').write_text(str(os.getpid()))
        while True:
            time.sleep(1)
    for line in sys.stdin:
        request = json.loads(line)
        with config.with_suffix('.requests').open('a') as calls:
            calls.write(request['command'] + '\n')
        output({'event': 'reply', 'request_id': request['request_id'], 'ok': request['expected_app'] == app,
                'payload': payload(request['command'])})
    config.with_suffix('.closed').write_text('stdin closed')
