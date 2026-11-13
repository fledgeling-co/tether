#!/usr/bin/env python3
"""Android nearby pairing against a task-owned Rust host whose owner approves once the device has.

The emulator reaches the Mac's loopback at 10.0.2.2, so the host listens on 127.0.0.1. The owner's
approval goes through the host's owner control socket, as the Mac and Windows apps send it."""
import argparse, glob, json, os, pathlib, shutil, socket, subprocess, tempfile, threading, time, uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--serial', required=True)
parser.add_argument('--adb', default='adb')
parser.add_argument('--test-apk', type=pathlib.Path, required=True)
parser.add_argument('--helper', type=pathlib.Path, required=True)
args = parser.parse_args()
package = 'app.fledgeling.tether.test'
app = 'app.tether.android-nearby'
stage = pathlib.Path(tempfile.mkdtemp(prefix='tether-android-nearby-')); stage.chmod(0o700)
stop = threading.Event(); children = []; installed = False; approvals = []

def adb(*values, input=None, check=True):
    return subprocess.run([args.adb, '-s', args.serial, *values], input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check, timeout=300)

def unused():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]

def owner(path, request):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(1); s.connect(path)
        s.sendall((json.dumps({'v': 1, 'request_id': str(uuid.uuid4()), 'expected_app': app, **request}) + '\n').encode())
        return json.loads(s.recv(65536).decode())

def approve_when_device_has(sockets_before):
    # Approve only requests the device has already approved, so the device's own rule is what's tested.
    while not stop.is_set():
        for path in set(glob.glob(f'/tmp/tether-{os.getuid()}/*.sock')) - sockets_before:
            try:
                for r in (owner(path, {'command': 'nearby'}).get('payload') or {}).get('requests', []):
                    if r.get('client_approved') and r['id'] not in approvals:
                        owner(path, {'command': 'nearby-decide', 'nearby_id': r['id'], 'approve': True}); approvals.append(r['id'])
            except (OSError, ValueError, KeyError): pass
        time.sleep(0.3)

try:
    if adb('shell', 'pm', 'path', package, check=False).stdout.strip(): raise RuntimeError('test package already installed; preserve existing device data')
    config = stage / 'host.json'; port = unused()
    subprocess.run([str(args.helper), 'host', 'init', '--config', str(config), '--app', app, '--service', 'tcp=tcp://127.0.0.1:9'], check=True, stdout=subprocess.DEVNULL)
    before = set(glob.glob(f'/tmp/tether-{os.getuid()}/*.sock'))
    children.append(subprocess.Popen([str(args.helper), 'host', 'run', '--config', str(config), '--direct', f'127.0.0.1:{port}'],
                                     stdout=subprocess.DEVNULL, stderr=(stage / 'host.log').open('wb')))
    threading.Thread(target=approve_when_device_has, args=(before,), daemon=True).start()
    adb('install', '-r', str(args.test_apk)); installed = True
    adb('shell', 'run-as', package, 'mkdir', '-p', 'files')
    adb('shell', 'run-as', package, 'tee', 'files/tether-nearby-fixture.json', input=json.dumps({'appId': app, 'port': port}).encode())
    result = adb('shell', 'am', 'instrument', '-w', '-r', '-e', 'class', 'app.fledgeling.tether.CoreInstrumentationTest#liveRustHostNearbyPairingNeedsBothApprovals',
                 package + '/androidx.test.runner.AndroidJUnitRunner', check=False)
    log = result.stdout.decode(errors='replace')
    if result.returncode != 0 or 'OK (1 test)' not in log: raise RuntimeError('nearby test did not pass:\n' + log[-2000:])
    if len(approvals) != 1: raise RuntimeError(f'expected one owner approval, saw {len(approvals)}')
    print('Android nearby pairing passed: one code, both approvals, then leave')
finally:
    stop.set()
    for p in children:
        p.terminate()
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
    if installed: adb('uninstall', package, check=False)
    shutil.rmtree(stage)
