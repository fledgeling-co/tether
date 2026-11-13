#!/usr/bin/env python3
"""Owned loopback Rust relay + host, then the web client against them: Node first, then Chromium.
Set TETHER_WEB_BROWSER=0 to skip the browser pass, TETHER_WEB_SHOTS=<dir> to keep screenshots."""
import json, os, pathlib, selectors, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.request

web = pathlib.Path(__file__).resolve().parents[1]
root = web.parents[1]
stage = pathlib.Path(tempfile.mkdtemp(prefix="tether-web-live-", dir="/tmp"))
children, sockets, stop = [], [], threading.Event()

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); return sock.getsockname()[1]

def tcp_echo():
    listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0)); listener.listen(); listener.settimeout(.2); sockets.append(listener)
    def peer(conn):
        with conn:
            while not stop.is_set():
                data = conn.recv(16384)
                if not data: return
                conn.sendall(data)
    def run():
        while not stop.is_set():
            try: conn, _ = listener.accept(); threading.Thread(target=peer, args=(conn,), daemon=True).start()
            except socket.timeout: pass
            except OSError: return
    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]

def start_host(binary, config, relay_url):
    log = open(stage / "host.log", "ab")
    host = subprocess.Popen([str(binary), "host", "run", "--config", str(config), "--relay", relay_url, "--allow-loopback-dev", "--pair"],
                            stdout=subprocess.PIPE, stderr=log, text=True)
    children.append(host)
    selector = selectors.DefaultSelector(); selector.register(host.stdout, selectors.EVENT_READ)
    if not selector.select(15): raise RuntimeError("host pairing window did not open")
    code = host.stdout.readline().strip(); selector.close()
    if len(code) != 8: raise RuntimeError("invalid fixture pairing code")
    time.sleep(1.0)  # let the relay registration settle
    return code

try:
    subprocess.run(["cargo", "build", "-p", "tether", "-p", "tether-relay", "--locked", "--jobs", "2"], cwd=root, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["bash", str(web / "scripts/build.sh")], check=True, stdout=subprocess.DEVNULL)
    binary, relay = root / "target/debug/tether", root / "target/debug/tether-relay"
    app = "app.tether.web-fixture"; config = stage / "host.json"
    subprocess.run([str(binary), "host", "init", "--config", str(config), "--app", app, "--service", f"tcp=tcp://127.0.0.1:{tcp_echo()}"],
                   check=True, stdout=subprocess.DEVNULL)
    host_id = subprocess.check_output([str(binary), "host", "describe", "--config", str(config)], text=True).strip()
    relay_port = port()
    relay_log = open(stage / "relay.log", "wb")
    children.append(subprocess.Popen([str(relay), f"127.0.0.1:{relay_port}", "--allow-open-registration"], stdout=relay_log, stderr=relay_log))
    for _ in range(100):
        try:
            if urllib.request.urlopen(f"http://127.0.0.1:{relay_port}/healthz", timeout=.2).status == 200: break
        except OSError: time.sleep(.05)
    relay_url = f"ws://127.0.0.1:{relay_port}/v1/relay"
    code = start_host(binary, config, relay_url)
    fixture = stage / "fixture.json"
    fixture.write_text(json.dumps({"appID": app, "relayURL": relay_url, "hostID": host_id, "code": code, "binary": str(binary), "hostConfig": str(config)}))
    fixture.chmod(0o600)
    subprocess.run(["node", str(web / "test/live.mjs"), str(fixture)], check=True, timeout=180)
    if os.environ.get("TETHER_WEB_BROWSER", "1") != "0":
        playwright = pathlib.Path(os.environ.get("TETHER_PLAYWRIGHT_ROOT", pathlib.Path.home() / "Dev/dAIolog"))
        env = os.environ.copy(); env.update({"TETHER_WEB_FIXTURE": str(fixture), "TETHER_WEB_DIST": str(web / "dist"),
                                             "TETHER_WEB_SHOTS": os.environ.get("TETHER_WEB_SHOTS", str(stage / "shots"))})
        # Playwright resolves from the working directory's node_modules.
        subprocess.run(["node", str(web / "test/browser.mjs")], cwd=playwright, env=env, check=True, timeout=240)
    print("web live checks passed")
finally:
    stop.set()
    for child in reversed(children):
        child.terminate()
        try: child.wait(timeout=3)
        except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
    for sock in sockets: sock.close()
    if os.environ.get("TETHER_WEB_KEEP") != "1": shutil.rmtree(stage)
    else: print(f"kept {stage}", file=sys.stderr)
