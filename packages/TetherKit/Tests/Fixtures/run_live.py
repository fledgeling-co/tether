#!/usr/bin/env python3
"""Owned loopback Rust relay/host + Swift SDK integration; no real Keychain/configuration."""
import base64, json, os, pathlib, selectors, shutil, socket, struct, subprocess, tempfile, threading, time, urllib.request

root = pathlib.Path(__file__).resolve().parents[4]
stage = pathlib.Path(tempfile.mkdtemp(prefix="tether-swift-live-", dir="/tmp"))
children = []
stop = threading.Event()
sockets = []

def exact(sock, length):
    value = b""
    while len(value) < length:
        chunk = sock.recv(length-len(value))
        if not chunk: raise RuntimeError("fixture connection closed")
        value += chunk
    return value

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        return sock.getsockname()[1]

def tcp_echo():
    listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(("127.0.0.1",0)); listener.listen(); listener.settimeout(.2); sockets.append(listener)
    def peer(conn):
        with conn:
            while not stop.is_set():
                data = conn.recv(16384)
                if not data: return
                conn.sendall(data)
    def run():
        while not stop.is_set():
            try: conn,_=listener.accept(); threading.Thread(target=peer,args=(conn,),daemon=True).start()
            except socket.timeout: pass
            except OSError: return
    threading.Thread(target=run,daemon=True).start()
    return listener.getsockname()[1]

def udp_echo():
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(("127.0.0.1",0));sock.settimeout(.2);sockets.append(sock)
    def run():
        while not stop.is_set():
            try: data,peer=sock.recvfrom(16385);sock.sendto(data,peer)
            except socket.timeout: pass
            except OSError: return
    threading.Thread(target=run,daemon=True).start()
    return sock.getsockname()[1]

def relay_ready(relay_port, app, host):
    try:
        with socket.create_connection(("127.0.0.1",relay_port),timeout=1) as sock:
            sock.settimeout(1)
            key=base64.b64encode(os.urandom(16)).decode()
            sock.sendall((f"GET /v1/relay HTTP/1.1\r\nHost: 127.0.0.1:{relay_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
            header=b""
            while not header.endswith(b"\r\n\r\n"): header+=exact(sock,1)
            if not header.startswith(b"HTTP/1.1 101"): return False
            value=json.dumps({"type":"client","app_id":app,"host_id":host}).encode()
            mask=os.urandom(4)
            frame=bytes([0x81,0x80|len(value)]) if len(value)<126 else bytes([0x81,0xfe])+struct.pack("!H",len(value))
            sock.sendall(frame+mask+bytes(b^mask[i%4] for i,b in enumerate(value)))
            frame=exact(sock,2);length=frame[1]&127
            if length==126:length=struct.unpack("!H",exact(sock,2))[0]
            if length>2048:return False
            return json.loads(exact(sock,length)).get("type")=="ready"
    except (OSError, ValueError, RuntimeError):return False

try:
    binary=root/"target/debug/tether";relay=root/"target/debug/tether-relay"
    if not binary.is_file() or not relay.is_file():raise RuntimeError("build tether and tether-relay first")
    app="app.tether.swift-fixture";config=stage/"host.json";api_echo=tcp_echo()
    subprocess.run([str(binary),"host","init","--config",str(config),"--app",app,
        "--service",f"tcp=tcp://127.0.0.1:{api_echo}","--service",f"udp=udp://127.0.0.1:{udp_echo()}"],check=True,stdout=subprocess.DEVNULL)
    host_id=subprocess.check_output([str(binary),"host","describe","--config",str(config)],text=True).strip()
    relay_port=port();direct_port=port()
    relay_log=open(stage/"relay.log","wb")
    relay_process=subprocess.Popen([str(relay),f"127.0.0.1:{relay_port}","--allow-open-registration"],stdout=relay_log,stderr=relay_log)
    children.append(relay_process)
    for _ in range(100):
        try:
            if urllib.request.urlopen(f"http://127.0.0.1:{relay_port}/healthz",timeout=.2).status==200:break
        except OSError:time.sleep(.05)
    relay_url=f"ws://127.0.0.1:{relay_port}/v1/relay"
    host_log=open(stage/"host.log","wb")
    host=subprocess.Popen([str(binary),"host","run","--config",str(config),"--direct",f"127.0.0.1:{direct_port}",
        "--relay",relay_url,"--allow-loopback-dev","--pair"],stdout=subprocess.PIPE,stderr=host_log,text=True)
    children.append(host)
    selector=selectors.DefaultSelector();selector.register(host.stdout,selectors.EVENT_READ)
    if not selector.select(15):raise RuntimeError("host pairing window did not open")
    code=host.stdout.readline().strip();selector.close()
    if len(code)!=8:raise RuntimeError("invalid fixture pairing code")
    for _ in range(100):
        if relay_ready(relay_port,app,host_id):break
        if host.poll() is not None:raise RuntimeError("fixture host stopped")
        time.sleep(.05)
    else:raise RuntimeError("fixture relay route did not become ready")
    fixture=stage/"fixture.json"
    fixture.write_text(json.dumps({"appID":app,"relayURL":relay_url,"hostID":host_id,"directPort":direct_port,"ownerPort":port(),"otherOwnerPort":port(),"apiEchoPort":api_echo,
                                  "code":code,"binary":str(binary),"hostConfig":str(config)}))
    fixture.chmod(0o600)
    env=os.environ.copy();env["TETHER_SWIFT_LIVE_FIXTURE"]=str(fixture)
    log=open("/tmp/tether-swift-live-tests.log","wb")
    run=subprocess.run(["swift","test","--package-path",str(root/"packages/TetherKit"),"--jobs",env.get("TETHER_SWIFT_JOBS","2"),"--filter","ClientLiveTests"],
                       cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240)
    if run.returncode:raise RuntimeError("Swift SDK live checks failed; see /tmp/tether-swift-live-tests.log")
    print("Swift SDK live relay/direct checks passed")
finally:
    stop.set()
    for child in reversed(children):
        child.terminate()
        try:child.wait(timeout=3)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
    for sock in sockets:sock.close()
    shutil.rmtree(stage)
