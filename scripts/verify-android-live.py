#!/usr/bin/env python3
"""Run Android JNI/Keystore and real Mac-host interop against task-owned synthetic profiles."""
import argparse, hashlib, json, os, pathlib, selectors, shutil, socket, subprocess, tempfile, threading, time

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--serial',required=True)
parser.add_argument('--adb',default='adb')
parser.add_argument('--test-apk',type=pathlib.Path,required=True)
parser.add_argument('--helper',type=pathlib.Path,required=True)
parser.add_argument('--relay',type=pathlib.Path,required=True)
parser.add_argument('--output',type=pathlib.Path,required=True)
args=parser.parse_args()
if args.output.exists():parser.error('output must be a fresh directory')
root=pathlib.Path(__file__).resolve().parents[1];args.output.mkdir(parents=True,mode=0o700)
stage=pathlib.Path(tempfile.mkdtemp(prefix='tether-android-live-'));stage.chmod(0o700)
stop=threading.Event();children=[];listeners=[];installed=False;reverse_port=None;package='app.fledgeling.tether.test'

def adb(*values,input=None,check=True):
 return subprocess.run([args.adb,'-s',args.serial,*values],input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=check,timeout=180)

def unused():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def await_port(port):
 deadline=time.monotonic()+15
 while time.monotonic()<deadline:
  try:
   with socket.create_connection(('127.0.0.1',port),timeout=.2):return
  except OSError:time.sleep(.05)
 raise RuntimeError('owned relay did not listen')

def pairing_line(process):
 selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
 try:
  if not selector.select(15):raise RuntimeError('host pairing window unavailable')
  value=process.stdout.readline().strip()
  if len(value)!=8:raise RuntimeError('host pairing invitation malformed')
  return value
 finally:selector.close()

def echo(tcp):
 s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.settimeout(.2);listeners.append(s)
 if tcp:s.listen()
 def peer(c):
  with c:
   while not stop.is_set():
    data=c.recv(16384)
    if not data:return
    c.sendall(data)
 def run():
  while not stop.is_set():
   try:
    if tcp:
     c,_=s.accept();threading.Thread(target=peer,args=(c,),daemon=True).start()
    else:
     data,p=s.recvfrom(16385);s.sendto(data,p)
   except socket.timeout:pass
   except OSError:return
 threading.Thread(target=run,daemon=True).start();return s.getsockname()[1]

try:
 before=adb('shell','pm','path',package,check=False)
 if before.returncode==0 and before.stdout.strip():raise RuntimeError('test package already installed; preserve existing device data')
 app='app.tether.android.fixture';config=stage/'host.json';port=unused();tcp=echo(True);udp=echo(False)
 subprocess.run([str(args.helper),'host','init','--config',str(config),'--app',app,'--service',f'tcp=tcp://127.0.0.1:{tcp}','--service',f'udp=udp://127.0.0.1:{udp}'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 host_log=(args.output/'host.log').open('wb')
 host=subprocess.Popen([str(args.helper),'host','run','--config',str(config),'--direct',f'127.0.0.1:{port}','--pair'],stdout=subprocess.PIPE,stderr=host_log,text=True);children.append(host)
 code=pairing_line(host)
 cloud_app='app.tether.android.cloudfixture';cloud_config=stage/'cloud-host.json';cloud_port=unused()
 subprocess.run([str(args.helper),'host','init','--config',str(cloud_config),'--app',cloud_app,'--service',f'tcp=tcp://127.0.0.1:{tcp}','--service',f'udp=udp://127.0.0.1:{udp}'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 host_id=subprocess.run([str(args.helper),'host','describe','--config',str(cloud_config)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout.strip()
 relay_log=(args.output/'relay.log').open('wb');relay=subprocess.Popen([str(args.relay),f'127.0.0.1:{cloud_port}','--allow-host',host_id],stdout=subprocess.DEVNULL,stderr=relay_log);children.append(relay);await_port(cloud_port)
 cloud_log=(args.output/'cloud-host.log').open('wb');cloud_host=subprocess.Popen([str(args.helper),'host','run','--config',str(cloud_config),'--relay',f'ws://127.0.0.1:{cloud_port}/v1/relay','--allow-loopback-dev','--pair'],stdout=subprocess.PIPE,stderr=cloud_log,text=True);children.append(cloud_host);cloud_code=pairing_line(cloud_host)
 if f'tcp:{cloud_port}'.encode() in adb('reverse','--list').stdout:raise RuntimeError('chosen reverse route already exists')
 adb('reverse',f'tcp:{cloud_port}',f'tcp:{cloud_port}');reverse_port=cloud_port
 adb('install','-r',str(args.test_apk));installed=True;adb('shell','run-as',package,'mkdir','-p','files')
 fixture=json.dumps({'appId':app,'port':port,'code':code,'cloud':{'appId':cloud_app,'port':cloud_port,'hostId':host_id,'code':cloud_code}}).encode()
 adb('shell','run-as',package,'tee','files/tether-fixture.json',input=fixture)
 adb('shell','run-as',package,'chmod','600','files/tether-fixture.json')
 result=adb('shell','am','instrument','-w','-r','-e','class','app.fledgeling.tether.CoreInstrumentationTest',package+'/androidx.test.runner.AndroidJUnitRunner',check=False)
 # AndroidJUnitRunner prints class/test names and assertion failures, never fixture contents.
 log=result.stdout.decode(errors='replace');(args.output/'instrumentation.log').write_text(log)
 if result.returncode!=0 or 'OK (4 tests)' not in log or 'FAILURES!!!' in log:raise RuntimeError('Android native suite did not pass; read instrumentation.log')
 live=json.loads(adb('shell','run-as',package,'cat','files/tether-live-result.json').stdout)
 required=['pair','wrongCodeRefused','wrongPinRefused','udpEmpty','quicHeartbeatBeyondTTL','leave']
 if not all(live.get(k) is True for k in required) or live.get('tcpBytes')!=131072:raise RuntimeError('live witness did not prove required effects')
 cloud=json.loads(adb('shell','run-as',package,'cat','files/tether-cloud-result.json').stdout)
 if cloud.get('tcpBytes')!=524288 or not all(cloud.get(k) is True for k in ['pair','boundedBackpressure','idleReceiveCancelled','queuedReaderClosed','udpEmpty','leave']):raise RuntimeError('cloud witness did not prove required effects')
 receipt={'schema':'tether.android-native/1','serial':args.serial,'tests':4,'live':live,'cloud':cloud,'scope':'Android guest JNI/Keystore/direct QUIC and local Rust WebSocket relay through owned adb reverse; no physical, internet WAN or cloud-latency claim','testApkSHA256':hashlib.sha256(args.test_apk.read_bytes()).hexdigest()}
 (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
finally:
 stop.set()
 if reverse_port is not None:adb('reverse','--remove',f'tcp:{reverse_port}',check=False)
 for p in children:
  if p.poll() is None:
   p.terminate()
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:p.kill();p.wait()
 for s in listeners:s.close()
 shutil.rmtree(stage)
 if installed:adb('uninstall',package,check=False)
