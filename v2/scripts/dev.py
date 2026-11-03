#!/usr/bin/env python3
"""Local Linux development only. No production deployment and no application credentials printed."""
from pathlib import Path
import argparse,json,os,secrets,stat,subprocess,time,urllib.request,urllib.error,sys
ROOT=Path(__file__).resolve().parents[1];STATE=ROOT/'.local'
DOCKER=['docker','--host=unix:///var/run/docker.sock','compose','--project-name','surveyscan-v2-c04','--file',str(ROOT/'deploy/compose.yaml')]
ENV=dict(os.environ,DEV_UID=str(os.getuid()),DEV_GID=str(os.getgid()))
for key in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):ENV.pop(key,None)
def compose(*args,capture=False):
 return subprocess.run(DOCKER+list(args),cwd=ROOT,env=ENV,check=True,text=True,stdout=subprocess.PIPE if capture else None).stdout

def private_json(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(data,f);f.flush();os.fsync(f.fileno())
def initialize():
 STATE.mkdir(mode=0o700,exist_ok=True);os.chmod(STATE,0o700)
 secret=STATE/'pg_password'
 if not secret.exists():
  fd=os.open(secret,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as f:f.write(secrets.token_urlsafe(32)+'\n')
 info=secret.stat()
 if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)&0o077:raise RuntimeError('private pg_password file required')

def bao_request(path,data=None):
 request=urllib.request.Request('http://127.0.0.1:58200'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method='GET' if data is None else 'PUT')
 with urllib.request.urlopen(request,timeout=60 if path=='/v1/sys/init' and data is not None else 5) as response:return json.load(response)
def unseal():
 for _ in range(60):
  try:status=bao_request('/v1/sys/init');break
  except (OSError,ValueError):time.sleep(.5)
 else:raise RuntimeError('OpenBao API did not become reachable')
 keyfile=STATE/'bao-init.json'
 if not status['initialized']:
  if keyfile.exists():raise RuntimeError('OpenBao storage is new but bootstrap file already exists; inspect volume identity before recovery')
  initial=bao_request('/v1/sys/init',{'secret_shares':1,'secret_threshold':1})
  private_json(keyfile,initial)
 if bao_request('/v1/sys/seal-status')['sealed']:
  if not keyfile.exists():raise RuntimeError('OpenBao initialized but local unseal file missing; restore authorized unseal material, do not reset volume')
  if stat.S_IMODE(keyfile.stat().st_mode)&0o077:raise RuntimeError('OpenBao bootstrap file permissions must be private')
  initial=json.loads(keyfile.read_text());key=initial.get('keys_base64',initial.get('keys'))[0]
  result=bao_request('/v1/sys/unseal',{'key':key})
  if result['sealed']:raise RuntimeError('OpenBao remained sealed')
 print('OpenBao initialized/unsealed; bootstrap material remains private outside source control.')

def up():
 initialize()
 if not (ROOT/'.dist/surveyscan-server').exists():raise RuntimeError('Build v2 binaries first: make build')
 compose('up','--detach','db','bao');unseal()
 compose('build','backend','migrate')
 compose('run','--rm','migrate')
 compose('up','--detach','--wait','backend','edge')
 print('C06 infrastructure ready; registry/auth available; machine transport pending C07.')
def testenv():
 initialize();env=dict(ENV)
 env['SURVEYSCAN_TEST_DATABASE_URL']='postgres://surveyscan_v2@127.0.0.1:55432/surveyscan_v2?sslmode=disable'
 env['SURVEYSCAN_TEST_DATABASE_PASSWORD_FILE']=str(STATE/'pg_password')
 return env

def main():
 parser=argparse.ArgumentParser();parser.add_argument('action',choices=['init','up','down','status','integration','unseal']);args=parser.parse_args()
 if args.action=='init':initialize()
 elif args.action=='up':up()
 elif args.action=='down':compose('down') # keep all named volumes
 elif args.action=='status':compose('ps')
 elif args.action=='unseal':unseal()
 elif args.action=='integration':
  go=os.environ.get('GO','go')
  subprocess.run([go,'test','-mod=readonly','-tags=integration','-count=1','-p','2','./...'],cwd=ROOT,env=testenv(),check=True)
if __name__=='__main__':
 try:main()
 except RuntimeError as error:
  print(str(error),file=sys.stderr);raise SystemExit(1)
 except subprocess.CalledProcessError:
  print('Development operation failed; inspect component status and private local state. No credentials are printed.',file=sys.stderr);raise SystemExit(1)
 except Exception:
  print('Development operation failed; verify local service/configuration without dumping secrets.',file=sys.stderr);raise SystemExit(1)
