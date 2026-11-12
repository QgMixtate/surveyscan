#!/usr/bin/env python3
"""Live auth regression for C06 binary/CLI/HTTP checks using one temporary, owned development database."""
import http.cookiejar,json,os,secrets,socket,subprocess,time,urllib.request,urllib.error,uuid
from pathlib import Path
from dev import compose,ROOT,STATE,initialize

def main():
 initialize();db='ssv2smoke_'+uuid.uuid4().hex;tenant=str(uuid.uuid4());checks=[];proc=None
 password=secrets.token_urlsafe(32);password_file=STATE/('auth-smoke-password-'+uuid.uuid4().hex)
 fd=os.open(password_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:f.write(password+'\n')
 with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
 origin=f'http://127.0.0.1:{port}'
 env=dict(os.environ,SURVEYSCAN_V2_DATABASE_URL=f'postgres://surveyscan_v2@127.0.0.1:55432/{db}?sslmode=disable',SURVEYSCAN_V2_DATABASE_PASSWORD_FILE=str(STATE/'pg_password'),SURVEYSCAN_V2_PUBLIC_ORIGIN=origin,SURVEYSCAN_V2_INSECURE_LOCAL_HTTP='1',SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{port}',SURVEYSCAN_V2_BAO_ADDR='http://127.0.0.1:58200')
 binary=str(ROOT/'.dist/surveyscan-server');created=False
 def sql(query):return compose('exec','-T','db','psql','-U','surveyscan_v2','-d','surveyscan_v2','-v','ON_ERROR_STOP=1','-Atc',query,capture=True).strip()
 def command(*args,want=0):
  result=subprocess.run([binary,*args],cwd=ROOT,env=env,capture_output=True,text=True,timeout=20)
  assert result.returncode==want,'console/migration unexpected exit'
  assert password not in result.stdout+result.stderr,'credential appeared in console output'
  return result.stdout
 jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar))
 def request(method,path,data=None,csrf=None,origin_header=origin):
  headers={'Origin':origin_header}
  if csrf:headers['X-CSRF-Token']=csrf
  if data is not None:headers['Content-Type']='application/json'
  req=urllib.request.Request(origin+path,data=None if data is None else json.dumps(data).encode(),headers=headers,method=method)
  try:
   with client.open(req,timeout=6) as r:return r.status,r.read()
  except urllib.error.HTTPError as e:return e.code,e.read()
 def wait():
  for _ in range(60):
   try:
    if request('GET','/health/ready')[0]==200:return
   except OSError:pass
   time.sleep(.2)
  raise RuntimeError('C05 server did not become ready')
 def start():
  nonlocal proc
  with (STATE/'auth-smoke-server.log').open('ab') as log:proc=subprocess.Popen([binary,'serve'],cwd=ROOT,env=env,stdout=log,stderr=log)
  wait()
 def stop():
  nonlocal proc
  if proc is not None:
   proc.terminate()
   try:proc.wait(timeout=7)
   except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=3)
   proc=None
 try:
  sql('CREATE DATABASE '+db);created=True
  assert 'applied_migrations=47' in command('migrate')
  assert 'applied_migrations=0' in command('migrate');checks.append('binary migrate and repeat')
  base=['--tenant',tenant,'--username','admin','--password-file',str(password_file)]
  command('bootstrap-admin',*base,'--tenant-name','C05 binary smoke')
  command('bootstrap-admin',*base,'--tenant-name','C05 binary smoke',want=1);checks.append('CLI bootstrap once; no credential in output')
  command('create-user','--tenant',tenant,'--username','viewer','--role','viewer','--password-file',str(password_file));checks.append('CLI provision viewer')
  start();assert request('GET','/api/v1/assets')[0]==401
  assert request('POST','/api/v1/auth/sessions',{'username':'admin','password':password},origin_header='http://untrusted.invalid')[0]==403
  code,body=request('POST','/api/v1/auth/sessions',{'username':'admin','password':password});assert code==201;session=json.loads(body);checks.append('live login and origin policy')
  assert request('GET','/api/v1/assets')[0]==200
  assert request('POST','/api/v1/jobs',{})[0]==403
  assert request('POST','/api/v1/jobs',{},csrf=session['csrf_token'])[0]==501;checks.append('auth/CSRF gate before future domain handlers')
  stop();start();assert request('GET','/api/v1/assets')[0]==200;checks.append('session survives real server process restart')
  code,body=request('POST','/api/v1/auth/tokens',{'name':'smoke','expires_in_seconds':60,'scopes':['assets:read']},csrf=session['csrf_token']);assert code==201;token=json.loads(body)
  assert request('DELETE','/api/v1/auth/tokens/'+token['token_id'],csrf=session['csrf_token'])[0]==204;checks.append('live token issue/revoke')
  assert request('DELETE','/api/v1/auth/session',csrf=session['csrf_token'])[0]==204
  assert request('GET','/api/v1/assets')[0]==401;checks.append('live logout revokes session')
  code,body=request('POST','/api/v1/auth/sessions',{'username':'viewer','password':password});assert code==201;viewer=json.loads(body)
  assert request('POST','/api/v1/jobs',{},csrf=viewer['csrf_token'])[0]==403;checks.append('viewer mutation forbidden')
  command('set-user-state','--tenant',tenant,'--username','viewer','--role','viewer','--enabled=false')
  assert request('GET','/api/v1/assets')[0]==401;checks.append('console disable revokes active HTTP session')
  report={'package':'C06','status':'passed','count':len(checks),'checks':checks,'target':'real compiled Go binary + isolated PG + local Bao; HTTP allowed only with explicit dev flag','private_material':'temporary password removed; no credential in report'}
  (STATE/'auth-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
 finally:
  stop();password_file.unlink(missing_ok=True)
  if created:sql('DROP DATABASE '+db+' WITH (FORCE)')
if __name__=='__main__':main()
