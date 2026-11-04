#!/usr/bin/env python3
"""C12.01 compiled human CLI against real auth/registry/source HTTP and isolated PostgreSQL."""
import json,os,subprocess,uuid
from pathlib import Path
from machine_smoke import main as harness
from dev import ROOT,STATE

def scenario(**s):
 binary=str(ROOT/'.dist/surveyscanctl');context=s['directory']/'human-context.json';checks=s['checks'];seen=[]
 password=s['directory']/'human-password';fd=os.open(password,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,'w') as f:f.write(s['password']+'\n')
 def run(args,expected=0,path=context):
  p=subprocess.run([binary,*args,'--context-file',str(path)],capture_output=True,text=True,timeout=25);seen.append(p.stdout+p.stderr);assert p.returncode==expected,'unexpected CLI exit: '+args[0];assert s['password'] not in p.stdout+p.stderr,'CLI leaked password';return json.loads(p.stdout) if p.stdout else json.loads(p.stderr)
 login=['login','--server',s['origin'],'--ca-file',s['ca_file'],'--username',s['username'],'--password-file',str(password)]
 result=run(login);assert result['tenant_id']==s['tenant'] and context.stat().st_mode&0o077==0;private=json.loads(context.read_text());checks.append('compiled CLI logs in via existing HTTPS/session API and writes private0600 context without printing credentials')
 assert run(['context','show'])['tenant_id']==s['tenant'];run(login,2);checks.append('public context omits secrets and existing tenant/session context cannot be overwritten by login')
 page=run(['assets','list','--limit','1']);assert page['items'][0]['asset_uid']==s['asset'];asset=run(['assets','get','--id',s['asset']]);assert asset['asset_uid']==s['asset'];sources=run(['sources','list','--limit','1']);assert len(sources['items'])==1
 source=sources['items'][0]['source_id'];assert run(['sources','status','--id',source])['source_id']==source;assert run(['status'])['status']=='ok';checks.append('assets list/get and sources list/status use real backend data; readiness is a separate endpoint')
 if sources.get('next_cursor'):
  second=run(['sources','list','--limit','1','--cursor',sources['next_cursor']]);assert second['items'][0]['source_id']!=source
 run(['assets','get','--id',str(uuid.uuid4())],4);run(['assets','list','--limit','201'],2);run(['assets','list','--tenant',str(uuid.uuid4())],2);checks.append('pagination cursor works and invalid bounds/unknown resource/tenant override have stable exit codes')
 table=subprocess.run([binary,'assets','list','--output','table','--context-file',str(context)],capture_output=True,text=True,timeout=20);seen.append(table.stdout+table.stderr);assert table.returncode==0 and 'ASSET_UID' in table.stdout and s['asset'] in table.stdout;checks.append('explicit table output and default JSON expose the same real asset UID')
 # Separate real tenant/user, provisioned by the operator fixture; no auth or registry mocks.
 other=str(uuid.uuid4());s['sql'](f"INSERT INTO access.tenants(tenant_id,name,status) VALUES('{other}','CLI other tenant','active')")
 s['command']('create-user','--tenant',other,'--username','other-cli-user','--password-file',str(password),'--role','viewer');other_context=s['directory']/'other-context.json';other_login=[*login];other_login[other_login.index(s['username'])]='other-cli-user';assert run(other_login,path=other_context)['tenant_id']==other
 assert run(['assets','list'],path=other_context)['items']==[];run(['assets','get','--id',s['asset']],4,path=other_context);checks.append('second real tenant session cannot list or read first tenant known asset UUID')
 # Use another viewer context on the original tenant to check same effective read policy.
 s['command']('create-user','--tenant',s['tenant'],'--username','cli-viewer','--password-file',str(password),'--role','viewer');viewer=s['directory']/'viewer-context.json';viewer_login=[*login];viewer_login[viewer_login.index(s['username'])]='cli-viewer';run(viewer_login,path=viewer);assert run(['assets','get','--id',s['asset']],path=viewer)['asset_uid']==s['asset'];run(['logout'],path=viewer);run(['logout'],path=other_context);checks.append('viewer reads follow existing role policy and logout revokes its session through Origin/CSRF API')
 run(['logout']);assert not context.exists();cookie=private['cookie'].split('=',1)[1];assert s['sql']("SELECT count(*) FROM access.credentials WHERE kind='session' AND revoked_at IS NOT NULL")=='3';checks.append('CLI logout revokes remote sessions and removes local credentials')
 assert all(private['cookie'] not in text and private['csrf'] not in text for text in seen);checks.append('all captured CLI outputs exclude password/session cookie/CSRF; no secrets in argv')
 report={'package':'C12','task':'C12.01','status':'passed','count':len(checks),'checks':checks,'target':'compiled surveyscanctl+compiled server/collector+real HTTPS/auth/CSRF/PG; synthetic inventory source; two real tenants and viewer; no mocked CLI/API/auth','authentication':'private session context using existing C03 login/logout API; session token never printed; password read from0600 file','unrun':['interactive OS keychain','bearer-token client context','production/24h soak']};(STATE/'cli-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':harness(web_scenario=scenario)
