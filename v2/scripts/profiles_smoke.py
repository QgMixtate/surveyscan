#!/usr/bin/env python3
"""C12.02: real central profile publication, signed relay/ACK, cache fallback and isolation."""
import json,os,subprocess,time,uuid,secrets
from pathlib import Path
from machine_smoke import main as harness
from dev import ROOT,STATE

def scenario(**s):
 checks=s['checks'];save=s['save'];request=s['request'];sql=s['sql'];agent=str(ROOT/'.dist/surveyscan-agent');cli=str(ROOT/'.dist/surveyscanctl');state=s['directory']/'profile-agent'
 config=save('profile-agent-config.json',json.dumps({'tenant_id':s['tenant'],'site_id':s['site'],'network_scope_id':s['scope'],'collector_url':f"https://127.0.0.1:{s['collector_port']}",'collector_source_id':s['collector_source'],'ca_certificate_file':s['ca_file'],'state_directory':str(state),'inventory_seconds':180,'heartbeat_seconds':60,'jitter_percent':0,'spool_limit_bytes':1048576}))
 def a(operation,extra=None):
  p=subprocess.run([agent,operation,'--config',config,*(extra or [])],capture_output=True,text=True,timeout=30);assert p.returncode==0,'agent command failed';return p.stdout
 def until(check,message,seconds=55):
  end=time.monotonic()+seconds
  while time.monotonic()<end:
   if check():return
   time.sleep(.3)
  raise RuntimeError(message)
 prep=json.loads(a('prepare'));headers={'Origin':s['origin'],'Cookie':s['cookie'],'X-CSRF-Token':s['session']['csrf_token']}
 grant={'tenant_id':s['tenant'],'source_id':prep['source_id'],'source_kind':'agent','site_id':s['site'],'collector_id':s['collector_id'],'ttl_seconds':900,'csr_sha256':prep['csr_sha256'],'signing_public_key':prep['signing_public_key']};code,grant,_=request(s['tls_port'],s['plain'],'POST','/api/v1/enrollments',grant,headers);assert code==201;permission=save('profile-grant.json',json.dumps(grant));a('enroll',['--grant-file',permission])
 # Reuse the existing verified browser session, without exposing it; CLI profile commands use the same API.
 context=save('profile-context.json',json.dumps({'version':1,'server':s['origin'],'ca_file':s['ca_file'],'dev_loopback_http':False,'tenant_id':s['tenant'],'user_id':s['session']['user_id'],'cookie':s['cookie'],'csrf':s['session']['csrf_token'],'expires_at':s['session']['expires_at']}))
 def c(args,expect=0,context_file=context):
  p=subprocess.run([cli,*args,'--context-file',context_file],capture_output=True,text=True,timeout=25);assert p.returncode==expect,'CLI profile operation failed: '+args[0];assert s['cookie'] not in p.stdout+p.stderr and s['session']['csrf_token'] not in p.stdout+p.stderr;return json.loads(p.stdout) if p.stdout else json.loads(p.stderr)
 def profile(source=prep['source_id']):return c(['profiles','get','--id',source])
 before=profile();assert not before['managed'] and before['config']['profile_revision']=='1' and before['last_contact_at'] is None;checks.append('unpublished revision1 is explicit local-config mode; central profile read does not fabricate source contact')
 options={'heartbeat_seconds':30,'inventory_seconds':60,'jitter_percent':0,'spool_limit_bytes':1048576};options_file=save('profile-update.json',json.dumps(options))
 published=c(['profiles','set','--id',prep['source_id'],'--revision','1','--profile-file',options_file]);assert published['managed'] and published['config']['profile_revision']=='2';c(['profiles','set','--id',prep['source_id'],'--revision','1','--profile-file',options_file],6);checks.append('admin CLI publishes revision2 and stale If-Match receives412 instead of overwriting')
 first=s['start']('profile-agent-first',[agent,'run','--config',config]);until(lambda:sql('SELECT count(*) FROM inventory.observations')=='1','managed first inventory missing');until(lambda:not list((state/'spool').glob('*.pending')),'managed ACK missing');uid=sql('SELECT asset_uid::text FROM assets.assets')
 signed=json.loads((state/'profile.json').read_text());assert signed['payload']['config']['inventory_seconds']==60 and signed['payload']['config']['heartbeat_seconds']==30;signing=(state/'signing.key').read_bytes();generation=json.loads((state/'identity.json').read_text())['generation_id'];original_contact=profile()['last_contact_at'];original_inventory=profile()['last_successful_inventory_at']
 until(lambda:profile()['applied_revision']=='2','signed application revision did not reach server',35);v=profile();assert v['last_config_contact_at'] is not None and v['last_contact_at']==original_contact and v['last_successful_inventory_at']==original_inventory;checks.append('real agent validates signed nonce-bound relay profile, caches it and reports applied revision; config contact is separate from heartbeat and inventory freshness')
 options['inventory_seconds']=120;Path(options_file).write_text(json.dumps(options));assert c(['profiles','set','--id',prep['source_id'],'--revision','2','--profile-file',options_file])['config']['profile_revision']=='3'
 until(lambda:profile()['applied_revision']=='3','new revision did not apply',50);assert json.loads((state/'profile.json').read_text())['payload']['config']['inventory_seconds']==120 and (state/'signing.key').read_bytes()==signing and json.loads((state/'identity.json').read_text())['generation_id']==generation;checks.append('running agent applies new interval revision without restarting source/generation/signing key/counters')
 first.terminate();first.wait(timeout=8);count=int(sql('SELECT count(*) FROM inventory.observations'));cached=(state/'profile.json').read_bytes();s['center_process'].terminate();s['center_process'].wait(timeout=8)
 offline=s['start']('profile-agent-offline',[agent,'run','--config',config]);until(lambda:bool(list((state/'spool').glob('*.pending'))),'offline cache did not allow durable collection',20);assert (state/'profile.json').read_bytes()==cached;checks.append('center outage/restart retains verified last managed profile and unacknowledged source data')
 offline.terminate();offline.wait(timeout=8);s['start']('profile-center-restarted',[str(ROOT/'.dist/surveyscan-server'),'serve'])
 def ready():
  try:return request(s['tls_port'],s['plain'],'GET','/health/live')[0]==200
  except OSError:return False
 until(ready,'center did not restart',15);resumed=s['start']('profile-agent-resumed',[agent,'run','--config',config]);until(lambda:int(sql('SELECT count(*) FROM inventory.observations'))>=count+2,'cached profile reconnect did not deliver originals',20);until(lambda:not list((state/'spool').glob('*.pending')),'source queue did not drain',15);assert sql('SELECT asset_uid::text FROM assets.assets')==uid;resumed.terminate();resumed.wait(timeout=8);checks.append('reconnect applies offline original and next inventory exactly once to one UID with profile intact')
 # Real second tenant and viewer have no profile mutation rights across scope.
 other=str(uuid.uuid4());sql(f"INSERT INTO access.tenants(tenant_id,name,status) VALUES('{other}','profile other tenant','active')")
 for role,name,tenant in [('viewer','profile-viewer',s['tenant']),('admin','profile-other',other)]:
  secret=save(name+'-password',secrets.token_urlsafe(32));s['command']('create-user','--tenant',tenant,'--username',name,'--role',role,'--password-file',secret);target=save(name+'-placeholder','');Path(target).unlink();c(['login','--server',s['origin'],'--ca-file',s['ca_file'],'--username',name,'--password-file',secret],context_file=target)
  c(['profiles','get','--id',prep['source_id']],expect=0 if role=='viewer' else 4,context_file=target);c(['profiles','set','--id',prep['source_id'],'--revision','3','--profile-file',options_file],expect=3 if role=='viewer' else 4,context_file=target)
 checks.append('real viewer cannot publish; another tenant admin cannot read or update known source profile')
 assert int(sql("SELECT count(*) FROM audit.audit_events WHERE action='source.profile_updated'"))==2 and int(sql("SELECT count(*) FROM messaging.outbox_events WHERE event_type='source.profile_updated.v1'"))==2;checks.append('both accepted profile updates have one durable audit and outbox event each')
 report={'package':'C12','task':'C12.02','status':'passed','count':len(checks),'checks':checks,'target':'compiled agent/collector/server/CLI +real HTTPS/PG; signed config relay and origin proof; real clock/outage/restart; no mocked configuration/auth','unrun':['UI interval controls','metrics/alerts C12.03','24h soak','collector autonomous network inventory (C16)'],'source_health':'profile last_config_contact/applied_revision remain separate from heartbeat and inventory freshness'};(STATE/'profiles-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':harness(agent_scenario=scenario)
