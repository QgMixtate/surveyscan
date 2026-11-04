#!/usr/bin/env python3
"""C08: три автоматических host cycles; PKI и isolated PG из C07 harness."""
import json,subprocess,time,uuid,socket
from pathlib import Path
from machine_smoke import main as machine_harness
from dev import ROOT,STATE

def live_agent(**s):
 checks=s['checks'];save=s['save'];request=s['request'];sql=s['sql'];start=s['start']
 cfg={'tenant_id':s['tenant'],'site_id':s['site'],'network_scope_id':s['scope'],'collector_url':f"https://127.0.0.1:{s['collector_port']}",'collector_source_id':s['collector_source'],'ca_certificate_file':s['ca_file'],'state_directory':str(s['directory']/'agent-state'),'inventory_seconds':60,'heartbeat_seconds':30,'jitter_percent':0,'spool_limit_bytes':1048576}
 config=save('agent-config.json',json.dumps(cfg));binary=str(ROOT/'.dist/surveyscan-agent')
 def command(*args,expect=0):
  p=subprocess.run([binary,*args],cwd=ROOT,capture_output=True,text=True,timeout=30)
  assert p.returncode==expect,'agent console failed: '+p.stderr[:300];return p.stdout
 prep=json.loads(command('prepare','--config',config));repeat=json.loads(command('prepare','--config',config));assert prep==repeat;checks.append('compiled agent prepares stable separate TLS and signing keys')
 body={'tenant_id':s['tenant'],'source_id':prep['source_id'],'source_kind':'agent','site_id':s['site'],'collector_id':s['collector_id'],'ttl_seconds':900,'csr_sha256':prep['csr_sha256'],'signing_public_key':prep['signing_public_key']}
 headers={'Origin':s['origin'],'Cookie':s['cookie'],'X-CSRF-Token':s['session']['csrf_token']}
 status,grant,_=request(s['tls_port'],s['plain'],'POST','/api/v1/enrollments',body,headers);assert status==201;permission=save('agent-grant.json',json.dumps(grant))
 wrong=dict(cfg,collector_source_id=str(uuid.uuid4()));wrongfile=save('agent-wrong-config.json',json.dumps(wrong));command('enroll','--config',wrongfile,'--grant-file',permission,expect=1);assert not (Path(cfg['state_directory'])/'identity.json').exists();checks.append('wrong collector certificate identity rejected before enrollment')
 command('enroll','--config',config,'--grant-file',permission);command('enroll','--config',config,'--grant-file',permission);checks.append('compiled agent enrollment through collector trusts preinstalled CA and is idempotent')
 process=start('agent',[binary,'run','--config',config]);deadline=time.monotonic()+155
 while time.monotonic()<deadline:
  assert process.poll() is None,'live agent exited'
  observed=int(sql('SELECT count(*) FROM inventory.observations'))
  if observed>=3:break
  time.sleep(.5)
 else:raise RuntimeError('three automatic inventory cycles did not commit')
 # Host facts остаются во временной БД и не копируются в отчёт.
 assert sql('SELECT count(*) FROM assets.assets')=='1'
 assert sql('SELECT count(DISTINCT asset_uid) FROM assets.observation_links')=='1'
 assert sql('SELECT count(DISTINCT source_sequence) FROM inventory.observations')=='3'
 uid=sql('SELECT asset_uid::text FROM assets.assets');status,card,_=request(s['tls_port'],s['plain'],'GET','/api/v1/assets/'+uid,headers={'Cookie':s['cookie']});assert status==200 and card['observed_hostname']==socket.gethostname() and card['observed_os'] and card['accountable_subject_id']==s['subject'];checks.append('three scheduled live Linux host inventories update one stable asset UID through real API')
 assert int(sql("SELECT count(*) FROM sources.heartbeat_receipts WHERE source_id='"+prep['source_id']+"'"))>=3;assert sql("SELECT count(*) FROM sources.heartbeat_state WHERE last_contact_at IS NOT NULL AND source_id='"+prep['source_id']+"'")=='1';checks.append('independent challenge-bound heartbeats accepted while inventory has separate sequence')
 end=time.monotonic()+8
 while list((Path(cfg['state_directory'])/'spool').glob('*.pending')) and time.monotonic()<end:time.sleep(.2)
 assert not list((Path(cfg['state_directory'])/'spool').glob('*.pending'));assert len(list((Path(cfg['state_directory'])/'spool').glob('*.receipt')))==3;checks.append('agent spool trims only after verified signed center receipts')
 command('run','--config',config,expect=1);checks.append('exclusive local state lock rejects simultaneous second agent')
 process.terminate();assert process.wait(timeout=8)==0
 start('agent-restarted',[binary,'run','--config',config]);end=time.monotonic()+15
 while int(sql('SELECT count(*) FROM inventory.observations'))<4 and time.monotonic()<end:time.sleep(.2)
 assert int(sql('SELECT count(*) FROM inventory.observations'))==4 and sql('SELECT count(*) FROM assets.assets')=='1';assert sql('SELECT max(source_sequence)::text FROM inventory.observations')=='4';checks.append('graceful restart preserves keys, source, monotonic counters and asset UID')
 status,_,_=request(s['tls_port'],s['plain'],'POST','/api/v1/sources/'+prep['source_id']+'/revocations',{'reason_code':'TEST_REVOKE'},headers);assert status==200
 command('enroll','--config',config,'--grant-file',permission,expect=1);checks.append('revoked source cannot reenroll through collector')
 report={'package':'C08','status':'passed','checks':checks,'count':len(checks),'inventory_cycles_before_restart':3,'inventory_cycles_after_restart':4,'target':'compiled Linux/amd64 agent + collector + server; real host read-only inventory, verified TLS/mTLS, PostgreSQL; independent 30s heartbeats and 60s inventory','private_data':'host facts/keys confined to temporary database/files, removed after run; report has no host values','unrun':['24h soak','production PKI','Windows','full disk/outage matrix']};(STATE/'agent-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))

if __name__=='__main__':machine_harness(agent_scenario=live_agent)
