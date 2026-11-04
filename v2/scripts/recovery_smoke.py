#!/usr/bin/env python3
"""C10 real SIGKILL, offline spool/reconnect on compiled agent/collector/server + isolated PG."""
import json,subprocess,time,uuid,ssl
from pathlib import Path
from dev import ROOT,STATE
from machine_smoke import main as machine_harness,freeport

def recovery(**s):
 save=s['save'];sql=s['sql'];request=s['request'];start=s['start'];checks=s['checks']
 # Тот же spool с другим listen address: ошибка должна быть writer lock, не bind port.
 duplicate=json.loads(Path(s['collector_config']).read_text());duplicate['listen']=f'127.0.0.1:{freeport()}';dup=save('duplicate-collector.json',json.dumps(duplicate))
 p=subprocess.run([str(ROOT/'.dist/surveyscan-collector'),'run','--config',dup],capture_output=True,text=True,timeout=10)
 assert p.returncode==1 and 'active writer' in p.stderr,'collector spool allowed a second process';checks.append('collector single writer enforced across different listen ports')
 cfg={'tenant_id':s['tenant'],'site_id':s['site'],'network_scope_id':s['scope'],'collector_url':f"https://127.0.0.1:{s['collector_port']}",'collector_source_id':s['collector_source'],'ca_certificate_file':s['ca_file'],'state_directory':str(s['directory']/'recovery-agent'),'inventory_seconds':60,'heartbeat_seconds':30,'jitter_percent':0,'spool_limit_bytes':524288}
 config=save('recovery-agent.json',json.dumps(cfg));binary=str(ROOT/'.dist/surveyscan-agent')
 def command(*args):
  p=subprocess.run([binary,*args],capture_output=True,text=True,timeout=25);assert p.returncode==0,'agent console failed';return p.stdout
 prep=json.loads(command('prepare','--config',config));headers={'Origin':s['origin'],'Cookie':s['cookie'],'X-CSRF-Token':s['session']['csrf_token']}
 body={'tenant_id':s['tenant'],'source_id':prep['source_id'],'source_kind':'agent','site_id':s['site'],'collector_id':s['collector_id'],'ttl_seconds':900,'csr_sha256':prep['csr_sha256'],'signing_public_key':prep['signing_public_key']}
 status,grant,_=request(s['tls_port'],s['plain'],'POST','/api/v1/enrollments',body,headers);assert status==201;permission=save('recovery-grant.json',json.dumps(grant));command('enroll','--config',config,'--grant-file',permission)
 center=s['center_process'];center.terminate();assert center.wait(timeout=8)==0
 agent=start('recovery-agent',[binary,'run','--config',config]);agent_spool=Path(cfg['state_directory'])/'spool';collector_spool=s['directory']/'spool'
 def until(predicate,message,timeout=20):
  end=time.monotonic()+timeout
  while time.monotonic()<end:
   if predicate():return
   time.sleep(.1)
  raise RuntimeError(message)
 until(lambda:agent_spool.exists() and list(agent_spool.glob('*.pending')) and list(collector_spool.glob('*.pending')),'offline delivery did not become durable on both hops')
 collector_original={p.name:p.read_bytes() for p in collector_spool.glob('*.pending')};original={p.name:p.read_bytes() for p in agent_spool.glob('*.pending')};assert len(original)==1 and sql('SELECT count(*) FROM inventory.observations')=='0';checks.append('center offline leaves durable pending packet at source and collector without applied data')
 agent.kill();agent.wait(timeout=5);relay=s['collector_process'];relay.kill();relay.wait(timeout=5)
 assert all((agent_spool/name).read_bytes()==data for name,data in original.items()) and all((collector_spool/name).read_bytes()==data for name,data in collector_original.items());checks.append('SIGKILL of both daemons preserves unacknowledged source bytes')
 start('recovery-collector',[str(ROOT/'.dist/surveyscan-collector'),'run','--config',s['collector_config']]);time.sleep(.6)
 start('recovery-agent-restarted',[binary,'run','--config',config]);until(lambda:len(list(agent_spool.glob('*.pending')))>=2,'restart did not resume sequence while center unavailable')
 sequences=json.loads((Path(cfg['state_directory'])/'sequences.json').read_text());assert sequences['inventory']=='2';assert all((agent_spool/name).read_bytes()==data for name,data in original.items());checks.append('exclusive lock released by crash; source identity/sequence resumes without discarding old pending')
 restarted_center=start('recovery-center',[str(ROOT/'.dist/surveyscan-server'),'serve']);until(lambda:sql('SELECT count(*) FROM inventory.observations')=='2','reconnect did not commit both observations',timeout=30)
 until(lambda:not list(agent_spool.glob('*.pending')) and not list(collector_spool.glob('*.pending')),'verified ACK did not drain both spools',timeout=20)
 assert sql('SELECT count(*) FROM assets.assets')=='1';assert sql('SELECT max(source_sequence)::text FROM inventory.observations')=='2';assert sql('SELECT count(*) FROM inventory.observation_results')=='2';checks.append('reconnect applies two original observations once to one UID then verified ACK drains both queues')
 # Центр тоже переживает настоящий SIGKILL; повтор уже committed batch не меняет факты.
 first_raw=next(iter(original.values()));first_batch=json.loads(first_raw);expected=json.loads((agent_spool/(first_batch['delivery_id']+'.receipt')).read_text());event_count=sql('SELECT count(*) FROM messaging.outbox_events');collected=sql('SELECT max(collected_at)::text FROM inventory.observations')
 restarted_center.kill();restarted_center.wait(timeout=5);start('recovery-center-after-kill',[str(ROOT/'.dist/surveyscan-server'),'serve'])
 collector_cfg=json.loads(Path(s['collector_config']).read_text());client=ssl.create_default_context(cafile=s['ca_file']);client.load_cert_chain(collector_cfg['certificate_file'],collector_cfg['private_key_file'])
 def ready():
  try:return request(s['tls_port'],client,'GET','/health/live')[0]==200
  except OSError:return False
 until(ready,'center did not recover after SIGKILL')
 status,replayed,_=request(s['tls_port'],client,'POST','/api/v1/machine/observations',first_batch)
 assert status==202 and replayed['signature']==expected['signature'] and replayed['payload']['receipt_id']==expected['payload']['receipt_id'];assert sql('SELECT count(*) FROM inventory.observations')=='2' and sql('SELECT count(*) FROM messaging.outbox_events')==event_count and sql('SELECT max(collected_at)::text FROM inventory.observations')==collected;checks.append('center SIGKILL/restart preserves cached receipt after payload GC; replay adds no effects or false inventory freshness')
 report={'package':'C10','status':'passed','count':len(checks),'checks':checks,'target':'real compiled agent/collector/server; real TLS/mTLS/PG; explicit center outage and SIGKILL of both daemons; no mocked network or storage','unrun':['large reconnect storm/production scale','physical reboot/power loss','production/24h soak']};(STATE/'recovery-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':machine_harness(agent_scenario=recovery)
