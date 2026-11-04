#!/usr/bin/env python3
"""Collector renewal: retained queues, actual committed ACK loss, restart and live hot reload."""
import http.server,json,os,socket,ssl,subprocess,tempfile,threading,time,uuid
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from bao_fixture import fixture
from machine_smoke import main as harness,freeport
from dev import ROOT,STATE,initialize

def main():
 initialize()
 with tempfile.TemporaryDirectory(prefix='c11-collector-renew-',dir=STATE) as temp:
  with fixture(Path(temp)) as f:
   output=Path(temp)/'issuer';p=subprocess.run([str(ROOT/'.dist/surveyscan-server'),'bootstrap-issuer','--config',f['config'],'--output-directory',str(output)],capture_output=True,text=True,timeout=30);assert p.returncode==0,'remote bootstrap failed'
   def scenario(**s):
    checks=s['checks'];request=s['request'];sql=s['sql'];save=s['save'];agent=str(ROOT/'.dist/surveyscan-agent');collector=str(ROOT/'.dist/surveyscan-collector');state=s['directory']/'agent-state'
    cfg={'tenant_id':s['tenant'],'site_id':s['site'],'network_scope_id':s['scope'],'collector_url':f"https://127.0.0.1:{s['collector_port']}",'collector_source_id':s['collector_source'],'ca_certificate_file':s['ca_file'],'state_directory':str(state),'inventory_seconds':60,'heartbeat_seconds':30,'jitter_percent':0,'spool_limit_bytes':1048576};config=save('agent-config.json',json.dumps(cfg))
    def command(binary,operation,config_path,extra=None,expect=0):
     p=subprocess.run([binary,operation,'--config',config_path,*(extra or [])],capture_output=True,text=True,timeout=30);assert p.returncode==expect,'console failed: '+Path(binary).name+'/'+operation;return p.stdout
    def until(test,message):
     end=time.monotonic()+22
     while time.monotonic()<end:
      if test():return
      time.sleep(.2)
     raise RuntimeError(message)
    prep=json.loads(command(agent,'prepare',config));headers={'Origin':s['origin'],'Cookie':s['cookie'],'X-CSRF-Token':s['session']['csrf_token']}
    body={'tenant_id':s['tenant'],'source_id':prep['source_id'],'source_kind':'agent','site_id':s['site'],'collector_id':s['collector_id'],'ttl_seconds':900,'csr_sha256':prep['csr_sha256'],'signing_public_key':prep['signing_public_key']};status,grant,_=request(s['tls_port'],s['plain'],'POST','/api/v1/enrollments',body,headers);assert status==201
    permission=save('agent-grant.json',json.dumps(grant));command(agent,'enroll',config,['--grant-file',permission]);first=s['start']('collector-renew-agent-first',[agent,'run','--config',config]);until(lambda:sql('SELECT count(*) FROM inventory.observations')=='1','first inventory missing');until(lambda:not list((state/'spool').glob('*.pending')),'first ACK missing');first.terminate();first.wait(timeout=8);uid=sql('SELECT asset_uid::text FROM assets.assets')
    collector_config=Path(s['collector_config']);original=json.loads(collector_config.read_text());credentials=Path(original['credential_directory']);spool=Path(original['spool_directory']);old=x509.load_pem_x509_certificate(Path(original['certificate_file']).read_bytes());signing=Path(original['signing_private_key_file']).read_bytes()
    other=dict(original,spool_directory=str(s['directory']/'other-spool'),listen='127.0.0.1:'+str(freeport()));other_file=save('other-collector.json',json.dumps(other));command(collector,'run',other_file,expect=1);checks.append('separate credential writer lock rejects a second collector using another spool/listen address')
    s['center_process'].terminate();s['center_process'].wait(timeout=8)
    offline=s['start']('collector-renew-agent-offline',[agent,'run','--config',config]);until(lambda:bool(list((state/'spool').glob('*.pending'))) and bool(list(spool.glob('*.pending'))),'both queues did not retain offline batch');offline.terminate();offline.wait(timeout=8);s['collector_process'].terminate();s['collector_process'].wait(timeout=8)
    source_packets={p.name:p.read_bytes() for p in (state/'spool').glob('*.pending')};collector_packets={p.name:p.read_bytes() for p in spool.glob('*.pending')};checks.append('center outage leaves original unacknowledged batch durable at source and collector before rotation')
    s['start']('collector-renew-center-restart',[str(ROOT/'.dist/surveyscan-server'),'serve'])
    def ready():
     try:return request(s['tls_port'],s['plain'],'GET','/health/live')[0]==200
     except OSError:return False
    until(ready,'center did not restart')
    upstream=ssl.create_default_context(cafile=s['ca_file']);upstream.load_cert_chain(original['certificate_file'],original['private_key_file']);seen=[]
    class Relay(http.server.BaseHTTPRequestHandler):
     def log_message(self,*args):pass
     def do_POST(self):
      raw=self.rfile.read(int(self.headers.get('Content-Length','0')));status,result,_=request(s['tls_port'],upstream,'POST',self.path,json.loads(raw))
      if self.path=='/api/v1/machine/renewals':
       seen.append(raw)
       if len(seen)==1 and status==200:self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
      encoded=json.dumps(result).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(encoded)));self.end_headers();self.wfile.write(encoded)
    proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Relay);proxy.daemon_threads=True;server_tls=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH);server_tls.load_verify_locations(s['ca_file']);server_tls.verify_mode=ssl.CERT_REQUIRED;server_tls.load_cert_chain(str(output/'server.pem'),str(output/'server.key'));proxy.socket=server_tls.wrap_socket(proxy.socket,server_side=True);thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
    collector_config.write_text(json.dumps(dict(original,center_url='https://127.0.0.1:'+str(proxy.server_port))))
    try:
     command(collector,'renew',str(collector_config),expect=1);pending=(credentials/'renewal.pending.json').read_bytes();assert sql('SELECT count(*) FROM sources.renewal_receipts')=='1' and not (credentials/'tls-identity.json').exists()
     command(collector,'renew',str(collector_config));assert len(seen)==2 and seen[0]==seen[1] and sql('SELECT count(*) FROM sources.renewal_receipts')=='1';checks.append('real TLS disconnect after collector certificate commit preserves pending key/CSR; fresh CLI process replays one original result')
    finally:proxy.shutdown();proxy.server_close();thread.join(timeout=3);collector_config.write_text(json.dumps(original))
    bundle=json.loads((credentials/'tls-identity.json').read_text());new=x509.load_pem_x509_certificate(bundle['result']['certificate_chain_pem'].encode());key=serialization.load_pem_private_key(bundle['private_key_pem'].encode(),None)
    def pub(value):return value.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    assert pub(new.public_key())!=pub(old.public_key()) and pub(new.public_key())==pub(key.public_key()) and (credentials/'tls-identity.json').stat().st_mode&0o077==0 and Path(original['signing_private_key_file']).read_bytes()==signing
    assert {p.name:p.read_bytes() for p in (state/'spool').glob('*.pending')}==source_packets and {p.name:p.read_bytes() for p in spool.glob('*.pending')}==collector_packets;checks.append('collector atomically rotates matching TLS key/cert without changing origin signing key or either pending queue')
    active=s['start']('collector-renew-restarted',[collector,'run','--config',str(collector_config)]);sender=s['start']('collector-renew-agent-resume',[agent,'run','--config',config]);until(lambda:sql('SELECT count(*) FROM inventory.observations')=='3','rotated collector did not drain original queues');until(lambda:not list((state/'spool').glob('*.pending')) and not list(spool.glob('*.pending')),'rotated queues did not drain')
    assert sql('SELECT asset_uid::text FROM assets.assets')==uid and sql('SELECT max(source_sequence)::text FROM inventory.observations')=='3';checks.append('restart uses rotated inbound/outbound TLS credentials; queued originals and next live inventory apply once to one UID')
    sender.terminate();sender.wait(timeout=8);active.terminate();active.wait(timeout=8)
    env=dict(os.environ,SURVEYSCAN_TEST_COLLECTOR_CONFIG=str(collector_config));p=subprocess.run([os.environ.get('GO','go'),'test','-mod=readonly','-tags=collectorlive','-count=1','-run','^TestLiveCollectorAutomaticTLSReload$','-v','./internal/collector'],cwd=ROOT,env=env,capture_output=True,text=True,timeout=60);assert p.returncode==0,'live collector auto-renewal test failed: '+p.stdout[-2000:]+p.stderr[-500:]
    assert sql('SELECT count(*) FROM sources.renewal_receipts')=='2';checks.append('real collector Run auto-renews under injected scheduler clock, hot-reloads listener TLS and authenticates new outbound identity; real center/PG/Bao, no restart')
    status,_,_=request(s['tls_port'],s['plain'],'POST','/api/v1/sources/'+s['collector_source']+'/revocations',{'reason_code':'TEST_REVOKE'},headers);assert status==200;command(collector,'renew',str(collector_config),expect=1);assert sql('SELECT count(*) FROM sources.renewal_receipts')=='2';checks.append('source revoke prevents further renewal of all collector certificates')
    assert f['audit_check']();checks.append('actual masked Bao audit excludes application/root tokens and KV canary')
    report={'package':'C11','status':'passed','count':len(checks),'checks':checks,'target':'compiled Linux agent+collector+server, real host inventory/PG/scoped Bao; real TLS ACK loss; automatic loop tested via Go collector runtime with scheduler clock advanced only','unrun':['real24h auto-renewal soak','physical power loss','production custody/DR','full clone/expired administrative recovery matrix']};(STATE/'collector-renewal-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
   settings={'config':f['config'],'ca_certificate':str(output/'ca.pem'),'server_certificate':str(output/'server.pem'),'server_private':str(output/'server.key'),'center_id':str(uuid.uuid4()),'center_public':f['profile']['keys']['center']['public_key']};harness(agent_scenario=scenario,bao_settings=settings)
if __name__=='__main__':main()
