#!/usr/bin/env python3
"""Real compiled Linux agent renewal with atomic identity bundle and persistent server ledger."""
import json,os,subprocess,tempfile,time,uuid,http.server,ssl,socket,threading
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from bao_fixture import fixture
from machine_smoke import main as harness
from dev import ROOT,STATE,initialize

def main():
 initialize()
 with tempfile.TemporaryDirectory(prefix='c11-renewal-',dir=STATE) as temp:
  with fixture(Path(temp)) as f:
   output=Path(temp)/'issuer';p=subprocess.run([str(ROOT/'.dist/surveyscan-server'),'bootstrap-issuer','--config',f['config'],'--output-directory',str(output)],capture_output=True,text=True,timeout=30);assert p.returncode==0,'remote bootstrap failed'
   def scenario(**s):
    checks=s['checks'];request=s['request'];sql=s['sql'];save=s['save'];binary=str(ROOT/'.dist/surveyscan-agent');state=s['directory']/'agent-state'
    cfg={'tenant_id':s['tenant'],'site_id':s['site'],'network_scope_id':s['scope'],'collector_url':f"https://127.0.0.1:{s['collector_port']}",'collector_source_id':s['collector_source'],'ca_certificate_file':s['ca_file'],'state_directory':str(state),'inventory_seconds':60,'heartbeat_seconds':30,'jitter_percent':0,'spool_limit_bytes':1048576};config=save('agent-config.json',json.dumps(cfg))
    def command(operation,extra=None,expect=0):
     p=subprocess.run([binary,operation,'--config',config,*(extra or [])],capture_output=True,text=True,timeout=30);assert p.returncode==expect,'agent operation failed: '+operation;return p.stdout
    def until(test,message):
     end=time.monotonic()+18
     while time.monotonic()<end:
      if test():return
      time.sleep(.2)
     raise RuntimeError(message+'; daemon_events='+''.join(p.read_text()[-500:] for p in s['directory'].glob('renewal-agent-*.log')))
    prep=json.loads(command('prepare'));headers={'Origin':s['origin'],'Cookie':s['cookie'],'X-CSRF-Token':s['session']['csrf_token']}
    body={'tenant_id':s['tenant'],'source_id':prep['source_id'],'source_kind':'agent','site_id':s['site'],'collector_id':s['collector_id'],'ttl_seconds':900,'csr_sha256':prep['csr_sha256'],'signing_public_key':prep['signing_public_key']};status,grant,_=request(s['tls_port'],s['plain'],'POST','/api/v1/enrollments',body,headers);assert status==201
    permission=save('agent-grant.json',json.dumps(grant));command('enroll',['--grant-file',permission]);old=json.loads((state/'identity.json').read_text());signing=(state/'signing.key').read_bytes()
    process=s['start']('renewal-agent-before',[binary,'run','--config',config]);until(lambda:sql('SELECT count(*) FROM inventory.observations')=='1','first live inventory missing');until(lambda:not list((state/'spool').glob('*.pending')),'source ACK not durable')
    command('renew',expect=1);process.terminate();process.wait(timeout=8);uid=sql('SELECT asset_uid::text FROM assets.assets');counters=(state/'sequences.json').read_bytes();checks.append('live agent commits host inventory and daemon lock blocks simultaneous renewal writer')
    # Real TLS relay drops the first committed renewal ACK; it does not fake issuance/PG.
    collector_cfg=json.loads(Path(s['collector_config']).read_text());upstream=ssl.create_default_context(cafile=s['ca_file']);upstream.load_cert_chain(save('old-agent.pem',old['certificate_chain_pem']),str(state/'tls.key'));seen=[]
    class Relay(http.server.BaseHTTPRequestHandler):
     def log_message(self,*args):pass
     def do_POST(self):
      raw=self.rfile.read(int(self.headers.get('Content-Length','0')));body=json.loads(raw)
      status,result,_=request(s['collector_port'],upstream,'POST',self.path,body,sni=s['collector_source']+'.collector.invalid')
      if self.path=='/api/v1/machine/renewals':
       seen.append(raw)
       if len(seen)==1 and status==200:
        self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
      encoded=json.dumps(result).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(encoded)));self.end_headers();self.wfile.write(encoded)
    proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Relay);proxy.daemon_threads=True;server_tls=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH);server_tls.load_verify_locations(s['ca_file']);server_tls.verify_mode=ssl.CERT_REQUIRED;server_tls.load_cert_chain(collector_cfg['certificate_file'],collector_cfg['private_key_file']);proxy.socket=server_tls.wrap_socket(proxy.socket,server_side=True);thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
    proxy_config=dict(cfg,collector_url='https://127.0.0.1:'+str(proxy.server_port));Path(config).write_text(json.dumps(proxy_config))
    try:
     command('renew',expect=1);pending=(state/'renewal.pending.json').read_bytes();assert sql('SELECT count(*) FROM sources.renewal_receipts')=='1' and not (state/'tls-identity.json').exists() and (state/'signing.key').read_bytes()==signing
     command('renew');assert len(seen)==2 and seen[0]==seen[1] and sql('SELECT count(*) FROM sources.renewal_receipts')=='1';checks.append('actual TLS disconnect after committed renewal retains pending CSR/private key; separate CLI retry returns same certificate without duplicate issuance')
    finally:
     proxy.shutdown();proxy.server_close();thread.join(timeout=3);Path(config).write_text(json.dumps(cfg))
    bundle=json.loads((state/'tls-identity.json').read_text());renewed=bundle['result'];assert (state/'tls-identity.json').stat().st_mode&0o077==0
    assert renewed['source_id']==old['source_id'] and renewed['generation_id']==old['generation_id'] and renewed['signing_key_id']==old['signing_key_id'];assert (state/'sequences.json').read_bytes()==counters and (state/'signing.key').read_bytes()==signing and json.loads((state/'preparation.json').read_text())==prep
    newcert=x509.load_pem_x509_certificate(renewed['certificate_chain_pem'].encode());oldcert=x509.load_pem_x509_certificate(old['certificate_chain_pem'].encode());private=serialization.load_pem_private_key(bundle['private_key_pem'].encode(),None)
    def pub(key):return key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    assert pub(newcert.public_key())==pub(private.public_key()) and pub(oldcert.public_key())!=pub(newcert.public_key());assert not (state/'renewal.pending.json').exists() and sql('SELECT count(*) FROM sources.renewal_receipts')=='1';checks.append('compiled agent rotates TLS key using scoped Bao issuer; atomic private bundle commits matching cert/key and leaves origin signing key/generation/counters unchanged')
    restarted=s['start']('renewal-agent-after',[binary,'run','--config',config]);until(lambda:sql('SELECT count(*) FROM inventory.observations')=='2','renewed agent did not resume');until(lambda:not list((state/'spool').glob('*.pending')),'renewed source ACK missing')
    assert sql('SELECT asset_uid::text FROM assets.assets')==uid and sql('SELECT max(source_sequence)::text FROM inventory.observations')=='2';checks.append('restart loads atomic rotated credentials and resumes real inventory/ACK with one UID and monotonic sequence')
    restarted.terminate();restarted.wait(timeout=8)
    status,_,_=request(s['tls_port'],s['plain'],'POST','/api/v1/sources/'+prep['source_id']+'/revocations',{'reason_code':'TEST_REVOKE'},headers);assert status==200;command('renew',expect=1);assert sql('SELECT count(*) FROM sources.renewal_receipts')=='1';checks.append('source revoke prevents renewed credentials from obtaining another certificate')
    assert f['audit_check']();checks.append('actual audit has no raw operator/application tokens or canary')
    report={'package':'C11','status':'passed','count':len(checks),'checks':checks,'target':'compiled Linux/amd64 agent+collector+server, real host inventory/PG/TLS/scoped OpenBao Transit CA, no mocked APIs','unrun':['collector self-renewal','physical power-loss rotation windows','expired certificate administrative recovery','full clone matrix','production key custody/DR']};(STATE/'renewal-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
   settings={'config':f['config'],'ca_certificate':str(output/'ca.pem'),'server_certificate':str(output/'server.pem'),'server_private':str(output/'server.key'),'center_id':str(uuid.uuid4()),'center_public':f['profile']['keys']['center']['public_key']}
   harness(agent_scenario=scenario,bao_settings=settings)
if __name__=='__main__':main()
