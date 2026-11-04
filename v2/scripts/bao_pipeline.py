#!/usr/bin/env python3
"""CA/receipt key ops through scoped OpenBao, real machine flow and sealed dependency recovery."""
import base64,copy,datetime,json,os,subprocess,tempfile,time,uuid
from pathlib import Path
import rfc8785
from cryptography.hazmat.primitives import serialization
from bao_fixture import fixture
from machine_smoke import main as harness,b64
from dev import ROOT,STATE,initialize,unseal

def main():
 initialize()
 with tempfile.TemporaryDirectory(prefix='c11-pipeline-',dir=STATE) as temp:
  directory=Path(temp)
  with fixture(directory) as f:
   output=directory/'issuer';p=subprocess.run([str(ROOT/'.dist/surveyscan-server'),'bootstrap-issuer','--config',f['config'],'--output-directory',str(output)],capture_output=True,text=True,timeout=30);assert p.returncode==0,'scoped issuer bootstrap failed'
   def scenario(**s):
    checks=s['checks'];request=s['request'];sql=s['sql'];checks.append('real enrollment and center ACK use scoped Transit CA/receipt keys, without local private signing-key files')
    assert sql('SELECT count(*) FROM inventory.observations')=='1'
    f['call']('POST','sys/seal',{});status,card,_=request(s['tls_port'],s['plain'],'GET','/api/v1/assets/'+s['asset'],headers={'Cookie':s['cookie']});assert status==200
    status,_,_=request(s['tls_port'],s['plain'],'GET','/health/ready');assert status==503;checks.append('sealed OpenBao declares readiness degraded while authenticated inventory reads remain available')
    key,signing,csr=s['enroll_material']();new_source=str(uuid.uuid4());permission=s['grant'](new_source,'agent',s['collector_id'],signing,csr)
    body={'grant_id':permission['grant_id'],'source_id':new_source,'csr_pem':csr.public_bytes(serialization.Encoding.PEM).decode(),'signing_public_key':b64(signing.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))}
    status,_,_=request(s['collector_port'],s['plain'],'POST','/api/v1/machine/enroll',body,{'Authorization':'Bearer '+permission['enrollment_token']},s['collector_name']);assert status==503;checks.append('sealed issuer refuses new certificates with no local CA fallback')
    payload=copy.deepcopy(s['payload']);stamp=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z');payload['observation_id']=str(uuid.uuid4());payload['source_sequence']='2';payload['collected_at']=stamp
    for section in payload['sections']:section['collected_at']=stamp
    canonical=rfc8785.dumps(payload);import hashlib
    record={'payload':payload,'digest':hashlib.sha256(canonical).hexdigest(),'key_id':s['agent_result']['signing_key_id'],'signature':b64(s['agent_sign'].sign(b'SURVEYSCAN-OBSERVATION-V1\n'+canonical))};batch={'schema_version':{'major':1,'minor':0},'tenant_id':s['tenant'],'delivery_id':str(uuid.uuid4()),'records':[record]}
    status,_,_=request(s['collector_port'],s['client'],'POST','/api/v1/machine/observations',batch,sni=s['collector_name']);assert status==202
    end=time.monotonic()+12
    while sql('SELECT count(*) FROM inventory.observations')!='2' and time.monotonic()<end:time.sleep(.2)
    assert sql('SELECT count(*) FROM inventory.observations')=='2';assert sql("SELECT count(*) FROM imports.delivery_payloads WHERE payload IS NOT NULL AND receipt IS NULL")=='1';checks.append('valid ingestion/checkpoint continues while receipt signing waits and retains staged payload')
    status,waiting,_=request(s['collector_port'],s['client'],'GET','/api/v1/machine/deliveries/'+batch['delivery_id'],sni=s['collector_name']);assert status==200 and waiting['spool_action']=='retain' and 'payload' not in waiting
    s['center_process'].terminate();s['center_process'].wait(timeout=8);s['start']('center-sealed-restart',[str(ROOT/'.dist/surveyscan-server'),'serve']);end=time.monotonic()+10
    while time.monotonic()<end:
     try:
      status,_,_=request(s['tls_port'],s['plain'],'GET','/api/v1/assets/'+s['asset'],headers={'Cookie':s['cookie']})
      if status==200:break
     except OSError:pass
     time.sleep(.1)
    else:raise RuntimeError('readonly API did not restart with sealed dependency')
    checks.append('server restarts with sealed Bao using only pinned public metadata; readonly API remains available')
    unseal();end=time.monotonic()+55
    while time.monotonic()<end:
     status,result,_=request(s['collector_port'],s['client'],'GET','/api/v1/machine/deliveries/'+batch['delivery_id'],sni=s['collector_name'])
     if status==200 and 'payload' in result:break
     time.sleep(.4)
    else:raise RuntimeError('key operations failed to recover after unseal')
    s['center_key'].public_key().verify(base64.urlsafe_b64decode(result['signature']+'=='),b'SURVEYSCAN-CENTER-RESULT-V1\n'+rfc8785.dumps(result['payload']));assert result['payload']['results'][0]['disposition']=='applied' and sql('SELECT count(*) FROM inventory.observations')=='2' and sql('SELECT count(*) FROM assets.assets')=='1';checks.append('unseal resumes persisted retry and signs durable ACK without duplicate observation or manual requeue')
    # Existing agent signing key proves a fresh TLS CSR through its assigned collector.
    status,challenges,_=request(s['collector_port'],s['client'],'POST','/api/v1/machine/heartbeat-challenges',{'source_ids':[s['agent_source']],'purpose':'cert_renew'},sni=s['collector_name']);assert status==200
    challenge=challenges['challenges'][0];tls_key,_,csr=s['enroll_material']()
    renewal={'schema_version':{'major':1,'minor':0},'renewal_id':str(uuid.uuid4()),'tenant_id':s['tenant'],'origin':s['payload']['origin'],'challenge_id':challenge['challenge_id'],'nonce':challenge['nonce'],'csr_pem':csr.public_bytes(serialization.Encoding.PEM).decode(),'sent_at':datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')}
    canonical=rfc8785.dumps(renewal);proof={'payload':renewal,'digest':hashlib.sha256(canonical).hexdigest(),'key_id':s['agent_result']['signing_key_id'],'signature':b64(s['agent_sign'].sign(b'SURVEYSCAN-RENEWAL-V1\n'+canonical))}
    status,renewed,_=request(s['collector_port'],s['client'],'POST','/api/v1/machine/renewals',proof,sni=s['collector_name']);assert status==200
    status,replayed,_=request(s['collector_port'],s['client'],'POST','/api/v1/machine/renewals',proof,sni=s['collector_name']);assert status==200 and replayed==renewed
    assert renewed['generation_id']==s['agent_result']['generation_id'] and renewed['signing_key_id']==s['agent_result']['signing_key_id']
    cert_file=s['directory']/'renewed.pem';cert_file.write_text(renewed['certificate_chain_pem']);key_file=s['directory']/'renewed.key';fd=os.open(key_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(tls_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    renewed_context=s['context'](cert_file,key_file)
    status,_,_=request(s['collector_port'],renewed_context,'POST','/api/v1/machine/heartbeat-challenges',{'source_ids':[s['agent_source']],'purpose':'heartbeat'},sni=s['collector_name']);assert status==200
    checks.append('real agent cert_renew proof through assigned collector returns one durable replay result; new TLS key/certificate works with unchanged generation/signing identity')
    f['call']('POST','auth/token/revoke',{'token':f['token']})
    status,_,_=request(s['tls_port'],s['plain'],'GET','/health/ready');assert status==503
    status,_,_=request(s['tls_port'],s['plain'],'GET','/api/v1/assets/'+s['asset'],headers={'Cookie':s['cookie']});assert status==200;checks.append('revoked application token declares readiness degraded while inventory reads stay available')
    assert f['audit_check']();checks.append('audit log contains no raw application/root tokens or canary secret')
    report={'package':'C11','status':'passed','scope':'C11 scoped key/secret operations + real machine path; agent/collector lifecycle covered by separate reports','count':len(checks),'checks':checks,'target':'real OpenBao2.7.2 Raft + scoped periodic token + non-exportable Transit Ed25519 CA/receipt keys + compiled server/collector + synthetic signed agent + PostgreSQL; actual seal/unseal and server restart','unrun':['production bootstrap custody/HTTPS certificate deployment','backup restore rehearsal'],'private_material':'no root token in app config, no CA/receipt private keys outside Bao, all own keys/tokens/policy/test DB cleaned'};(STATE/'bao-pipeline.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
   settings={'config':f['config'],'ca_certificate':str(output/'ca.pem'),'server_certificate':str(output/'server.pem'),'server_private':str(output/'server.key'),'center_id':str(uuid.uuid4()),'center_public':f['profile']['keys']['center']['public_key'],'hook':scenario}
   harness(bao_settings=settings)
if __name__=='__main__':main()
