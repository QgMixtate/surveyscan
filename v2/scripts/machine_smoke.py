#!/usr/bin/env python3
"""C07 live binaries, private dev PKI and synthetic agent through collector; no credential output."""
import base64,datetime,hashlib,http.client,http.cookiejar,json,os,secrets,socket,ssl,subprocess,tempfile,time,uuid
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
import ipaddress,rfc8785
from dev import ROOT,STATE,compose,initialize

def uid():return str(uuid.uuid4())
def b64(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def rawpublic(key):return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def freeport():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def main(agent_scenario=None):
 initialize();db='ssv2machine_'+uuid.uuid4().hex;tenant,site,scope,subject=uid(),uid(),uid(),uid();processes=[];checks=[];created=False
 def sql(query,database='surveyscan_v2'):
  return compose('exec','-T','db','psql','-U','surveyscan_v2','-d',database,'-v','ON_ERROR_STOP=1','-Atc',query,capture=True).strip()
 with tempfile.TemporaryDirectory(prefix='c07-',dir=STATE) as temporary:
  directory=Path(temporary)
  def save(name,data):
   p=directory/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
   with os.fdopen(fd,'wb') as f:f.write(data if isinstance(data,bytes) else data.encode())
   return str(p)
  def private(key):return key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
  ca_key=ed25519.Ed25519PrivateKey.generate();now=datetime.datetime.now(datetime.timezone.utc)
  ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'C07 synthetic dev CA')])
  ca=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True).sign(ca_key,None)
  ca_file=save('ca.pem',ca.public_bytes(serialization.Encoding.PEM));ca_private=save('ca.key',private(ca_key))
  server_key=ed25519.Ed25519PrivateKey.generate();server=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'C07 center')])).issuer_name(ca_name).public_key(server_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=12)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(ca_key,None)
  server_file=save('server.pem',server.public_bytes(serialization.Encoding.PEM));server_private=save('server.key',private(server_key));center_key=ed25519.Ed25519PrivateKey.generate();center_id=uid();center_private=save('center.json',json.dumps({'key_id':center_id,'private_key':b64(center_key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())+rawpublic(center_key))}))
  tls_port,http_port,collector_port=freeport(),freeport(),freeport();machine_file=save('machine.json',json.dumps({'dev_mode':True,'listen':f'127.0.0.1:{tls_port}','ca_certificate_file':ca_file,'ca_private_key_file':ca_private,'server_certificate_file':server_file,'server_private_key_file':server_private,'center_signing_key_file':center_private}))
  origin=f'https://127.0.0.1:{tls_port}';env=dict(os.environ,SURVEYSCAN_V2_DATABASE_URL=f'postgres://surveyscan_v2@127.0.0.1:55432/{db}?sslmode=disable',SURVEYSCAN_V2_DATABASE_PASSWORD_FILE=str(STATE/'pg_password'),SURVEYSCAN_V2_PUBLIC_ORIGIN=origin,SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{http_port}',SURVEYSCAN_V2_BAO_ADDR='http://127.0.0.1:58200',SURVEYSCAN_V2_MACHINE_CONFIG=machine_file)
  env.pop('SURVEYSCAN_V2_INSECURE_LOCAL_HTTP',None)
  def command(*args):
   p=subprocess.run([str(ROOT/'.dist/surveyscan-server'),*args],cwd=ROOT,env=env,capture_output=True,text=True,timeout=30)
   assert p.returncode==0,'server console failed';return p.stdout
  def start(name,args):
   with (directory/(name+'.log')).open('ab') as log:p=subprocess.Popen(args,cwd=ROOT,env=env,stdout=log,stderr=log)
   processes.append(p);return p
  def context(cert=None,key=None):
   c=ssl.create_default_context(cafile=ca_file)
   if cert:c.load_cert_chain(cert,key)
   return c
  def request(port,ctx,method,path,data=None,headers=None,sni=None):
   connection=http.client.HTTPSConnection('127.0.0.1',port,context=ctx,timeout=8)
   if sni:
    connection.sock=ctx.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=8),server_hostname=sni)
   h=dict(headers or {})
   if data is not None:h['Content-Type']='application/json';data=json.dumps(data).encode()
   try:
    connection.request(method,path,body=data,headers=h);response=connection.getresponse();body=response.read();return response.status,json.loads(body) if body else None,response.getheader('Set-Cookie')
   finally:connection.close()
  def ready(port,ctx,sni=None):
   for _ in range(100):
    try:
     if request(port,ctx,'GET','/health/live',sni=sni)[0]==200:return
    except (OSError,http.client.HTTPException):pass
    time.sleep(.1)
   raise RuntimeError('machine/collector binary did not start')
  try:
   sql('CREATE DATABASE '+db);created=True
   assert 'applied_migrations=28' in command('migrate')
   password=secrets.token_urlsafe(32);password_file=save('password',password+'\n');command('bootstrap-admin','--tenant',tenant,'--tenant-name','C07 synthetic','--username','admin','--password-file',password_file)
   sql(f"INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact) VALUES('{tenant}','{subject}','team','fallback','synthetic@example.invalid'); INSERT INTO scope.sites(tenant_id,site_id,name,fallback_subject_id) VALUES('{tenant}','{site}','synthetic','{subject}'); INSERT INTO scope.network_scopes(tenant_id,scope_id,site_id,namespace) VALUES('{tenant}','{scope}','{site}','default');",db)
   start('center',[str(ROOT/'.dist/surveyscan-server'),'serve']);plain=context();ready(tls_port,plain);checks.append('compiled center starts with explicit private loopback PKI')
   status,session,cookie=request(tls_port,plain,'POST','/api/v1/auth/sessions',{'username':'admin','password':password},{'Origin':origin});assert status==201;cookie=cookie.split(';',1)[0]
   def enroll_material():
    key=ed25519.Ed25519PrivateKey.generate();signing=ed25519.Ed25519PrivateKey.generate();csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'untrusted-subject')])).sign(key,None)
    return key,signing,csr
   def grant(source,kind,collector,key,csr):
    body={'tenant_id':tenant,'source_id':source,'source_kind':kind,'site_id':site,'collector_id':collector,'ttl_seconds':900,'csr_sha256':hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest(),'signing_public_key':b64(rawpublic(key))}
    status,result,_=request(tls_port,plain,'POST','/api/v1/enrollments',body,{'Origin':origin,'Cookie':cookie,'X-CSRF-Token':session['csrf_token']});assert status==201;return result
   collector_source=uid();collector_key,collector_sign,csr=enroll_material();permission=grant(collector_source,'collector',None,collector_sign,csr)
   body={'grant_id':permission['grant_id'],'source_id':collector_source,'csr_pem':csr.public_bytes(serialization.Encoding.PEM).decode(),'signing_public_key':b64(rawpublic(collector_sign))};status,collector_result,_=request(tls_port,plain,'POST','/api/v1/machine/enroll',body,{'Authorization':'Bearer '+permission['enrollment_token']});assert status==201
   collector_cert=save('collector.pem',collector_result['certificate_chain_pem']);collector_private=save('collector.key',private(collector_key));cert=x509.load_pem_x509_certificate(collector_result['certificate_chain_pem'].encode());uris=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier);collector_id=next(u.rsplit('/',1)[1] for u in uris if '/kind/collector/' in u)
   cfg=save('collector.json',json.dumps({'listen':f'127.0.0.1:{collector_port}','center_url':origin,'certificate_file':collector_cert,'private_key_file':collector_private,'ca_certificate_file':ca_file,'spool_directory':str(directory/'spool'),'spool_limit_bytes':1048576}));start('collector',[str(ROOT/'.dist/surveyscan-collector'),'run','--config',cfg]);collector_name=collector_source+'.collector.invalid';ready(collector_port,plain,collector_name);checks.append('compiled collector enrolls and starts HTTPS daemon')
   if agent_scenario is not None:
    agent_scenario(checks=checks,save=save,request=request,sql=lambda query:sql(query,db),start=start,tenant=tenant,site=site,scope=scope,collector_port=collector_port,collector_source=collector_source,collector_id=collector_id,ca_file=ca_file,directory=directory,tls_port=tls_port,plain=plain,origin=origin,cookie=cookie,session=session,subject=subject)
    return
   agent_source=uid();agent_key,agent_sign,agent_csr=enroll_material();permission=grant(agent_source,'agent',collector_id,agent_sign,agent_csr);body={'grant_id':permission['grant_id'],'source_id':agent_source,'csr_pem':agent_csr.public_bytes(serialization.Encoding.PEM).decode(),'signing_public_key':b64(rawpublic(agent_sign))};status,agent_result,_=request(collector_port,plain,'POST','/api/v1/machine/enroll',body,{'Authorization':'Bearer '+permission['enrollment_token']},collector_name);assert status==201;checks.append('synthetic agent enrollment traverses collector')
   agent_cert=save('agent.pem',agent_result['certificate_chain_pem']);agent_private=save('agent.key',private(agent_key));client=context(agent_cert,agent_private);stamp=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
   payload={'schema_version':{'major':1,'minor':0},'observation_id':uid(),'tenant_id':tenant,'origin':{'source_id':agent_source,'source_kind':'agent','generation_id':agent_result['generation_id']},'source_record':{'namespace':'host','source_local_id':'synthetic-host'},'scope':{'site_id':site,'network_scope_id':scope},'source_sequence':'1','collected_at':stamp,'clock_quality':'trusted','identity_candidates':[{'kind':'hostname','namespace':'dns','value':'pipeline-host'}],'sections':[{'name':'identity','collected_at':stamp,'status':'ok','collection_complete':True,'reason_code':'COLLECTED','record_count':1,'records':[{'hostname':'pipeline-host'}]}]}
   canonical=rfc8785.dumps(payload);record={'payload':payload,'digest':hashlib.sha256(canonical).hexdigest(),'key_id':agent_result['signing_key_id'],'signature':b64(agent_sign.sign(b'SURVEYSCAN-OBSERVATION-V1\n'+canonical))};batch={'schema_version':{'major':1,'minor':0},'tenant_id':tenant,'delivery_id':uid(),'records':[record]};status,transport,_=request(collector_port,client,'POST','/api/v1/machine/observations',batch,sni=collector_name);assert status==202 and transport['spool_action']=='retain';checks.append('durable collector transport receipt retains source data')
   for _ in range(80):
    status,result,_=request(collector_port,client,'GET','/api/v1/machine/deliveries/'+batch['delivery_id'],sni=collector_name)
    if status==200 and 'payload' in result:break
    time.sleep(.2)
   else:raise RuntimeError('center result did not arrive')
   signed=result['payload'];center_key.public_key().verify(base64.urlsafe_b64decode(result['signature']+'=='),b'SURVEYSCAN-CENTER-RESULT-V1\n'+rfc8785.dumps(signed));assert signed['batch_digest']==hashlib.sha256(rfc8785.dumps(batch)).hexdigest() and signed['delivery_id']==batch['delivery_id'] and signed['results'][0]['observation_digest']==record['digest'];assert signed['results'][0]['disposition']=='applied';checks.append('center commit receipt verifies with pinned key and exact bindings')
   status,card,_=request(tls_port,plain,'GET','/api/v1/assets/'+signed['results'][0]['asset_uid'],headers={'Cookie':cookie});assert status==200 and card['observed_hostname']=='pipeline-host' and card['accountable_subject_id']==subject;checks.append('committed PG registry card visible through real authenticated API')
   assert not (directory/'spool'/(batch['delivery_id']+'.pending')).exists();checks.append('collector trims only after verified center acknowledgement')
   assert sql('SELECT count(*) FROM inventory.observations',db)=='1';checks.append('exactly one durable observation in isolated PostgreSQL')
   report={'package':'C07','status':'passed','checks':checks,'count':len(checks),'target':'compiled server + compiled collector + real TLS/mTLS + synthetic Python Ed25519 source + PostgreSQL','keys':'temporary private files removed after run; no credential in report'};(STATE/'machine-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
  finally:
   for process in reversed(processes):
    process.terminate()
    try:process.wait(timeout=7)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
   if created:sql('DROP DATABASE '+db+' WITH (FORCE)')
if __name__=='__main__':main()
