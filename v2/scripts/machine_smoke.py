#!/usr/bin/env python3
"""C07 live binaries, private dev PKI and synthetic agent through collector; no credential output."""
import base64,contextlib,datetime,hashlib,http.client,http.cookiejar,json,os,secrets,socket,ssl,subprocess,tempfile,time,uuid
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
def main(agent_scenario=None,web_scenario=None,browser_origin=None,bao_settings=None,report_directory=None,inventory12=False,collector_inventory12=False,persist=None):
 # persist=Path — постоянный стенд (vm_center --persistent): каталог, БД, tenant, admin и collector сохраняются между запусками.
 initialize();db='ssv2machine_'+uuid.uuid4().hex;tenant,site,scope,subject=uid(),uid(),uid(),uid();processes=[];checks=[];created=False
 state=json.loads((Path(persist)/'stand.json').read_text()) if persist and (Path(persist)/'stand.json').exists() else None
 if state:db,tenant,site,scope,subject=state['db'],state['tenant'],state['site'],state['scope'],state['subject']
 def sql(query,database='surveyscan_v2'):
  return compose('exec','-T','db','psql','-U','surveyscan_v2','-d',database,'-v','ON_ERROR_STOP=1','-Atc',query,capture=True).strip()
 with (contextlib.nullcontext(str(persist)) if persist else tempfile.TemporaryDirectory(prefix='c07-',dir=STATE)) as temporary:
  directory=Path(temporary)
  def save(name,data):
   p=directory/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|(os.O_TRUNC if persist else os.O_EXCL),0o600)
   with os.fdopen(fd,'wb') as f:f.write(data if isinstance(data,bytes) else data.encode())
   return str(p)
  def private(key):return key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
  if bao_settings is None:
   ca_key=ed25519.Ed25519PrivateKey.generate();now=datetime.datetime.now(datetime.timezone.utc)
   ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'C07 synthetic dev CA')])
   ca=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),False).sign(ca_key,None)
   ca_file=save('ca.pem',ca.public_bytes(serialization.Encoding.PEM));ca_private=save('ca.key',private(ca_key))
   server_key=ed25519.Ed25519PrivateKey.generate();server=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'C07 center')])).issuer_name(ca_name).public_key(server_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=12)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False).sign(ca_key,None)
   server_file=save('server.pem',server.public_bytes(serialization.Encoding.PEM));server_private=save('server.key',private(server_key));center_key=ed25519.Ed25519PrivateKey.generate();center_id=uid();center_private=save('center.json',json.dumps({'key_id':center_id,'private_key':b64(center_key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())+rawpublic(center_key))}))
  else:
   ca_file=save('ca.pem',Path(bao_settings['ca_certificate']).read_bytes());ca_private=''
   server_file=save('server.pem',Path(bao_settings['server_certificate']).read_bytes());server_private=save('server.key',Path(bao_settings['server_private']).read_bytes());center_id=bao_settings['center_id'];center_private=''
   class PublicOnly:
    def public_key(self):return ed25519.Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(bao_settings['center_public']+'=='))
   center_key=PublicOnly()
  tls_port,http_port,collector_port=(state['tls_port'] if state else freeport()),(state['http_port'] if state else freeport()),int(os.environ.get('C15_COLLECTOR_PORT') or freeport());machine_file=save('machine.json',json.dumps({'dev_mode':True,'listen':f'127.0.0.1:{tls_port}','ca_certificate_file':ca_file,'ca_private_key_file':ca_private,'server_certificate_file':server_file,'server_private_key_file':server_private,'center_signing_key_file':center_private}))
  if inventory12:
   cfg=json.loads(Path(machine_file).read_text());cfg['inventory12_enabled']=True;Path(machine_file).write_text(json.dumps(cfg))
  if bao_settings is not None:
   cfg=json.loads(Path(machine_file).read_text());cfg['openbao_config_file']=bao_settings['config'];cfg['center_signing_key_id']=center_id;Path(machine_file).write_text(json.dumps(cfg))
  origin=f'https://127.0.0.1:{tls_port}';browser_origin=browser_origin or origin;env=dict(os.environ,SURVEYSCAN_V2_DATABASE_URL=f'postgres://surveyscan_v2@127.0.0.1:55432/{db}?sslmode=disable',SURVEYSCAN_V2_DATABASE_PASSWORD_FILE=str(STATE/'pg_password'),SURVEYSCAN_V2_PUBLIC_ORIGIN=browser_origin,SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{http_port}',SURVEYSCAN_V2_BAO_ADDR='http://127.0.0.1:58200',SURVEYSCAN_V2_MACHINE_CONFIG=machine_file)
  env.pop('SURVEYSCAN_V2_INSECURE_LOCAL_HTTP',None)
  if browser_origin.startswith('http://127.0.0.1:'):env['SURVEYSCAN_V2_INSECURE_LOCAL_HTTP']='1'
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
   if state:
    command('migrate');password=(directory/'password').read_text().strip()  # постоянный стенд: только новые миграции
   else:
    sql('CREATE DATABASE '+db);created=True
    assert 'applied_migrations=43' in command('migrate')
   if not state:
    password=secrets.token_urlsafe(32);password_file=save('password',password+'\n');command('bootstrap-admin','--tenant',tenant,'--tenant-name','C07 synthetic','--username','admin','--password-file',password_file)
    sql(f"INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact) VALUES('{tenant}','{subject}','team','fallback','synthetic@example.invalid'); INSERT INTO scope.sites(tenant_id,site_id,name,fallback_subject_id) VALUES('{tenant}','{site}','synthetic','{subject}'); INSERT INTO scope.network_scopes(tenant_id,scope_id,site_id,namespace) VALUES('{tenant}','{scope}','{site}','default');",db)
   center_process=start('center',[str(ROOT/'.dist/surveyscan-server'),'serve']);plain=context();ready(tls_port,plain);checks.append('compiled center starts with explicit private loopback PKI')
   # постоянный стенд (R-027): прежняя сессия обвязки закрывается до входа — иначе каждый перезапуск оставляет активную
   # сессию admin, и после 5 перезапусков вход упирается в лимит сессий пользователя (центр не стартует)
   previous=directory/'harness-session.json'
   if persist and previous.exists():
    try:
     old=json.loads(previous.read_text());request(tls_port,plain,'DELETE','/api/v1/auth/session',None,{'Origin':browser_origin,'Cookie':old['cookie'],'X-CSRF-Token':old['csrf']})
    except Exception:pass  # просроченная или уже отозванная сессия — не препятствие для старта
   status,session,cookie=request(tls_port,plain,'POST','/api/v1/auth/sessions',{'username':'admin','password':password},{'Origin':browser_origin});assert status==201,('admin login',status);cookie=cookie.split(';',1)[0]
   if persist:save('harness-session.json',json.dumps({'cookie':cookie,'csrf':session['csrf_token']}))
   def enroll_material():
    key=ed25519.Ed25519PrivateKey.generate();signing=ed25519.Ed25519PrivateKey.generate();csr=x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'untrusted-subject')])).sign(key,None)
    return key,signing,csr
   def grant(source,kind,collector,key,csr):
    body={'tenant_id':tenant,'source_id':source,'source_kind':kind,'site_id':site,'collector_id':collector,'ttl_seconds':900,'csr_sha256':hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).hexdigest(),'signing_public_key':b64(rawpublic(key))}
    if kind=='agent' and os.environ.get('C15_SMOKE_PLATFORM'):body['inventory_platform']=os.environ['C15_SMOKE_PLATFORM']
    status,result,_=request(tls_port,plain,'POST','/api/v1/enrollments',body,{'Origin':browser_origin,'Cookie':cookie,'X-CSRF-Token':session['csrf_token']});assert status==201;return result
   if state:  # постоянный стенд: collector уже зарегистрирован, его ключи и конфиг в каталоге
    collector_source,collector_id,collector_result=state['collector_source'],state['collector_id'],None
    cfg,collector_cert,collector_private=str(directory/'collector.json'),str(directory/'collector.pem'),str(directory/'collector.key')
   else:
    collector_source=uid();collector_key,collector_sign,csr=enroll_material();permission=grant(collector_source,'collector',None,collector_sign,csr)
    body={'grant_id':permission['grant_id'],'source_id':collector_source,'csr_pem':csr.public_bytes(serialization.Encoding.PEM).decode(),'signing_public_key':b64(rawpublic(collector_sign))};status,collector_result,_=request(tls_port,plain,'POST','/api/v1/machine/enroll',body,{'Authorization':'Bearer '+permission['enrollment_token']});assert status==201
    collector_cert=save('collector.pem',collector_result['certificate_chain_pem']);collector_private=save('collector.key',private(collector_key));cert=x509.load_pem_x509_certificate(collector_result['certificate_chain_pem'].encode());uris=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier);collector_id=next(u.rsplit('/',1)[1] for u in uris if '/kind/collector/' in u)
    collector_signing=save('collector-signing.key',private(collector_sign))
    cfg=save('collector.json',json.dumps({'source_id':collector_source,'credential_directory':str(directory/'collector-credentials'),'signing_private_key_file':collector_signing,'listen':f"{os.environ.get('C15_COLLECTOR_BIND','127.0.0.1')}:{collector_port}",'center_url':origin,'certificate_file':collector_cert,'private_key_file':collector_private,'ca_certificate_file':ca_file,'spool_directory':str(directory/'spool'),'spool_limit_bytes':1048576}))
    if collector_inventory12:
     collector_settings=json.loads(Path(cfg).read_text());collector_settings['inventory12_enabled']=True;Path(cfg).write_text(json.dumps(collector_settings))
    if persist:(directory/'stand.json').write_text(json.dumps({'db':db,'tenant':tenant,'site':site,'scope':scope,'subject':subject,'tls_port':tls_port,'http_port':http_port,'collector_source':collector_source,'collector_id':collector_id}))
   collector_process=start('collector',[str(ROOT/'.dist/surveyscan-collector'),'run','--config',cfg]);collector_name=collector_source+'.collector.invalid';ready(collector_port,plain,collector_name);checks.append('compiled collector enrolls and starts HTTPS daemon')
   if agent_scenario is not None:
    agent_scenario(command=command,checks=checks,save=save,request=request,sql=lambda query:sql(query,db),start=start,tenant=tenant,site=site,scope=scope,collector_port=collector_port,collector_source=collector_source,collector_id=collector_id,ca_file=ca_file,directory=directory,tls_port=tls_port,plain=plain,origin=origin,cookie=cookie,session=session,subject=subject,center_process=center_process,collector_process=collector_process,collector_config=cfg,server_environment=dict(env),collector_result=collector_result,collector_client=context(collector_cert,collector_private),grant=grant,enroll_material=enroll_material)
    return
   agent_source=uid();agent_key,agent_sign,agent_csr=enroll_material();permission=grant(agent_source,'agent',collector_id,agent_sign,agent_csr);body={'grant_id':permission['grant_id'],'source_id':agent_source,'csr_pem':agent_csr.public_bytes(serialization.Encoding.PEM).decode(),'signing_public_key':b64(rawpublic(agent_sign))};status,agent_result,_=request(collector_port,plain,'POST','/api/v1/machine/enroll',body,{'Authorization':'Bearer '+permission['enrollment_token']},collector_name);assert status==201;checks.append('synthetic agent enrollment traverses collector')
   agent_cert=save('agent.pem',agent_result['certificate_chain_pem']);agent_private=save('agent.key',private(agent_key));client=context(agent_cert,agent_private);stamp=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
   payload={'schema_version':{'major':1,'minor':0},'observation_id':uid(),'tenant_id':tenant,'origin':{'source_id':agent_source,'source_kind':'agent','generation_id':agent_result['generation_id']},'source_record':{'namespace':'host','source_local_id':'synthetic-host'},'scope':{'site_id':site,'network_scope_id':scope},'source_sequence':'1','collected_at':stamp,'clock_quality':'trusted','identity_candidates':[{'kind':'hostname','namespace':'dns','value':'pipeline-host'}],'sections':[{'name':'identity','collected_at':stamp,'status':'ok','collection_complete':True,'reason_code':'COLLECTED','record_count':1,'records':[{'hostname':'pipeline-host'}]}]}
   if web_scenario is not None:
    payload['sections'] += [{'name':'os','collected_at':stamp,'status':'ok','collection_complete':True,'reason_code':'COLLECTED','record_count':1,'records':[{'name':'Linux','version':'synthetic','architecture':'amd64'}]},{'name':'network','collected_at':stamp,'status':'ok','collection_complete':True,'reason_code':'COLLECTED','record_count':1,'records':[{'name':'eth0','mac':'02:00:00:00:00:01','addresses':[{'ip':'192.0.2.9','prefix':24}]}]}]
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
   if bao_settings is not None:
    bao_settings['hook'](directory=directory,context=context,checks=checks,request=request,sql=lambda query:sql(query,db),start=start,center_process=center_process,tls_port=tls_port,collector_port=collector_port,collector_name=collector_name,client=client,plain=plain,cookie=cookie,session=session,origin=browser_origin,grant=grant,enroll_material=enroll_material,payload=payload,agent_sign=agent_sign,agent_result=agent_result,center_key=center_key,center_id=center_id,asset=signed['results'][0]['asset_uid'],site=site,tenant=tenant,collector_id=collector_id,agent_source=agent_source,collector_source=collector_source,collector_result=collector_result,collector_client=context(collector_cert,collector_private))
    return
   if web_scenario is not None:
    def quiesce():
     for process in reversed(processes):
      if process.poll() is None:
       process.terminate();assert process.wait(timeout=8)==0,'fixture service did not stop cleanly'
    web_scenario(sql=lambda query:sql(query,db),command=command,directory=directory,origin=browser_origin,center_port=tls_port,ca_file=ca_file,username='admin',password=password,asset=signed['results'][0]['asset_uid'],tenant=tenant,checks=checks,quiesce=quiesce,server_environment=dict(env),center_process=center_process,collector_process=collector_process)
    return
   report={'package':'C07','status':'passed','checks':checks,'count':len(checks),'target':'compiled server + compiled collector + real TLS/mTLS + synthetic Python Ed25519 source + PostgreSQL','keys':'temporary private files removed after run; no credential in report'};((Path(report_directory) if report_directory is not None else STATE)/'machine-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
  finally:
   for process in reversed(processes):
    process.terminate()
    try:process.wait(timeout=7)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
   if created and not persist:sql('DROP DATABASE '+db+' WITH (FORCE)')
if __name__=='__main__':main()
