"""Own scoped OpenBao test resources; root used solely for reversible provisioning/cleanup."""
import base64,contextlib,json,os,secrets,uuid,urllib.request,urllib.error
from pathlib import Path
from dev import STATE,unseal,compose

def b64(raw):return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
@contextlib.contextmanager
def fixture(directory):
 unseal();address='http://127.0.0.1:58200';initial=json.loads((STATE/'bao-init.json').read_text());root=initial['root_token'];prefix='c11-'+uuid.uuid4().hex[:20];transit=prefix+'-tr';kv=prefix+'-kv';policy=prefix+'-server';token=None;extra_tokens=[];mounted=[];audit_path="/openbao/file/surveyscan-audit.jsonl"
 def call(method,path,body=None,credential=None):
  request=urllib.request.Request(address+'/v1/'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'X-Vault-Token':credential or root,'Content-Type':'application/json'})
  with urllib.request.urlopen(request,timeout=5) as response:raw=response.read();return json.loads(raw) if raw else {}
 def save(name,value):
  path=directory/name;fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  with os.fdopen(fd,'w') as f:f.write(value)
  return str(path)
 def assert_redacted(*texts):
  protected=[root,canary,*extra_tokens]+([token] if token else [])
  assert all(value not in text for text in texts for value in protected),'raw test secret present in emitted output'
  return True
 def audit_check():
  raw=compose('exec','-T','bao','cat',audit_path,capture=True)
  assert prefix in raw and '"type":"request"' in raw, 'actual scoped audit events missing'
  assert root not in raw and (token is None or token not in raw) and canary not in raw and all(t not in raw for t in extra_tokens),'raw test secret present in Bao audit'
  return True
 try:
  for mount,kind,options in [(transit,'transit',{}),(kv,'kv',{'version':'2'})]:call('POST','sys/mounts/'+mount,{'type':kind,'options':options});mounted.append(mount)
  keys={}
  for name in ['ca','center','forbidden']:
   call('POST',transit+'/keys/'+name,{'type':'ed25519','exportable':False,'allow_plaintext_backup':False})
   if name!='forbidden':
    data=call('GET',transit+'/keys/'+name)['data'];public=data['keys']['1']['public_key'];keys[name]={'name':name,'version':1,'public_key':b64(base64.b64decode(public))}
  canary='C11-private-'+secrets.token_urlsafe(24);call('POST',kv+'/data/server/runtime',{'data':{'canary':canary}})
  paths={'auth/token/lookup-self':['read'],'auth/token/renew-self':['update'],kv+'/data/server/runtime':['read']}
  for key in ['ca','center']:paths[transit+'/keys/'+key]=['read'];paths[transit+'/sign/'+key]=['update']
  hcl='\n'.join('path '+json.dumps(path)+' { capabilities = '+json.dumps(caps)+' }' for path,caps in paths.items());call('PUT','sys/policies/acl/'+policy,{'policy':hcl});save('server-policy.hcl',hcl+'\n')
  token=call('POST','auth/token/create',{'policies':[policy],'no_default_policy':True,'period':'1h','renewable':True,'no_parent':True})['auth']['client_token'];token_file=save('server-token',token+'\n');root_file=save('root-negative-test-token',root+'\n')
  cfg={'address':address,'dev_loopback_http':True,'token_file':token_file,'policy':policy,'transit_mount':transit,'kv_mount':kv,'keys':keys,'secrets':{'canary':{'path':'server/runtime','field':'canary'}}};config=save('bao-config.json',json.dumps(cfg));root_cfg=dict(cfg,token_file=root_file);root_config=save('root-negative-config.json',json.dumps(root_cfg))
  short=call('POST','auth/token/create',{'policies':[policy],'no_default_policy':True,'period':'30s','renewable':True,'no_parent':True})['auth']['client_token'];extra_tokens.append(short)
  short_file=save('short-token',short+'\n');short_cfg=dict(cfg,token_file=short_file);short_config=save('short-config.json',json.dumps(short_cfg))
  dead=call('POST','auth/token/create',{'policies':[policy],'no_default_policy':True,'period':'1h','renewable':True,'no_parent':True})['auth']['client_token'];call('POST','auth/token/revoke',{'token':dead});dead_file=save('revoked-token',dead+'\n')
  yield {'short_config':short_config,'revoked_token_file':dead_file,'assert_redacted':assert_redacted,'audit_check':lambda: audit_check(), 'config':config,'root_config':root_config,'profile':cfg,'token':token,'canary':canary,'call':call,'transit':transit,'kv':kv,'policy':policy}
 finally:
  # Снять seal тем же authorized dev bootstrap, не reset volume/keys.
  try:unseal()
  except Exception:pass
  for extra in extra_tokens:
   try:call('POST','auth/token/revoke',{'token':extra})
   except Exception:pass
  if token:
   try:call('POST','auth/token/revoke',{'token':token})
   except Exception:pass
  try:call('DELETE','sys/policies/acl/'+policy)
  except Exception:pass
  for mount in reversed(mounted):
   try:call('DELETE','sys/mounts/'+mount)
   except Exception:pass
