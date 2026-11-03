"""C03 executable contract examples. No HTTP server, database or production handler."""
import base64,calendar,datetime,hashlib,json,math
import ipaddress
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from jsonschema import Draft202012Validator,FormatChecker
from referencing import Registry,Resource

DOMAINS={'SignedObservation':b'SURVEYSCAN-OBSERVATION-V1\n','SignedHeartbeat':b'SURVEYSCAN-HEARTBEAT-V1\n','SignedCenterResult':b'SURVEYSCAN-CENTER-RESULT-V1\n','RenewRequest':b'SURVEYSCAN-RENEWAL-V1\n'}
class ContractError(Exception):
 def __init__(self,code):super().__init__(code);self.code=code

def fail(code):raise ContractError(code)
def strict_loads(raw):
 if len(raw)>1048576:fail('PAYLOAD_TOO_LARGE')
 def pairs(items):
  out={}
  for key,val in items:
   if key in out:fail('INVALID_JSON')
   out[key]=val
  return out
 def safe(value,depth=0):
  if depth>32:fail('INVALID_JSON')
  if isinstance(value,str):value.encode('utf-8',errors='strict')
  elif isinstance(value,float) and not math.isfinite(value):fail('INVALID_JSON')
  elif isinstance(value,dict):
   for k,v in value.items():safe(k,depth+1);safe(v,depth+1)
  elif isinstance(value,list):
   for v in value:safe(v,depth+1)
 try:
  result=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _:fail('INVALID_JSON'))
  safe(result)
  return result
 except (UnicodeError,ValueError,RecursionError):fail('INVALID_JSON')
def canonical(payload):
 try:return rfc8785.dumps(payload)
 except (ValueError,TypeError):fail('CANONICALIZATION_FAILED')
def sha(payload):return hashlib.sha256(canonical(payload)).hexdigest()
def decode64(s):
 try:return base64.urlsafe_b64decode(s+'='*((4-len(s)%4)%4))
 except (ValueError,TypeError):fail('SIGNATURE_INVALID')
def schema_check(name,data,wire):
 payload=data.get('payload',data) if isinstance(data,dict) else {}
 if isinstance(payload,dict) and 'schema_version' in payload and payload['schema_version']!={'major':1,'minor':0}:fail('UNSUPPORTED_SCHEMA_VERSION')
 registry=Registry().with_resource(wire['$id'],Resource.from_contents(wire))
 validator=Draft202012Validator({'$ref':wire['$id']+'#/$defs/'+name},registry=registry,format_checker=FormatChecker())
 if next(validator.iter_errors(data),None) is not None:fail('SCHEMA_INVALID')
def signed_check(name,envelope,keys):
 if envelope['digest']!=sha(envelope['payload']):fail('DIGEST_MISMATCH')
 k=keys.get(envelope['key_id'])
 if k is None:fail('SIGNING_KEY_UNKNOWN')
 try:Ed25519PublicKey.from_public_bytes(decode64(k)).verify(decode64(envelope['signature']),DOMAINS[name]+canonical(envelope['payload']))
 except (InvalidSignature,ValueError):fail('SIGNATURE_INVALID')
def origin_check(payload,ctx):
 if payload['tenant_id']!=ctx['tenant_id']:fail('AUTH_SCOPE_MISMATCH')
 origin=payload['origin'];binding=ctx['sources'].get(origin['source_id'])
 if binding is None or binding.get('revoked'):fail('SOURCE_NOT_AUTHORIZED')
 if origin['source_kind']!=binding['source_kind']:fail('AUTH_SCOPE_MISMATCH')
 if origin['generation_id']!=binding['generation_id']:fail('GENERATION_MISMATCH')
 return binding

def time_ns(value):
 base,_,fraction=value[:-1].partition('.')
 try:
  timestamp=datetime.datetime.strptime(base,'%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
  return calendar.timegm(timestamp.utctimetuple())*10**9+int((fraction+'0'*9)[:9])
 except (ValueError,TypeError):fail('TIMESTAMP_INVALID')

def validate_counters(value):
 names={'source_sequence','heartbeat_sequence','aggregate_version','lease_version','revision','business_revision','profile_revision','result_revision'}
 if isinstance(value,dict):
  for key,item in value.items():
   if key in names and (not isinstance(item,str) or not 1<=int(item)<=2**64-1):fail('INTEGER_OUT_OF_RANGE')
   validate_counters(item)
 elif isinstance(value,list):
  for item in value:validate_counters(item)

def observation_check(envelope,ctx,wire):
 schema_check('SignedObservation',envelope,wire);payload=envelope['payload'];binding=origin_check(payload,ctx)
 if payload['origin']['source_kind'] not in ctx.get('capabilities',['agent','collector']):fail('CAPABILITY_NOT_ENABLED')
 if envelope['key_id'] not in binding['key_ids']:fail('SOURCE_NOT_AUTHORIZED')
 if payload['scope']!=binding['scope']:fail('AUTH_SCOPE_MISMATCH')
 if payload.get('asserted_asset_uid') and payload['asserted_asset_uid'] not in ctx.get('allowed_asset_ids',[]):fail('ASSET_ASSERTION_FORBIDDEN')
 signed_check('SignedObservation',envelope,ctx['origin_keys'])
 if len(canonical(payload))>65536:fail('PAYLOAD_TOO_LARGE')
 if int(payload['source_sequence'])>2**64-1:fail('INTEGER_OUT_OF_RANGE')
 names=[s['name'] for s in payload['sections']]
 if len(set(names))!=len(names):fail('SECTION_DUPLICATE')
 for section in payload['sections']:
  if section['record_count']!=len(section['records']):fail('RECORD_COUNT_MISMATCH')
  if section['status']=='partial' and section['collection_complete']:fail('SECTION_COMPLETENESS_INVALID')
  if section['status']=='unknown' and not ctx.get('legacy_import',False):fail('LEGACY_STATUS_NOT_ALLOWED')
  if time_ns(section['collected_at'])>time_ns(payload['collected_at']):fail('SECTION_TIME_INVALID')
  if section['name']=='network':
   for record in section['records']:
    for address in record['addresses']:
     if address['prefix']>ipaddress.ip_address(address['ip']).max_prefixlen:fail('INVALID_PREFIX')
 return True

def validate_contract(name,data,ctx,wire):
 schema_check(name,data,wire)
 validate_counters(data)
 if name=='SignedObservation':return observation_check(data,ctx,wire)
 if name=='Batch':
  if data['tenant_id']!=ctx['tenant_id']:fail('AUTH_SCOPE_MISMATCH')
  if ctx.get('prior_delivery_digest') not in (None,sha(data)):fail('DELIVERY_DIGEST_CONFLICT')
  ids=[e['payload']['observation_id'] for e in data['records']]
  if len(set(ids))!=len(ids):fail('BATCH_RECORD_DUPLICATE')
  for envelope in data['records']:observation_check(envelope,ctx,wire)
 if name=='SignedHeartbeat':
  payload=data['payload'];binding=origin_check(payload,ctx)
  if data['key_id'] not in binding['key_ids']:fail('SOURCE_NOT_AUTHORIZED')
  signed_check(name,data,ctx['origin_keys'])
  challenge=ctx['challenge']
  if challenge.get('purpose')!='heartbeat':fail('HEARTBEAT_CHALLENGE_MISMATCH')
  for field in ('challenge_id','nonce','tenant_id'):
   if payload[field]!=challenge[field]:fail('HEARTBEAT_CHALLENGE_MISMATCH')
  if payload['origin']['source_id']!=challenge['source_id'] or payload['origin']['generation_id']!=challenge['generation_id']:fail('HEARTBEAT_CHALLENGE_MISMATCH')
  if ctx.get('consumed'):
   if ctx.get('prior_heartbeat_id')==payload['heartbeat_id'] and ctx.get('prior_heartbeat_digest')==data['digest']:return True
   fail('HEARTBEAT_REPLAY')
  if time_ns(ctx['now'])>=time_ns(challenge['expires_at']):fail('HEARTBEAT_EXPIRED')
  if int(payload['heartbeat_sequence'])>2**64-1:fail('INTEGER_OUT_OF_RANGE')
  if int(payload['heartbeat_sequence'])<=int(ctx.get('prior_heartbeat_sequence','0')):fail('HEARTBEAT_SEQUENCE_STALE')
 if name=='SignedCenterResult':
  signed_check(name,data,ctx['center_keys']);payload=data['payload'];batch=ctx['batch']
  if payload['tenant_id']!=ctx['tenant_id'] or payload['tenant_id']!=batch['tenant_id'] or payload['delivery_id']!=batch['delivery_id'] or payload['batch_digest']!=sha(batch):fail('RECEIPT_BINDING_MISMATCH')
  expected={(x['payload']['origin']['source_id'],x['payload']['observation_id'],x['digest']) for x in batch['records']}
  actual=[(x['origin_source_id'],x['observation_id'],x['observation_digest']) for x in payload['results']]
  if set(actual)!=expected or len(actual)!=len(expected):fail('RECEIPT_BINDING_MISMATCH')
  if payload['status']=='completed' and any(x['disposition']!='applied' for x in payload['results']):fail('RECEIPT_STATE_INVALID')
 if name=='EnrollmentRequest':
  grant=ctx['grant']
  if data['source_id']!=grant['source_id'] or data['grant_id']!=grant['grant_id'] or data['signing_public_key']!=grant['signing_public_key']:fail('ENROLLMENT_BINDING_MISMATCH')
  if time_ns(ctx['now'])>=time_ns(grant['expires_at']):fail('ENROLLMENT_EXPIRED')
  try:csr=x509.load_pem_x509_csr(data['csr_pem'].encode())
  except ValueError:fail('CSR_INVALID')
  if not csr.is_signature_valid or hashlib.sha256(csr.public_bytes(Encoding.DER)).hexdigest()!=grant['csr_sha256']:fail('ENROLLMENT_BINDING_MISMATCH')
 if name=='RenewRequest':
  payload=data['payload'];binding=origin_check(payload,ctx)
  if data['key_id'] not in binding['key_ids']:fail('SOURCE_NOT_AUTHORIZED')
  signed_check(name,data,ctx['origin_keys']);challenge=ctx['challenge']
  if challenge.get('purpose')!='cert_renew' or any(payload[x]!=challenge[x] for x in ('challenge_id','nonce','tenant_id')) or payload['origin']['source_id']!=challenge['source_id'] or payload['origin']['generation_id']!=challenge['generation_id']:fail('RENEWAL_CHALLENGE_MISMATCH')
  if time_ns(ctx['now'])>=time_ns(challenge['expires_at']):fail('RENEWAL_EXPIRED')
  try:csr=x509.load_pem_x509_csr(payload['csr_pem'].encode())
  except ValueError:fail('CSR_INVALID')
  if not csr.is_signature_valid:fail('CSR_INVALID')
 if name=='OutboxEvent':
  kind={'asset.created.v1':('asset','Assets','asset_uid'),'asset.facts_changed.v1':('asset','Assets','asset_uid'),'observation.recorded.v1':('observation','Inventory','observation_id'),'responsibility.assigned.v1':('asset','Responsibility','asset_uid'),'source.contact_updated.v1':('source','Sources','source_id')}[data['event_type']]
  if (data['aggregate_type'],data['producer_module'])!=kind[:2] or data['data'].get(kind[2])!=data['aggregate_id']:fail('EVENT_BINDING_MISMATCH')
  if int(data['aggregate_version'])>2**64-1:fail('INTEGER_OUT_OF_RANGE')
 return True
