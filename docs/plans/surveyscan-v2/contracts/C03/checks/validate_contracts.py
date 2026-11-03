"""Run with pinned external contract tools; validates files/examples, not a running service."""
from pathlib import Path
import json,sys,importlib.metadata,hashlib
from jsonschema import Draft202012Validator,FormatChecker
from openapi_spec_validator import validate
from reference_checks import strict_loads,validate_contract,ContractError,canonical

root=Path(__file__).resolve().parents[1]
wire=json.loads((root/'schemas/wire.schema.json').read_text())
api=json.loads((root/'openapi.json').read_text())
Draft202012Validator.check_schema(wire)
validate(api)
cases=json.loads((root/'fixtures/manifest.json').read_text())['cases'];results=[]
for case in cases:
 try:
  data=strict_loads((root/'fixtures'/case['file']).read_bytes())
  validate_contract(case['schema'],data,case['context'],wire)
  actual='OK'
 except ContractError as exc:actual=exc.code
 results.append({'id':case['id'],'title':case['title'],'expected':case['expected'],'actual':actual,'matched':actual==case['expected']})
byid={c['id']:c for c in cases};http=[]
ops={op['operationId']:op for methods in api['paths'].values() for op in methods.values()}
for i,example in enumerate(json.loads((root/'fixtures/http-examples.json').read_text()),1):
 op=ops[example['operation_id']];status=str(example['expected_status']);assert status in op['responses']
 for kind,key in [('request','request_fixture'),('response','response_fixture')]:
  if key not in example:continue
  case=byid[example[key]];data=strict_loads((root/'fixtures'/case['file']).read_bytes())
  content=(op['requestBody'] if kind=='request' else op['responses'][status])['content']['application/json']['schema']
  Draft202012Validator({**content,'components':api['components']},format_checker=FormatChecker()).validate(data)
 http.append({'id':f'C03-H{i:02}','operation':example['operation_id'],'status':'example_shape_valid','network_call':'not_run'})
states=json.loads((root/'state-machines.json').read_text());edges=[]
for case in states['state_tests']:
 actual=case['to'] in states[case['machine']]['transitions'][case['from']]
 edges.append({'id':case['id'],'expected':case['allowed_edge'],'actual':actual,'matched':actual==case['allowed_edge']})
vectors=json.loads((root/'fixtures/canonical-vectors.json').read_text());golden=[]
for i,vector in enumerate(vectors,1):golden.append({'id':f'C03-JCS{i:02}','matched':canonical(vector['input']).decode('utf-8')==vector['canonical_utf8']})
matched=all(x['matched'] for x in results+edges+golden)
report={'package':'C03','kind':'executable schemas and reference-fixture validation','result':'passed' if matched else 'failed','summary':{'schema_definitions':len(wire['$defs']),'openapi_operations':len(ops),'contract_cases':len(cases),'accepted_cases':sum(c['expected']=='OK' for c in cases),'negative_cases':sum(c['expected']!='OK' for c in cases),'matched_contract_cases':sum(x['matched'] for x in results),'state_graph_cases':len(edges),'canonical_vectors':len(golden),'http_example_shapes':len(http)},'schema_validation':'JSON Schema 2020-12 and OpenAPI 3.1 valid','fixture_results':results,'state_graph_results':edges,'canonical_results':golden,'http_examples':http,'tool_versions':{n:importlib.metadata.version(n) for n in ['jsonschema','openapi-spec-validator','rfc8785','cryptography']},'runtime_http_mtls_pg_tests':'unrun','production_handler_implementation':'not_started','note':'Reference checks validate example constraints/cryptographic signatures using synthetic public keys and declarative contexts. They do not prove actual enrollment consumption, commit, lease or source authorization.'}
report['input_sha256']={str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest() for path in root.rglob('*') if path.is_file() and '__pycache__' not in path.parts and path.suffix not in ('.pyc',) and path.name!='validation-report.json'}
output=Path(sys.argv[1]) if len(sys.argv)>1 else root/'validation-report.json'
output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(report['summary'],ensure_ascii=False))
if not matched:
 print(json.dumps([x for x in results+edges+golden if not x['matched']],ensure_ascii=False,indent=2));raise SystemExit(1)
print('Schemas/OpenAPI, fixtures, state graphs and canonical vectors passed; runtime service tests unrun.')
