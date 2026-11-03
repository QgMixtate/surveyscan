#!/usr/bin/env python3
"""C04 live HTTP/dependency/restart smoke checks; local named volumes are retained."""
import json,time,urllib.request,urllib.error,uuid
from pathlib import Path
from dev import compose,unseal,ROOT

def status(port,path):
 try:
  with urllib.request.urlopen(f'http://127.0.0.1:{port}{path}',timeout=4) as response:return response.status,response.read()
 except urllib.error.HTTPError as e:return e.code,e.read()
 except OSError:return 0,b''
def wait(port,path,want):
 for _ in range(60):
  code,body=status(port,path)
  if code==want:return body
  time.sleep(.5)
 raise RuntimeError(f'{port}{path}: expected {want}, got {code}')
def main():
 checks=[]
 tenant=str(uuid.uuid4())
 def sql(query):return compose('exec','-T','db','psql','-U','surveyscan_v2','-d','surveyscan_v2','-v','ON_ERROR_STOP=1','-Atc',query,capture=True).strip()
 sql(f"INSERT INTO access.tenants(tenant_id,name,status) VALUES ('{tenant}','C04 restart smoke','active')")
 for port in (58080,58081):
  wait(port,'/health/live',200);wait(port,'/health/ready',200);wait(port,'/api/v1/assets',404);checks.append(f'health and absent business handlers on {port}')
 doc=json.loads(wait(58081,'/contracts/openapi.json',200));assert doc['openapi']=='3.1.0';checks.append('separate proxy serves OpenAPI')
 compose('stop','bao');wait(58080,'/health/ready',503);wait(58080,'/health/live',200)
 compose('start','bao');unseal();wait(58080,'/health/ready',200);checks.append('Bao stop/restart/unseal readiness recovery')
 compose('stop','db');wait(58080,'/health/ready',503);wait(58080,'/health/live',200)
 compose('start','db');wait(58080,'/health/ready',200);assert sql(f"SELECT name FROM access.tenants WHERE tenant_id='{tenant}'")=="C04 restart smoke";sql(f"DELETE FROM access.tenants WHERE tenant_id='{tenant}'");checks.append('PostgreSQL stop/restart preserves committed row and migrations')
 compose('restart','backend');wait(58081,'/health/ready',200);checks.append('backend restart through proxy')
 report={'status':'passed','checks':checks,'count':len(checks),'business_handlers':'unimplemented C05 onward','production':'unrun'}
 (ROOT/'.local/smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,ensure_ascii=False))
if __name__=='__main__':main()
