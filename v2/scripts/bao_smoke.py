#!/usr/bin/env python3
"""Scoped real OpenBao proof; all tokens/canaries remain in temporary private files."""
import json,os,subprocess,tempfile,urllib.error
from pathlib import Path
from dev import ROOT,STATE,initialize
from bao_fixture import fixture

def main():
 initialize();checks=[]
 with tempfile.TemporaryDirectory(prefix='c11-scoped-',dir=STATE) as temp:
  directory=Path(temp)
  with fixture(directory) as f:
   env=dict(os.environ,SURVEYSCAN_TEST_BAO_CONFIG=f['config'],SURVEYSCAN_TEST_BAO_SHORT_CONFIG=f['short_config'],SURVEYSCAN_TEST_BAO_REVOKED_TOKEN=f['revoked_token_file'],SURVEYSCAN_TEST_BAO_ROOT_CONFIG=f['root_config'])
   subprocess.run([os.environ.get('GO','go'),'test','-mod=readonly','-tags=bao','-count=1','-v','./internal/platform/bao'],cwd=ROOT,env=env,check=True);checks.append('real scoped token/KV ref/Transit signature and root-token rejection pass Go live test')
   for path in [f['transit']+'/keys/forbidden',f['transit']+'/export/signing-key/ca',f['kv']+'/data/other', 'sys/mounts']:
    try:f['call']('GET',path,credential=f['token']);raise AssertionError('scoped token accessed forbidden path')
    except urllib.error.HTTPError as e:assert e.code==403
   checks.append('actual OpenBao policy denies other keys, private export, unrelated KV and system mounts')
   output=directory/'issuer';p=subprocess.run([str(ROOT/'.dist/surveyscan-server'),'bootstrap-issuer','--config',f['config'],'--output-directory',str(output)],cwd=ROOT,capture_output=True,text=True,timeout=30);assert p.returncode==0,'remote CA bootstrap failed';checks.append('scoped Transit CA signs public root and loopback server certificate; no local CA/receipt private key')
   assert {p.name for p in output.iterdir()}=={'ca.pem','server.pem','server.key'}
   assert f['audit_check']();checks.append('actual OpenBao audit contains no raw root token, application token or KV canary')
   report={'package':'C11','status':'passed','scope':'OpenBao scoped bootstrap/key ops/secret refs; full C11 renewal not yet accepted','count':len(checks),'checks':checks,'target':'real persistent OpenBao2.7.2 Raft; temporary unique mounts/policy/periodic scoped token; Go live client; root only operator provisioning','private_material':'test token/KV canary/mounts/policy/private files removed; no secret in report','unrun':['full machine lifecycle/renewal/clone','production HTTPS/bootstrap custody','raft backup/restore rehearsal']}
   (STATE/'bao-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
