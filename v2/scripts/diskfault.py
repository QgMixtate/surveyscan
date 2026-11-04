#!/usr/bin/env python3
"""Real ENOSPC in a disposable 64KiB Docker tmpfs; no host volume modifications."""
import json,os,subprocess
from dev import ROOT,STATE,ENV,initialize

def main():
 initialize();(ROOT/'.dist').mkdir(exist_ok=True)
 environment=dict(ENV,CGO_ENABLED='0');binary=ROOT/'.dist/spool-diskfault.test'
 subprocess.run([os.environ.get('GO','go'),'test','-mod=readonly','-c','-tags=diskfault','-o',str(binary),'./internal/platform/diskspool'],cwd=ROOT,env=environment,check=True)
 command=['docker','--host=unix:///var/run/docker.sock','run','--rm','--network','none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--user',f'{os.getuid()}:{os.getgid()}','--tmpfs',f'/spool:rw,size=65536,mode=0700,uid={os.getuid()},gid={os.getgid()}','--mount',f'type=bind,source={binary},target=/spool-test,readonly','-e','SURVEYSCAN_DISKFAULT_DIRECTORY=/spool','--entrypoint','/spool-test','nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03','-test.run','^TestRealDiskFullPreservesCommittedFile$','-test.v']
 with (STATE/'diskfault-test.log').open('w') as log:subprocess.run(command,cwd=ROOT,env=environment,check=True,stdout=log,stderr=subprocess.STDOUT)
 report={'package':'C10','status':'passed','count':1,'checks':['real ENOSPC leaves committed file unchanged and removes incomplete temporary file'],'target':'CGO=0 Go test binary in isolated 64KiB tmpfs; network none; rootfs read-only; no caps; existing dev volumes untouched','unrun':['physical power loss','host filesystem hardware faults']};(STATE/'diskfault-smoke.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
