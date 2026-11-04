#!/usr/bin/env python3
"""Offline root-mode systemd verifier in disposable networkless container; no host service changes."""
import json,os,re,shutil,subprocess,tempfile
from pathlib import Path
from dev import ROOT,STATE,ENV
from stage_install import stage
DOCKER=['docker','--host=unix:///var/run/docker.sock']
def main():
 STATE.mkdir(mode=0o700,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='c13-units-',dir=STATE) as temp:
  work=Path(temp);bundle=work/'checker';bundle.mkdir();filesystem=bundle/'fs';filesystem.mkdir()
  binary=Path('/usr/bin/systemd-analyze');dependencies=subprocess.check_output(['ldd',str(binary)],text=True)
  paths={str(binary),*re.findall(r'(/[^\s()]+)',dependencies)}
  for path in paths:
   src=Path(path)
   if not src.is_file():continue
   target=filesystem/str(src).lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,target);os.chmod(target,0o755)
  # Genuine systemd targets; no service executables are started. PostgreSQL/Bao are external prerequisites.
  targets=filesystem/'usr/lib/systemd/system';targets.mkdir(parents=True,exist_ok=True)
  for name in ['basic.target','sysinit.target','sockets.target','timers.target','paths.target','network.target','network-online.target','local-fs.target','multi-user.target','shutdown.target']:
   src=Path('/usr/lib/systemd/system')/name
   if src.is_file():shutil.copyfile(src,targets/name)
  (bundle/'Dockerfile').write_text('FROM scratch\nCOPY fs/ /\nENTRYPOINT ["/usr/bin/systemd-analyze"]\n')
  root=work/'target';manifest=stage(root,ROOT/'.dist',ROOT/'web/dist')
  # Verifier's target-root search paths need distribution targets too, all copied from the public host units.
  for src in targets.glob('*.target'):shutil.copyfile(src,root/'usr/lib/systemd/system'/src.name)
  subprocess.run(DOCKER+['build','--network=none','--tag','surveyscan-c13-unit-checker:local',str(bundle)],env=ENV,check=True,stdout=subprocess.DEVNULL)
  command=DOCKER+['run','--rm','--network=none','--read-only','--cap-drop=ALL','--tmpfs','/run:rw,noexec,nosuid,size=8m','--tmpfs','/tmp:rw,noexec,nosuid,size=8m','--mount','type=bind,src='+str(root)+',dst=/target,readonly','surveyscan-c13-unit-checker:local','--root=/target','--generators=no','--man=no','--recursive-errors=no','verify','surveyscan-agent.service','surveyscan-collector.service','surveyscan-server.service','surveyscan-migrate.service']
  result=subprocess.run(command,env=ENV,capture_output=True,text=True)
  print(result.stdout+result.stderr)
  report={'package':'C13','task':'C13.01','stage':manifest,'checked_units':['surveyscan-agent.service','surveyscan-collector.service','surveyscan-server.service','surveyscan-migrate.service'],'verifier_exit':result.returncode,'scope':'real system-mode systemd-analyze parser in networkless disposable container, not a boot/start test','unrun':['realboot/reboot','PG/Bao dependency start','credential provisioning','signed release','backuprestore']};(STATE/'c13-unit-check.json').write_text(json.dumps(report,indent=2)+'\n')
  print(json.dumps(report));return result.returncode
if __name__=='__main__':raise SystemExit(main())
