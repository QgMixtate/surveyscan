#!/usr/bin/env python3
"""Stage a reviewable Linux/systemd filesystem; never install/start services on the running host."""
import argparse,hashlib,json,os,shutil
from pathlib import Path
from dev import ROOT

def stage(root,distribution,web):
 root=root.resolve()
 if root==Path('/') or root.exists() and any(root.iterdir()):raise RuntimeError('an empty staging root is required; live host install is not supported')
 binaries=['surveyscan-server','surveyscan-collector','surveyscan-agent','surveyscanctl']
 for name in binaries:
  path=distribution/name
  if not path.is_file() or path.is_symlink():raise RuntimeError('all four locally built binaries are required')
 if any(p.is_symlink() for p in web.rglob('*')) or any(p.is_symlink() for p in (distribution/'contracts').rglob('*')):raise RuntimeError('symlinked source artifacts are not allowed')
 if not (web/'index.html').is_file():raise RuntimeError('separately built Web UI required')
 root.mkdir(parents=True,mode=0o700,exist_ok=True)
 release=root/'opt/surveyscan/releases/development';(release/'bin').mkdir(parents=True)
 for name in binaries:shutil.copyfile(distribution/name,release/'bin'/name);os.chmod(release/'bin'/name,0o755)
 shutil.copytree(distribution/'contracts',release/'contracts')
 shutil.copytree(web,release/'web',symlinks=False)
 os.symlink('releases/development',root/'opt/surveyscan/current')
 units=root/'usr/lib/systemd/system';units.mkdir(parents=True)
 for source in (ROOT/'deploy/systemd').glob('*.service'):shutil.copyfile(source,units/source.name)
 sysusers=root/'usr/lib/sysusers.d';sysusers.mkdir(parents=True);shutil.copyfile(ROOT/'deploy/systemd/surveyscan.conf',sysusers/'surveyscan.conf')
 for component in ['server','collector','agent','bao']:
  (root/('etc/surveyscan-'+component)).mkdir(parents=True,mode=0o700)
  (root/('var/lib/surveyscan-'+component)).mkdir(parents=True,mode=0o700)
 # Configs/keys are deliberately operator-provided, not generated/copied from the build workspace.
 # Public program/unit paths must be traversable by service users. Private state is created/chowned by systemd.
 for directory in [root,*[p for p in root.rglob('*') if p.is_dir() and not p.is_symlink()]]:os.chmod(directory,0o755)
 for component in ['server','collector','agent','bao']:os.chmod(root/('var/lib/surveyscan-'+component),0o700)
 for public in [*units.glob('*.service'),sysusers/'surveyscan.conf']:os.chmod(public,0o644)
 checksums={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink()}
 manifest={'format':1,'scope':'development staging; unsigned, not a release','files':checksums,'requires':['Debian/Ubuntu Linux with systemd>=252','external PostgreSQL17 system service','OpenBao2.7.2 executable and operator-provided TLS/custody config','static Web edge configuration','private configs/keys supplied by operator'],'unrun':['real systemd boot/reboot','production installation','signed release verification','backup/restore'],'host_services_modified':False}
 (root/'stage-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 return {'staged':True,'files':len(checksums),'live_install_supported':False,'services_started':False,'scope':manifest['scope']}

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',required=True,type=Path);p.add_argument('--dist',type=Path,default=ROOT/'.dist');p.add_argument('--web',type=Path,default=ROOT/'web/dist');a=p.parse_args()
 print(json.dumps(stage(a.root,a.dist,a.web)))
if __name__=='__main__':
 try:main()
 except RuntimeError as e:raise SystemExit(str(e))
