"""Inside owned tooling container only: create an unmounted private ext4 guest image."""
import json
import os
from pathlib import Path
import shutil
import subprocess

root = Path('/guest')
root.mkdir()
subprocess.run(['tar', '-xf', '-', '-C', str(root), '--exclude=dev/*', '--exclude=proc/*', '--exclude=sys/*', '--exclude=run/*'], check=True)
(root / '.dockerenv').unlink(missing_ok=True)
shutil.copytree('/staging', root, dirs_exist_ok=True, symlinks=True)
shutil.copytree('/bootstrap', root / 'root/boot-seed', dirs_exist_ok=True)
for path in (root / 'root/boot-seed').rglob('*'):
    path.chmod(0o700 if path.is_dir() else 0o600)
(root / 'root/boot-seed').chmod(0o700)
shutil.copytree('/tests', root / 'usr/local/lib/surveyscan-boot', dirs_exist_ok=True)
shutil.copyfile('/updater/updater.py', root / 'usr/local/lib/surveyscan-boot/updater.py')
shutil.copyfile('/updater/release.py', root / 'usr/local/lib/surveyscan-boot/release.py')
shutil.copyfile('/updater/checkpoint.py', root / 'usr/local/lib/surveyscan-boot/checkpoint.py')
shutil.copytree('/candidate', root / 'root/candidate')
(root / 'etc/machine-id').write_text('')
(root / 'etc/hostname').write_text('surveyscan-boot-stand\n')
(root / 'etc/fstab').write_text('/dev/vda / ext4 defaults 0 1\n')
(root / 'etc/systemd/system/serial-getty@ttyS0.service').symlink_to('/dev/null')
subprocess.run(['systemd-sysusers', '--root=' + str(root)], check=True)
seed = json.loads((root / 'root/boot-seed/seed.json').read_text())
pg = root / 'var/lib/postgresql/data'
pg.mkdir(parents=True, exist_ok=True)
pg.chmod(0o700)
os.chown(pg, 999, 999)
password = Path('/tmp/c13-initdb-password')
password.write_text(seed['pg_password'] + '\n')
password.chmod(0o600)
os.chown(password, 999, 999)
subprocess.run(['runuser', '-u', 'postgres', '--', '/usr/lib/postgresql/17/bin/initdb',
                '-D', str(pg), '--username=surveyscan_v2', '--pwfile=' + str(password),
                '--auth-local=trust', '--auth-host=scram-sha-256', '--locale=C.UTF-8'],
               check=True, stdout=subprocess.DEVNULL)
password.unlink()
unit = root / 'etc/systemd/system/postgresql.service'
unit.write_text('[Unit]\nDescription=Actual PostgreSQL17 for isolated boot stand\nAfter=local-fs.target\n[Service]\nType=notify\nNotifyAccess=main\nUser=postgres\nGroup=postgres\nRuntimeDirectory=postgresql\nExecStart=/usr/lib/postgresql/17/bin/postgres -D /var/lib/postgresql/data -k /run/postgresql -h 127.0.0.1\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
bao = root / 'etc/surveyscan-bao'
for source, name, mode in [('bao.pem', 'server.pem', 0o644), ('bao.key', 'server.key', 0o600), ('infra-ca.pem', 'ca.pem', 0o644)]:
    shutil.copyfile('/bootstrap/' + source, bao / name)
    (bao / name).chmod(mode)
(bao / 'bao.hcl').write_text('disable_mlock = true\nui = false\napi_addr = "https://127.0.0.1:8200"\ncluster_addr = "https://127.0.0.1:8201"\nstorage "raft" {\n path="/var/lib/surveyscan-bao"\n node_id="c13-boot-stand"\n}\nlistener "tcp" {\n address="127.0.0.1:8200"\n tls_cert_file="/etc/surveyscan-bao/server.pem"\n tls_key_file="/run/credentials/surveyscan-bao.service/listener_key"\n}\n')
shutil.copyfile('/bootstrap/infra-ca.pem', root / 'usr/local/share/ca-certificates/surveyscan-boot.crt')
subprocess.run(['chroot', str(root), 'update-ca-certificates'], check=True, stdout=subprocess.DEVNULL)
driver = root / 'etc/systemd/system/surveyscan-boot-proof.service'
driver.write_text('[Unit]\nDescription=Isolated VM test operator (not product auto-unseal)\nWants=postgresql.service surveyscan-bao.service\nAfter=postgresql.service surveyscan-bao.service surveyscan-server.service surveyscan-collector.service surveyscan-agent.service\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /usr/local/lib/surveyscan-boot/guest.py\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\nTimeoutStartSec=600\n[Install]\nWantedBy=multi-user.target\n')
for name in ('postgresql.service', 'surveyscan-bao.service', 'surveyscan-boot-proof.service'):
    subprocess.run(['systemctl', '--root=' + str(root), 'enable', name], check=True, stdout=subprocess.DEVNULL)
# Nginx starts only after its explicit TLS/static/API configuration is provisioned by the test operator.
subprocess.run(['systemctl', '--root=' + str(root), 'disable', 'nginx.service'], check=True, stdout=subprocess.DEVNULL)
image = Path('/out/guest.raw')
with image.open('wb') as stream:
    stream.truncate(3 * 1024 * 1024 * 1024)
subprocess.run(['mke2fs', '-q', '-t', 'ext4', '-F', '-d', str(root), str(image)], check=True)
for pattern, destination in [('vmlinuz-*', 'kernel'), ('initrd.img-*', 'initrd')]:
    source = sorted((root / 'boot').glob(pattern))[-1]
    shutil.copyfile(source, '/out/' + destination)
for path in Path('/out').iterdir():
    path.chmod(0o600)
    os.chown(path, int(os.environ['TEST_UID']), int(os.environ['TEST_GID']))
