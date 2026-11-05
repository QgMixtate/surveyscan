#!/usr/bin/env python3
"""Actual isolated QEMU TCG kernel/systemd reboot. No KVM/host cgroups/services required.

Requires local public surveyscan-c13-boot-tools:local built from deploy/bootstand/Dockerfile.
All runtime keys/root custody are test-only, supplied after image build and deleted with VM.
"""
import datetime
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import secrets
import release
from dev import ROOT, STATE, ENV

IMAGE = 'surveyscan-c13-boot-tools:local'
DOCKER = ['docker', '--host=unix:///var/run/docker.sock']


class VMFailure(RuntimeError):
    def __init__(self, record):
        super().__init__('actual VM boot/reboot failed; sanitized phase/line in report, raw serial private')
        self.record = record


def main():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    (STATE/'c13-boot-smoke.json').write_text(json.dumps({'status':'in_progress','scope':'actual QEMU VM'})+'\n')
    with tempfile.TemporaryDirectory(prefix='c13-vm-', dir=STATE) as temp:
        work = Path(temp)
        bootstrap = work / 'bootstrap'
        bootstrap.mkdir(mode=0o700)
        def save(name, raw):
            path = bootstrap / name
            path.write_bytes(raw)
            path.chmod(0o600)
            return path
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key = ed25519.Ed25519PrivateKey.generate()
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'C13 isolated boot stand CA')])
        ca = x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(ca_key,None)
        save('infra-ca.pem', ca.public_bytes(serialization.Encoding.PEM))
        for name in ('bao', 'edge'):
            key = ed25519.Ed25519PrivateKey.generate()
            certificate = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(ca_key,None)
            save(name+'.pem',certificate.public_bytes(serialization.Encoding.PEM))
            save(name+'.key',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        save('seed.json',json.dumps({'tenant':str(uuid.uuid4()),'site':str(uuid.uuid4()),'scope':str(uuid.uuid4()),'subject':str(uuid.uuid4()),'pg_password':secrets.token_urlsafe(30),'admin_password':secrets.token_urlsafe(30)}).encode())
        sign_key = ed25519.Ed25519PrivateKey.generate()
        signing = save('release.key',sign_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        public = save('release.pub',sign_key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        # Build fresh signed baseline from current locally compiled artifacts.
        version = json.loads(subprocess.check_output([str(ROOT/'.dist/surveyscan-server'),'version']))['version']
        bundle = work/'bundle'
        release.build(bundle,version,ROOT/'.dist',ROOT/'web/dist',Path(os.environ['GO']))
        release.sign(bundle,signing)
        staging = work/'staging'
        release.install(bundle,public,staging)
        # Candidate uses the same schema/code with a separately compiled visible release version.
        distribution = work/'candidate-dist'
        distribution.mkdir()
        shutil.copytree(ROOT/'.dist/contracts',distribution/'contracts')
        revision = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        for name in release.BINARIES:
            module='github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo.'
            result=subprocess.run([os.environ['GO'],'build','-mod=readonly','-trimpath','-p','2','-ldflags',f'-X {module}Version=0.0.1-c13 -X {module}Revision={revision} -X {module}Dirty=true','-o',str(distribution/name),'./cmd/'+name],cwd=ROOT,env=dict(os.environ,CGO_ENABLED='0'),capture_output=True,timeout=120)
            assert result.returncode==0,'VM candidate build failed'
        candidate=work/'candidate'
        release.build(candidate,'0.0.1-c13',distribution,ROOT/'web/dist',Path(os.environ['GO']))
        release.sign(candidate,signing)
        signing.unlink()  # Signing key is never supplied to guest/app, only the independent public anchor.
        out=work/'out';out.mkdir(mode=0o700)
        source='surveyscan-c13-export-'+uuid.uuid4().hex[:12]
        runner='surveyscan-c13-vm-'+uuid.uuid4().hex[:12]
        made=False
        try:
            subprocess.run(DOCKER+['create','--name',source,IMAGE],env=ENV,check=True,capture_output=True)
            made=True
            export=subprocess.Popen(DOCKER+['export',source],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            args=DOCKER+['run','--rm','--name',runner,'--network=none','-i','-e','TEST_UID='+str(os.getuid()),'-e','TEST_GID='+str(os.getgid())]
            for src,dst,readonly in [(staging,'/staging',True),(bootstrap,'/bootstrap',True),(ROOT/'deploy/bootstand','/tests',True),(ROOT/'scripts','/updater',True),(candidate,'/candidate',True),(out,'/out',False)]:
                args+=['--mount','type=bind,src='+str(src)+',dst='+dst+(',readonly' if readonly else '')]
            args += ['--entrypoint','python3',IMAGE,'/tests/prepare.py']
            with (STATE/'c13-vm-prepare.log').open('wb') as log:
                result=subprocess.run(args,env=ENV,stdin=export.stdout,stdout=log,stderr=subprocess.STDOUT,timeout=300)
            export.stdout.close()
            export.wait(timeout=10)
            assert result.returncode==0 and export.returncode==0,'VM filesystem preparation failed; inspect private log'
            with (STATE/'c13-vm-serial.log').open('wb') as log:
                result=subprocess.run(DOCKER+['run','--rm','--name',runner,'--network=none','--mount','type=bind,src='+str(out)+',dst=/vm','--entrypoint','qemu-system-x86_64',IMAGE,
                    '-accel','tcg,thread=multi','-machine','q35','-cpu','max','-smp','2','-m','2048','-nographic','-nic','none',
                    '-device','virtio-rng-pci','-drive','file=/vm/guest.raw,format=raw,if=virtio','-kernel','/vm/kernel','-initrd','/vm/initrd',
                    '-append','root=/dev/vda rw console=ttyS0 init=/lib/systemd/systemd systemd.log_level=warning'],env=ENV,stdout=log,stderr=subprocess.STDOUT,timeout=900)
            serial=(STATE/'c13-vm-serial.log').read_text(errors='replace')
            records=[json.loads(line.split('SURVEYSCAN_BOOT_RESULT ',1)[1].strip()) for line in serial.splitlines() if 'SURVEYSCAN_BOOT_RESULT ' in line]
            if result.returncode != 0 or not records or records[-1]['status'] != 'passed':
                guest = records[-1] if records else {}
                # No raw exception text, argv, journal, credentials or unseal material.
                diagnostic = {'package': 'C13', 'status': 'failed', 'qemu_exit': result.returncode,
                              'guest_result_present': bool(records)}
                for key in ('phase', 'error_type', 'failed_guest_line', 'guest_call_lines', 'completed_checks', 'bao_operation', 'bao_http_status',
                            'command_program', 'command_exit', 'command_elapsed_seconds', 'cli_error'):
                    if key in guest:
                        diagnostic[key] = guest[key]
                raise VMFailure(diagnostic)
            (STATE/'c13-boot-smoke.json').write_text(json.dumps(records[-1],indent=2)+'\n')
            print(json.dumps(records[-1]))
        finally:
            for name in (runner,source):
                subprocess.run(DOCKER+['rm','--force','-v',name],env=ENV,capture_output=True,timeout=20)


if __name__=='__main__':
    def interrupted(*_):raise InterruptedError('VM supervisor interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    try:main()
    except Exception as error:
        report = error.record if isinstance(error, VMFailure) else {'status':'failed','error_type':type(error).__name__}
        (STATE/'c13-boot-smoke.json').write_text(json.dumps(report)+'\n')
        print(json.dumps(report))
        raise
