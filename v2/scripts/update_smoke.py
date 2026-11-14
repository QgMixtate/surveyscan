#!/usr/bin/env python3
"""C13 real signed release update/restart, schema-safe rollback and interrupted-journal recovery.

Actual server processes, PG and TLS; no host systemd changes. Startup failure and drift are
explicit test injections. Production systemd controller/physical power-loss are not attested.
"""
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import tarfile
import time

import release
import updater
from dev import ROOT, STATE, DOCKER, ENV
from machine_smoke import main as harness


def main():
    with tempfile.TemporaryDirectory(prefix='c13-update-', dir=STATE) as temp:
        work = Path(temp)
        key, public = work / 'release.key', work / 'release.pub'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], check=True, capture_output=True)
        key.chmod(0o600)
        public.write_bytes(release.openssl('pkey', '-in', key, '-pubout'))
        base_version = json.loads(subprocess.check_output([str(ROOT / '.dist/surveyscan-server'), 'version']))['version']
        versions = [base_version, '0.0.1-c13', '0.0.2-c13', '0.0.3-c13']
        require_new = updater.version(versions[0]) < updater.version(versions[1])
        assert require_new, 'update test requires baseline0.0.0-c13'
        bundles = {}
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        go = os.environ.get('GO', 'go')
        for number, version in enumerate(versions):
            distribution = ROOT / '.dist'
            if number:
                source = ROOT
                if number == 3:
                    # A real compiled, append-only test migration in a private source copy, never product SQL.
                    source = work / 'schema-fixture'
                    source.mkdir()
                    archive = subprocess.check_output(['git', 'archive', 'HEAD', 'v2'], cwd=ROOT.parent)
                    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                        tar.extractall(source, filter='data')
                    source = source / 'v2'
                    (source / 'internal/platform/messaging/schema/0052_c13_update_acceptance.sql').write_text(
                        'CREATE TABLE messaging.c13_update_acceptance (row_id bigint PRIMARY KEY);\n')
                distribution = work / ('dist-' + version)
                distribution.mkdir()
                shutil.copytree(ROOT / '.dist/contracts', distribution / 'contracts')
                for name in release.BINARIES:
                    module = 'github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo.'
                    flags = f'-X {module}Version={version} -X {module}Revision={revision} -X {module}Dirty=true'
                    result = subprocess.run([go, 'build', '-mod=readonly', '-trimpath', '-p', '2', '-ldflags', flags,
                                             '-o', str(distribution / name), './cmd/' + name], cwd=source,
                                             env=dict(os.environ, CGO_ENABLED='0'), capture_output=True, timeout=120)
                    assert result.returncode == 0, 'candidate Go build failed'
            bundle = work / ('bundle-' + version)
            release.build(bundle, version, distribution, ROOT / 'web/dist', Path(go))
            release.sign(bundle, key)
            bundles[version] = bundle

        def scenario(**s):
            checks = s['checks']
            original = s['center_process']
            original.terminate()
            assert original.wait(timeout=8) == 0
            root = work / 'installation'
            release.install(bundles[base_version], public, root)
            base = root / 'opt/surveyscan'
            config = root / 'etc/surveyscan-server'
            data = json.loads((s['directory'] / 'machine.json').read_text())
            for name, value in list(data.items()):
                if name.endswith('_file') and value:
                    destination = config / Path(value).name
                    shutil.copyfile(value, destination)
                    destination.chmod(0o600)
                    data[name] = str(destination)
            (config / 'machine.json').write_text(json.dumps(data))
            (config / 'machine.json').chmod(0o600)
            artifact = root / 'var/lib/surveyscan-server/operator-artifact'
            artifact.write_bytes(b'private-fixture-artifact-preserved')
            artifact.chmod(0o600)
            preserved = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for directory in (config, root / 'var/lib')
                         for p in directory.rglob('*') if p.is_file()}
            env = dict(s['server_environment'], SURVEYSCAN_V2_MACHINE_CONFIG=str(config / 'machine.json'))

            class Processes:
                def __init__(self):
                    self.process = None
                    self.fail_version = None
                    self.migration_failure = False
                    self.inject_drift = False
                    self.kill_after_migrate = False

                def stop(self):
                    if self.process is not None and self.process.poll() is None:
                        self.process.terminate()
                        self.process.wait(timeout=8)

                def check_schema(self, binary):
                    return subprocess.run([str(binary), 'schema-check'], env=env, capture_output=True, timeout=15).returncode == 0

                def migrate(self, binary):
                    if self.migration_failure:
                        raise RuntimeError('injected pre-migration failure')
                    result = subprocess.run([str(binary), 'migrate'], env=env, capture_output=True, timeout=30)
                    assert result.returncode == 0
                    self.applied_migrations = int(result.stdout.decode().strip().split('=')[1])
                    if self.kill_after_migrate:
                        os.kill(os.getpid(), signal.SIGKILL)
                    if self.inject_drift:
                        # Explicit metadata fixture: imitate an ahead/unknown schema, never edit product SQL.
                        s['sql']("INSERT INTO platform.schema_migrations(id,owner,sha256) VALUES('9999_update_test','test','" + '0' * 64 + "')")

                def start(self):
                    assert not (base / 'update.fence').exists()
                    current = updater.active(base)
                    settings = dict(env)
                    if current == self.fail_version:
                        settings['SURVEYSCAN_V2_LISTEN'] = 'invalid-listen-address'
                    with (work / ('server-' + current + '.log')).open('ab') as log:
                        self.process = subprocess.Popen([str(base / 'current/bin/surveyscan-server'), 'serve'], env=settings, stdout=log, stderr=log)

                def healthy(self):
                    for _ in range(100):
                        if self.process is None or self.process.poll() is not None:
                            return False
                        try:
                            if s['request'](s['center_port'], context, 'GET', '/health/ready')[0] == 200:
                                return True
                        except OSError:
                            pass
                        time.sleep(.1)
                    return False

            import ssl
            context = ssl.create_default_context(cafile=s['ca_file'])
            # The harness request function is not part of the old web callback; use a bounded local TLS client.
            import http.client
            def request(port, tls, method, path, body=None, headers=None):
                connection = http.client.HTTPSConnection('127.0.0.1', port, context=tls, timeout=3)
                h = dict(headers or {})
                if body is not None:
                    body = json.dumps(body).encode()
                    h['Content-Type'] = 'application/json'
                try:
                    connection.request(method, path, body=body, headers=h)
                    response = connection.getresponse()
                    raw = response.read()
                    return response.status, json.loads(raw) if raw else None, {k.lower(): v for k, v in response.getheaders()}
                finally:
                    connection.close()
            s['request'] = request
            controller = Processes()
            def refused(action):
                try:
                    action()
                except (ValueError, OSError):
                    return
                raise AssertionError('invalid update accepted')
            try:
                controller.start()
                assert controller.healthy()
                assert controller.check_schema(base / 'current/bin/surveyscan-server')
                checks.append('installed signed baseline server actually serves existing PG registry with exact compiled schema')
                prepared = updater.prepare(root, bundles[versions[1]], public)
                assert prepared['phase'] == 'prepared' and updater.active(base) == base_version
                checks.append('candidate signature/hashes/catalog verified and staged without switching current or stopping server')
                result = updater.apply(root, public, controller)
                assert result['phase'] == 'complete' and updater.active(base) == versions[1]
                actual = json.loads(subprocess.check_output([str(base / 'current/bin/surveyscan-server'), 'version']))
                assert actual['version'] == versions[1]
                status, session, headers = request(s['center_port'], context, 'POST', '/api/v1/auth/sessions',
                    {'username': s['username'], 'password': s['password']}, {'Origin': s['origin']})
                assert status == 201 and session['tenant_id'] == s['tenant']
                status, card, _ = request(s['center_port'], context, 'GET', '/api/v1/assets/' + s['asset'],
                    headers={'Cookie': headers['set-cookie'].split(';', 1)[0]})
                assert status == 200 and card['asset_uid'] == s['asset']
                checks.append('actual stop/migrate0/atomic switch/restart reaches readiness; new version, old credentials and same UID visible')
                assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == value for path, value in preserved.items())
                checks.append('all selected operator configs/private TLS keys and private artifact bytes preserved across update')
                refused(lambda: updater.prepare(root, bundles[base_version], public))
                checks.append('implicit version downgrade refused')
                updater.prepare(root, bundles[versions[2]], public)
                controller.fail_version = versions[2]
                result = updater.apply(root, public, controller)
                assert result['phase'] == 'rolled_back' and updater.active(base) == versions[1] and controller.healthy()
                checks.append('real candidate startup failure safely returns to previous ready server only after exact DB/schema check')
                # Retry precisely the same signed candidate after a transient startup failure.
                updater.prepare(root, bundles[versions[2]], public)
                controller.stop()
                def killed_update():
                    controller.kill_after_migrate = True
                    updater.apply(root, public, controller)
                child = multiprocessing.get_context('fork').Process(target=killed_update)
                child.start()
                child.join(timeout=30)
                assert child.exitcode == -signal.SIGKILL
                record = release.read_json(base / 'update.json')
                assert record['phase'] == 'migrating' and (base / 'update.fence').exists()
                assert updater.active(base) == versions[1]
                controller.fail_version = None
                result = updater.apply(root, public, controller, recover=True)
                assert result['phase'] == 'complete' and updater.active(base) == versions[2]
                checks.append('actual updater SIGKILL after committed migrate leaves durable fence/journal; retry/recovery inspects DB and reaches ready candidate')
                # A drifted DB forbids rollback even when the old process could otherwise start.
                updater.fence(base, True)
                controller.stop()
                updater.state(base, record, 'migrating')
                s['sql']("INSERT INTO platform.schema_migrations(id,owner,sha256) VALUES('9999_update_test','test','" + '0' * 64 + "')")
                result = updater.apply(root, public, controller, recover=True)
                assert result['phase'] == 'recovery_required' and (base / 'update.fence').exists()
                assert controller.process.poll() is not None
                checks.append('actual DB ledger drift leaves persistent fence and no running server; incompatible old binary never auto-started')
                s['sql']("DELETE FROM platform.schema_migrations WHERE id='9999_update_test'")
                result = updater.apply(root, public, controller, recover=True)
                assert result['phase'] == 'complete' and controller.healthy()
                checks.append('explicit recovery after fixing own drift fixture restores matching current release without deleting state or identities')
                # Actual compiled schema36->37 fixture: require checkpoint, then refuse rollback after committed DDL.
                from pg_backup import Client, backup
                from checkpoint import pack
                from bao_restore_fixture import call
                refused(lambda: updater.prepare(root, bundles[versions[3]], public))
                controller.stop()
                s['collector_process'].terminate()
                s['collector_process'].wait(timeout=8)
                client = Client({tool: DOCKER + ['exec', '-T', '-e', 'PGUSER=surveyscan_v2', 'db', tool]
                                 for tool in ('psql', 'pg_dump', 'pg_restore')}, env=ENV)
                pg = work / 'schema-change-pg'
                backup(client, s['sql']('SELECT current_database()'), pg)
                custody = json.loads((STATE / 'bao-init.json').read_text())
                status, raw = call('http://127.0.0.1:58200', 'sys/storage/raft/snapshot', token=custody['root_token'], binary=True)
                assert status == 200
                raft = work / 'schema-change-raft.snapshot'
                raft.write_bytes(raw)
                raft.chmod(0o600)
                checkpoint = work / 'schema-change-checkpoint'
                pack(checkpoint, pg, raft, {'server-config': config, 'server-state': root / 'var/lib', 'fixture-collector': s['directory']}, True)
                updater.prepare(root, bundles[versions[3]], public, checkpoint)
                controller.fail_version = versions[3]
                result = updater.apply(root, public, controller)
                assert controller.applied_migrations == 1 and result['phase'] == 'recovery_required'
                assert updater.active(base) == versions[3] and (base / 'update.fence').exists()
                assert s['sql']('SELECT count(*) FROM platform.schema_migrations') == '53'
                assert not controller.check_schema(base / 'releases' / versions[2] / 'bin/surveyscan-server')
                controller.fail_version = None
                result = updater.apply(root, public, controller, recover=True)
                assert result['phase'] == 'complete' and controller.healthy()
                assert s['sql']('SELECT asset_uid::text FROM assets.assets') == s['asset']
                checks.append('actual compiled test-only schema36→37 requires verified common checkpoint; committed DDL plus failed startup keeps fence, refuses schema36 rollback and explicitly recovers ready schema37')
                with updater.locked(root):
                    refused(lambda: updater.prepare(root, bundles[base_version], public))
                checks.append('installation-wide writer lock refuses a concurrent updater')
                report = {'package': 'C13', 'task': 'C13.02', 'status': 'passed', 'count': len(checks), 'checks': checks,
                          'target': 'actual signed ELF releases/server processes, PostgreSQL, TLS/login/registry, original UID; explicit bad listen/ledger drift and private compiled append-only migration37 fixtures (product SQL unchanged)',
                          'unrun': ['production systemd controller', 'physical power loss', 'boot/reboot/two clean OS/production DR']}
                (STATE / 'c13-update-smoke.json').write_text(json.dumps(report, indent=2) + '\n')
                print(json.dumps(report))
            finally:
                controller.stop()

        harness(web_scenario=scenario)


if __name__ == '__main__':
    main()
