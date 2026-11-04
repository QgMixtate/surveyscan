#!/usr/bin/env python3
"""C13 common stopped-writer checkpoint: PG + Raft + actual agent/collector files, relocated replay."""
import base64
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import time
import uuid

import rfc8785
from bao_fixture import fixture
from bao_restore_fixture import call, restored_node
from checkpoint import pack, extract, verify, files
from dev import ROOT, STATE, DOCKER, ENV, initialize
from machine_smoke import main as harness
from pg_backup import Client, backup, restore


def until(predicate, message, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.15)
    raise AssertionError(message)


def main():
    initialize()
    with tempfile.TemporaryDirectory(prefix='c13-common-', dir=STATE) as temp:
        workspace = Path(temp)
        with fixture(workspace) as f:
            issuer = workspace / 'issuer'
            result = subprocess.run([str(ROOT / '.dist/surveyscan-server'), 'bootstrap-issuer',
                '--config', f['config'], '--output-directory', str(issuer)], capture_output=True, timeout=30)
            assert result.returncode == 0, 'scoped bootstrap failed'

            def scenario(**s):
                checks = s['checks']
                sql, save, request = s['sql'], s['save'], s['request']
                agent = str(ROOT / '.dist/surveyscan-agent')
                state = s['directory'] / 'agent-state'
                cfg = {'tenant_id': s['tenant'], 'site_id': s['site'], 'network_scope_id': s['scope'],
                       'collector_url': f"https://127.0.0.1:{s['collector_port']}",
                       'collector_source_id': s['collector_source'], 'ca_certificate_file': s['ca_file'],
                       'state_directory': str(state), 'inventory_seconds': 60, 'heartbeat_seconds': 30,
                       'jitter_percent': 0, 'spool_limit_bytes': 1048576}
                config = save('checkpoint-agent.json', json.dumps(cfg))
                def a(*args):
                    result = subprocess.run([agent, *args, '--config', config], capture_output=True, timeout=30)
                    assert result.returncode == 0, 'agent console failed'
                    return result.stdout
                prep = json.loads(a('prepare'))
                headers = {'Origin': s['origin'], 'Cookie': s['cookie'], 'X-CSRF-Token': s['session']['csrf_token']}
                body = {'tenant_id': s['tenant'], 'source_id': prep['source_id'], 'source_kind': 'agent',
                        'site_id': s['site'], 'collector_id': s['collector_id'], 'ttl_seconds': 900,
                        'csr_sha256': prep['csr_sha256'], 'signing_public_key': prep['signing_public_key']}
                status, grant, _ = request(s['tls_port'], s['plain'], 'POST', '/api/v1/enrollments', body, headers)
                assert status == 201
                permission = save('checkpoint-grant.json', json.dumps(grant))
                a('enroll', '--grant-file', permission)
                running = s['start']('checkpoint-agent-first', [agent, 'run', '--config', config])
                until(lambda: sql('SELECT count(*) FROM inventory.observations') == '1', 'first inventory missing')
                spool = state / 'spool'
                relay_spool = s['directory'] / 'spool'
                until(lambda: not list(spool.glob('*.pending')) and not list(relay_spool.glob('*.pending')), 'first ACK missing')
                uid = sql('SELECT asset_uid::text FROM assets.assets')
                running.terminate()
                assert running.wait(timeout=8) == 0
                center = s['center_process']
                center.terminate()
                assert center.wait(timeout=8) == 0
                offline = s['start']('checkpoint-agent-pending', [agent, 'run', '--config', config])
                until(lambda: list(spool.glob('*.pending')) and list(relay_spool.glob('*.pending')), 'both pending queues missing')
                offline.terminate()
                assert offline.wait(timeout=8) == 0
                s['collector_process'].terminate()
                assert s['collector_process'].wait(timeout=8) == 0
                pending = {p.name: p.read_bytes() for p in spool.glob('*.pending')}
                relay_pending = {p.name: p.read_bytes() for p in relay_spool.glob('*.pending')}
                assert len(pending) == len(relay_pending) == 1
                checks.append('actual Bao-issued continuous agent commits first inventory and leaves second durable on both hops; all application writers stopped')

                client = Client({tool: DOCKER + ['exec', '-T', '-e', 'PGUSER=surveyscan_v2', 'db', tool]
                                 for tool in ('psql', 'pg_dump', 'pg_restore')}, env=ENV)
                database = sql('SELECT current_database()')
                target_db = 'ssv2checkpoint_' + uuid.uuid4().hex
                backup_dir = workspace / 'pg-backup'
                backup(client, database, backup_dir)
                custody = json.loads((STATE / 'bao-init.json').read_text())
                status, snapshot = call('http://127.0.0.1:58200', 'sys/storage/raft/snapshot', token=custody['root_token'], binary=True)
                assert status == 200
                raft = workspace / 'raft.snapshot'
                raft.write_bytes(snapshot)
                raft.chmod(0o600)
                # Explicit allowlist: no fixture root/unseal material or negative-test tokens in app backup.
                app = workspace / 'app'
                app.mkdir(mode=0o700)
                for source in (Path(f['config']), Path(f['profile']['token_file'])):
                    shutil.copyfile(source, app / source.name)
                    (app / source.name).chmod(0o600)
                checkpoint = workspace / 'checkpoint'
                pack(checkpoint, backup_dir, raft, {'host': s['directory'], 'issuer': issuer, 'bao-app': app}, True)
                manifest = verify(checkpoint)
                assert not any('root-negative' in p or 'bao-init' in p for p in manifest['files'])
                checks.append('one private checkpoint contains stopped-agent/collector identity/counters/queues, server TLS/config, PG and Raft; operator recovery custody excluded')
                restored = workspace / 'extracted'
                extract(checkpoint, restored)
                assert files(restored / 'payload') == files(checkpoint / 'payload')
                # Prove corruption is rejected before exposing a target, without changing a real archive.
                probe = checkpoint / 'payload/unlisted'
                probe.write_bytes(b'bad')
                probe.chmod(0o600)
                try:
                    extract(checkpoint, workspace / 'bad-target')
                except ValueError:
                    pass
                else:
                    raise AssertionError('corrupt checkpoint accepted')
                probe.unlink()
                assert not (workspace / 'bad-target').exists()
                checks.append('extraction preserves every selected byte and refuses unlisted corruption before target publication')
                host = restored / 'payload/state/host'
                assert all((host / 'agent-state/spool' / name).read_bytes() == data for name, data in pending.items())
                assert all((host / 'spool' / name).read_bytes() == data for name, data in relay_pending.items())
                # Make original host/issuer files inaccessible to the restored programs, not just unused by convention.
                hidden = workspace / 'old-host-fenced'
                os.rename(s['directory'], hidden)
                old_issuer = workspace / 'old-issuer-fenced'
                os.rename(issuer, old_issuer)
                processes = []
                created = False
                try:
                    sql('CREATE DATABASE ' + target_db)
                    created = True
                    restore(client, restored / 'payload/postgres', target_db)
                    assert client.sql(target_db, 'SELECT asset_uid::text FROM assets.assets') == uid
                    assert client.sql(target_db, 'SELECT count(*) FROM inventory.observations') == '1'
                    checks.append('PG restored into different initially empty DB with same asset UID and committed first observation')
                    with restored_node(workspace / 'target-bao', restored / 'payload/bao.snapshot', custody) as bao_address:
                        path_map = {str(s['directory']): str(host), str(issuer): str(restored / 'payload/state/issuer'),
                                    str(workspace / 'bao-config.json'): str(restored / 'payload/state/bao-app/bao-config.json'),
                                    str(workspace / 'server-token'): str(restored / 'payload/state/bao-app/server-token')}
                        def relocate(value):
                            if isinstance(value, dict):
                                return {k: relocate(v) for k, v in value.items()}
                            if isinstance(value, list):
                                return [relocate(v) for v in value]
                            if isinstance(value, str):
                                for old, new in path_map.items():
                                    if value == old or value.startswith(old + '/'):
                                        return new + value[len(old):]
                            return value
                        # Relocate only operator configs. Signed payloads, identities, profile cache and queues stay byte-identical.
                        for file in (host / 'machine.json', host / 'collector.json', host / 'checkpoint-agent.json',
                                     restored / 'payload/state/bao-app/bao-config.json'):
                            data = relocate(json.loads(file.read_text()))
                            if file.name == 'bao-config.json':
                                data['address'] = bao_address
                            file.write_text(json.dumps(data))
                        env = dict(s['server_environment'], SURVEYSCAN_V2_DATABASE_URL='postgres://surveyscan_v2@127.0.0.1:55432/' + target_db + '?sslmode=disable',
                                   SURVEYSCAN_V2_MACHINE_CONFIG=str(host / 'machine.json'), SURVEYSCAN_V2_BAO_ADDR=bao_address)
                        def start(name, args):
                            with (workspace / (name + '.log')).open('ab') as log:
                                process = subprocess.Popen(args, env=env, cwd=ROOT, stdout=log, stderr=log)
                            processes.append(process)
                            return process
                        center_binary = str(ROOT / '.dist/surveyscan-server')
                        result = subprocess.run([center_binary, 'migrate'], env=env, capture_output=True, timeout=30)
                        assert result.returncode == 0 and b'applied_migrations=0' in result.stdout
                        start('restored-center', [center_binary, 'serve'])
                        def ready():
                            try:
                                return request(s['tls_port'], s['plain'], 'GET', '/health/ready')[0] == 200
                            except OSError:
                                return False
                        until(ready, 'restored scoped server not ready')
                        code, card, _ = request(s['tls_port'], s['plain'], 'GET', '/api/v1/assets/' + uid, headers={'Cookie': s['cookie']})
                        assert code == 200 and card['asset_uid'] == uid
                        checks.append('restored center is ready against restored Bao/PG and accepts pre-backup session; original host and issuer directories absent')
                        start('restored-collector', [str(ROOT / '.dist/surveyscan-collector'), 'run', '--config', str(host / 'collector.json')])
                        until(lambda: client.sql(target_db, 'SELECT count(*) FROM inventory.observations') == '2', 'restored relay did not apply saved packet')
                        until(lambda: not list((host / 'spool').glob('*.pending')), 'restored Transit signed ACK missing')
                        assert client.sql(target_db, 'SELECT asset_uid::text FROM assets.assets') == uid
                        assert client.sql(target_db, 'SELECT count(*) FROM inventory.observation_results') == '2'
                        checks.append('restored relay applies exact saved second observation once and restored non-exportable center key signs ACK for original UID')
                        resumed = start('restored-agent', [agent, 'run', '--config', str(host / 'checkpoint-agent.json')])
                        until(lambda: client.sql(target_db, 'SELECT count(*) FROM inventory.observations') == '3', 'restored agent did not resume next source sequence')
                        until(lambda: not list((host / 'agent-state/spool').glob('*.pending')) and not list((host / 'spool').glob('*.pending')), 'restored source/relay ACK did not drain')
                        resumed.terminate()
                        assert resumed.wait(timeout=8) == 0
                        assert client.sql(target_db, 'SELECT max(source_sequence)::text FROM inventory.observations') == '3'
                        assert client.sql(target_db, 'SELECT count(*) FROM assets.assets') == '1'
                        checks.append('relocated real agent retains source generation/signing identity, retransmits old packet without duplicates and continues sequence3; both queues drain')
                        # Force a new certificate through restored Transit CA, not only reuse a pre-backup leaf.
                        result = subprocess.run([agent, 'renew', '--config', str(host / 'checkpoint-agent.json')], capture_output=True, timeout=30)
                        assert result.returncode == 0, 'restored CA leaf renewal failed'
                        renewed = json.loads((host / 'agent-state/tls-identity.json').read_text())['result']
                        initial = json.loads((host / 'agent-state/identity.json').read_text())
                        assert renewed['source_id'] == prep['source_id'] and renewed['generation_id'] == initial['generation_id']
                        assert renewed['certificate_chain_pem'] != initial['certificate_chain_pem']
                        assert sql('SELECT count(*) FROM inventory.observations') == '1', 'original database received restored traffic'
                        checks.append('real agent certificate renewal succeeds through restored collector/PG and non-exportable Transit CA')
                        report = {'package': 'C13', 'task': 'C13.03', 'status': 'passed', 'count': len(checks), 'checks': checks,
                                  'target': 'common stopped-writer checkpoint; actual Linux agent/collector/server, PG17, restored Bao2.7.2 Raft, TLS/mTLS, separate filesystem paths, pending replay/receipt and leaf renewal',
                                  'unrun': ['previous-release schema upgrade', 'systemd boot/reboot', 'two clean OS systems', 'production HTTPS/KMS/custody/DR/RPO/RTO'],
                                  'backup_marker_updated': False}
                        f['assert_redacted'](json.dumps(report))
                        (STATE / 'c13-checkpoint-smoke.json').write_text(json.dumps(report, indent=2) + '\n')
                        print(json.dumps(report))
                        # Stop clients before restored Bao context tears down.
                        for process in reversed(processes):
                            if process.poll() is None:
                                process.terminate()
                                process.wait(timeout=8)
                finally:
                    for process in reversed(processes):
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=5)
                    if created:
                        sql('DROP DATABASE ' + target_db + ' WITH (FORCE)')
                    os.rename(hidden, s['directory'])
                    os.rename(old_issuer, issuer)

            settings = {'config': f['config'], 'ca_certificate': str(issuer / 'ca.pem'),
                        'server_certificate': str(issuer / 'server.pem'), 'server_private': str(issuer / 'server.key'),
                        'center_id': str(uuid.uuid4()), 'center_public': f['profile']['keys']['center']['public_key']}
            harness(agent_scenario=scenario, bao_settings=settings)


if __name__ == '__main__':
    main()
