#!/usr/bin/env python3
"""C14 real elapsed-time E1 soak outside chat. Preflight never counts as24h acceptance.

Own tenant/DB, scoped Bao resources, real host agent/collector/server/TLS. Two loopback TCP
relays cut encrypted links without changing packets or host firewall. All private state is local.
"""
import argparse
import contextlib
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

from cryptography import x509
from bao_fixture import fixture
from dev import ROOT, STATE, initialize
from machine_smoke import main as harness, freeport


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def atomic(path, data):
    temporary = path.with_name('.status-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def append(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(data) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def pending_bytes(paths):
    total = 0
    for path in paths:
        try:
            total += path.stat().st_size
        except FileNotFoundError:
            pass  # A verified ACK may unlink a listed packet before the sample stat.
    return total


class Relay(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, target):
        self.target = target
        self.enabled = True
        self.connections = set()
        self.lock = threading.Lock()
        class Handler(socketserver.BaseRequestHandler):
            def handle(handler):
                peer = None
                try:
                    with self.lock:
                        if not self.enabled:
                            return
                        self.connections.add(handler.request)
                    peer = socket.create_connection(('127.0.0.1', target), timeout=3)
                    peer.settimeout(3)
                    with self.lock:
                        if not self.enabled:
                            return
                        self.connections.add(peer)
                    while True:
                        ready, _, _ = select.select([handler.request, peer], [], [], 1)
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            (peer if source is handler.request else handler.request).sendall(data)
                except (OSError, ValueError):
                    pass
                finally:
                    with self.lock:
                        self.connections.discard(handler.request)
                        if peer:
                            self.connections.discard(peer)
                    if peer:
                        peer.close()
        super().__init__(('127.0.0.1', 0), Handler)
        self.port = self.server_address[1]
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def set_enabled(self, enabled):
        with self.lock:
            self.enabled = enabled
            if not enabled:
                for connection in list(self.connections):
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                        connection.close()
                    except OSError:
                        pass
                self.connections.clear()

    def close(self):
        self.set_enabled(False)
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=3)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group()
    group.add_argument('--hours', type=int, default=24)
    group.add_argument('--preflight-seconds', type=int)
    p.add_argument('--run-id', default=str(uuid.uuid4()))
    args = p.parse_args()
    assert str(uuid.UUID(args.run_id)) == args.run_id
    preflight = args.preflight_seconds is not None
    assert (120 <= args.preflight_seconds <= 900) if preflight else (24 <= args.hours <= 72)
    duration = args.preflight_seconds if preflight else args.hours * 3600
    initialize()
    directory = STATE / 'c14-soak' / args.run_id
    directory.mkdir(parents=True, mode=0o700)
    status = {'package': 'C14', 'task': 'C14.02', 'run_id': args.run_id, 'kind': 'preflight' if preflight else 'actual-soak',
              'status': 'preparing', 'pid': os.getpid(), 'started_at': now(), 'required_seconds': duration,
              'source_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
              'intervals': {'inventory_seconds': 60, 'heartbeat_seconds': 30, 'monitor_seconds': 1 if preflight else 30},
              'topology': 'real Linux host agent → loopback TLS relay → collector → loopback TLS relay → center → own PG17 DB; scoped Bao Transit/KV; no mocked frames or time',
              'unrun': ['production/HA/geo/100-user SLA'], 'events': []}
    atomic(directory / 'status.json', status)
    def event(kind, **details):
        entry = {'at': now(), 'event': kind, **details}
        append(directory / 'events.jsonl', entry)
        status['events'].append(entry)
        atomic(directory / 'status.json', status)
    def stop_signal(*_):
        raise InterruptedError('soak interrupted')
    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    try:
        with tempfile.TemporaryDirectory(prefix='private-', dir=directory) as temp:
            private = Path(temp)
            binaries = private / 'bin'
            binaries.mkdir(mode=0o700)
            for name in ('surveyscan-server', 'surveyscan-collector', 'surveyscan-agent'):
                shutil.copy2(ROOT / '.dist' / name, binaries / name)
            status['binary_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in binaries.iterdir()}
            status['runner_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            with fixture(private) as f:
                issuer = private / 'issuer'
                result = subprocess.run([str(binaries / 'surveyscan-server'), 'bootstrap-issuer', '--config', f['config'],
                    '--output-directory', str(issuer), '--server-validity', '120h'], capture_output=True, timeout=30)
                assert result.returncode == 0, 'soak issuer bootstrap failed'
                certificate = x509.load_pem_x509_certificate((issuer / 'server.pem').read_bytes())
                assert (certificate.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).total_seconds() > duration + 3600

                def scenario(**s):
                    sql, request, save = s['sql'], s['request'], s['save']
                    assert hashlib.sha256(Path('/proc/'+str(s['center_process'].pid)+'/exe').read_bytes()).hexdigest() == status['binary_sha256']['surveyscan-server'], 'center source changed during soak setup'
                    proxies = []
                    active = {'center': s['center_process'], 'collector': s['collector_process']}
                    extra = []
                    def launch(name, command):
                        env = dict(s['server_environment']) if name == 'center' else dict(os.environ)
                        if name != 'center':
                            for key in list(env):
                                if key.startswith('SURVEYSCAN_V2_'):
                                    env.pop(key)
                        with (private / (name + '-process.log')).open('ab') as log:
                            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=log)
                        active[name] = process
                        extra.append(process)
                        return process
                    def stop(name):
                        process = active[name]
                        if process.poll() is None:
                            process.terminate()
                            assert process.wait(timeout=10) == 0, 'process did not stop cleanly'
                    try:
                        to_center = Relay(s['tls_port'])
                        to_collector = Relay(s['collector_port'])
                        proxies += [to_center, to_collector]
                        stop('collector')
                        collector_config = json.loads(Path(s['collector_config']).read_text())
                        collector_config['center_url'] = 'https://127.0.0.1:' + str(to_center.port)
                        Path(s['collector_config']).write_text(json.dumps(collector_config))
                        commands = {'center': [str(binaries / 'surveyscan-server'), 'serve'],
                                    'collector': [str(binaries / 'surveyscan-collector'), 'run', '--config', s['collector_config']]}
                        launch('collector', commands['collector'])
                        deadline = time.monotonic() + 15
                        while True:
                            try:
                                if request(s['collector_port'], s['plain'], 'GET', '/health/live', sni=s['collector_source']+'.collector.invalid')[0] == 200:
                                    break
                            except (OSError, http.client.HTTPException):
                                pass
                            assert time.monotonic() < deadline, 'collector failed to restart before enrollment'
                            time.sleep(.1)
                        state = s['directory'] / 'soak-agent'
                        config = save('soak-agent.json', json.dumps({'tenant_id': s['tenant'], 'site_id': s['site'], 'network_scope_id': s['scope'],
                            'collector_url': 'https://127.0.0.1:' + str(to_collector.port), 'collector_source_id': s['collector_source'],
                            'ca_certificate_file': s['ca_file'], 'state_directory': str(state), 'inventory_seconds': 60, 'heartbeat_seconds': 30,
                            'jitter_percent': 0, 'spool_limit_bytes': 4194304}))
                        agent = str(binaries / 'surveyscan-agent')
                        def a(*args):
                            result = subprocess.run([agent, *args, '--config', config], capture_output=True, timeout=30)
                            assert result.returncode == 0, 'soak agent bootstrap failed'
                            return result.stdout
                        prep = json.loads(a('prepare'))
                        headers = {'Origin': s['origin'], 'Cookie': s['cookie'], 'X-CSRF-Token': s['session']['csrf_token']}
                        code, grant, _ = request(s['tls_port'], s['plain'], 'POST', '/api/v1/enrollments',
                            {'tenant_id': s['tenant'], 'source_id': prep['source_id'], 'source_kind': 'agent', 'site_id': s['site'],
                             'collector_id': s['collector_id'], 'ttl_seconds': 900, 'csr_sha256': prep['csr_sha256'], 'signing_public_key': prep['signing_public_key']}, headers)
                        assert code == 201
                        permission = save('soak-grant.json', json.dumps(grant))
                        a('enroll', '--grant-file', permission)
                        Path(permission).unlink()
                        commands['agent'] = [agent, 'run', '--config', config]
                        launch('agent', commands['agent'])
                        deadline = time.monotonic() + 30
                        while time.monotonic() < deadline and sql('SELECT count(*) FROM inventory.observations') != '1':
                            time.sleep(.2)
                        assert sql('SELECT count(*) FROM inventory.observations') == '1'
                        uid = sql('SELECT asset_uid::text FROM assets.assets')
                        initial = 1
                        start = time.monotonic()
                        status.update(status='running', measured_started_at=now(), elapsed_seconds=0, initial_observations=initial,
                                      source_id=prep['source_id'], asset_uid=uid, server_certificate_not_after=certificate.not_valid_after_utc.isoformat(),
                                      versions={name: json.loads(subprocess.check_output([str(binaries / name), 'version']))
                                                for name in ('surveyscan-server', 'surveyscan-collector', 'surveyscan-agent')})
                        atomic(directory / 'status.json', status)
                        event('measured_window_started')
                        # Test runner uses real wall time; preflight is explicitly a different result kind.
                        cut_a, restore_a, cut_c, restore_c = ((5, 25, 35, 55) if preflight else (3600, 3720, 7200, 7320))
                        def restart(name):
                            stop(name)
                            launch(name, commands[name])
                        schedule = [(cut_a, 'agent_link_cut', lambda: to_collector.set_enabled(False)),
                                    (cut_a+1, 'agent_restart_while_disconnected', lambda: restart('agent')),
                                    (restore_a, 'agent_link_restored', lambda: to_collector.set_enabled(True)),
                                    (cut_c, 'center_link_cut', lambda: to_center.set_enabled(False)),
                                    (cut_c+1, 'agent_collect_while_center_disconnected', lambda: restart('agent')),
                                    (restore_c, 'center_link_restored', lambda: to_center.set_enabled(True)),
                                    (75 if preflight else 10800, 'collector_restart', lambda: restart('collector')),
                                    (95 if preflight else 14400, 'center_restart', lambda: restart('center'))]
                        done = set()
                        previous = initial
                        samples = 0
                        peak_rss = {}
                        readiness_failures = 0
                        observed_pending = {'agent': False, 'collector': False}
                        while time.monotonic() - start < duration:
                            elapsed = time.monotonic() - start
                            for index, (at, kind, action) in enumerate(schedule):
                                if elapsed >= at and index not in done:
                                    action()
                                    done.add(index)
                                    event(kind, elapsed_seconds=round(elapsed, 3))
                            assert all(process.poll() is None for process in active.values()), 'soak process unexpectedly exited'
                            count = int(sql('SELECT count(*) FROM inventory.observations'))
                            assert count >= previous and sql('SELECT asset_uid::text FROM assets.assets') == uid
                            assert sql('SELECT count(*) FROM assets.assets') == '1'
                            assert sql('SELECT count(*)=count(DISTINCT source_sequence) FROM inventory.observations') == 't'
                            previous = count
                            spool = state / 'spool'
                            relay_spool = s['directory'] / 'spool'
                            pending_a = list(spool.glob('*.pending'))
                            pending_c = list(relay_spool.glob('*.pending'))
                            observed_pending['agent'] |= bool(pending_a)
                            observed_pending['collector'] |= bool(pending_c)
                            memory = {}
                            cpu = {}
                            for name, process in active.items():
                                raw = Path('/proc/' + str(process.pid) + '/status').read_text()
                                memory[name] = int(next((line.split()[1] for line in raw.splitlines() if line.startswith('VmRSS:')), '0'))
                                peak_rss[name] = max(peak_rss.get(name, 0), memory[name])
                                procstat = Path('/proc/' + str(process.pid) + '/stat').read_text().rsplit(')', 1)[1].split()
                                cpu[name] = round((int(procstat[11])+int(procstat[12])) / os.sysconf('SC_CLK_TCK'), 3)
                            # Real readiness calls renew the scoped Bao token as its lease approaches expiry.
                            try:
                                ready = request(s['tls_port'], s['plain'], 'GET', '/health/ready')[0] == 200
                            except (OSError, http.client.HTTPException):
                                ready = False
                            readiness_failures = readiness_failures + 1 if not ready else 0
                            assert readiness_failures <= (15 if preflight else 4), 'persistent unexpected readiness failure'
                            sample = {'at': now(), 'elapsed_seconds': round(elapsed, 3), 'observations': count,
                                      'max_source_sequence': sql('SELECT max(source_sequence)::text FROM inventory.observations'),
                                      'inventory_age_seconds': float(sql('SELECT extract(epoch FROM clock_timestamp()-max(collected_at)) FROM inventory.observations')),
                                      'agent_pending': len(pending_a), 'collector_pending': len(pending_c),
                                      'agent_pending_bytes': pending_bytes(pending_a),
                                      'collector_pending_bytes': pending_bytes(pending_c),
                                      'rss_kib': memory, 'process_cpu_seconds': cpu, 'ready': ready,
                                      'sections': json.loads(sql("SELECT COALESCE(json_object_agg(status,n),'{}'::json) FROM (SELECT status,count(*) n FROM inventory.observation_sections GROUP BY status) s")),
                                      'outbox_unapplied': int(sql("SELECT count(*) FROM messaging.outbox_events e WHERE NOT EXISTS (SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.state='applied')")),
                                      'source_inventory_age_seconds': float(sql('SELECT extract(epoch FROM clock_timestamp()-max(last_successful_inventory_at)) FROM sources.inventory_progress')),
                                      'renewal_receipts': int(sql('SELECT count(*) FROM sources.renewal_receipts'))}
                            append(directory / 'samples.jsonl', sample)
                            assert sample['inventory_age_seconds'] <= 300, 'no fresh inventory for more than300 real seconds'
                            assert sample['agent_pending_bytes'] <= 4194304 and sample['collector_pending_bytes'] <= 1048576, 'pending spool exceeded configured capacity'
                            samples += 1
                            status.update(elapsed_seconds=sample['elapsed_seconds'], last_sample=sample, samples=samples, peak_rss_kib=peak_rss)
                            atomic(directory / 'status.json', status)
                            time.sleep(1 if preflight else 30)
                        to_collector.set_enabled(True)
                        to_center.set_enabled(True)
                        # End the measured cadence, then drain a finite set. A live producer
                        # can enqueue a new packet while a previous result is being polled.
                        stop('agent')
                        drain_config = json.loads(Path(config).read_text())
                        drain_config['inventory_seconds'] = 86400
                        Path(config).write_text(json.dumps(drain_config))
                        launch('agent', commands['agent'])
                        event('final_drain_started', elapsed_seconds=round(time.monotonic()-start, 3), inventory_seconds=86400)
                        deadline = time.monotonic() + 180
                        while time.monotonic() < deadline:
                            if not list((state/'spool').glob('*.pending')) and not list((s['directory']/'spool').glob('*.pending')):
                                break
                            time.sleep(.3)
                        assert not list((state/'spool').glob('*.pending')) and not list((s['directory']/'spool').glob('*.pending')), 'final finite queue failed to drain within180s'
                        assert sql('SELECT count(*) FROM inventory.observations') == sql('SELECT count(*) FROM inventory.observation_results'), 'committed observation/result mismatch'
                        assert sql('SELECT asset_uid::text FROM assets.assets') == uid, 'asset UID changed during soak'
                        elapsed = time.monotonic() - start
                        assert elapsed >= duration and len(done) == len(schedule)
                        assert int(sql('SELECT count(*) FROM inventory.observations')) > initial + 2
                        assert sql('SELECT count(*)=max(source_sequence) FROM inventory.observations') == 't', 'source sequence gap after final drain'
                        assert all(observed_pending.values()), 'outage did not exercise both durable spools'
                        # Each 24h leaf reaches the real renewal boundary during the real soak.
                        if not preflight:
                            assert (state / 'tls-identity.json').exists(), 'agent did not rotate its actual expiring leaf'
                            assert (Path(collector_config['credential_directory']) / 'tls-identity.json').exists(), 'collector did not rotate its actual expiring leaf'
                            assert int(sql('SELECT count(*) FROM sources.renewal_receipts')) >= 2
                        status.update(status='preflight_passed' if preflight else 'passed', measured_ended_at=now(), elapsed_seconds=round(elapsed, 3),
                                      end_observations=int(sql('SELECT count(*) FROM inventory.observations')), pending_drained=True, observed_pending=observed_pending)
                        atomic(directory / 'status.json', status)
                        event('measured_window_completed', accepted_24h=not preflight)
                    finally:
                        for proxy in proxies:
                            proxy.close()
                        for process in reversed(extra):
                            if process.poll() is None:
                                process.terminate()
                                try:process.wait(timeout=10)
                                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)

                settings = {'config': f['config'], 'ca_certificate': str(issuer/'ca.pem'), 'server_certificate': str(issuer/'server.pem'),
                            'server_private': str(issuer/'server.key'), 'center_id': str(uuid.uuid4()), 'center_public': f['profile']['keys']['center']['public_key']}
                harness(agent_scenario=scenario, bao_settings=settings)
    except BaseException as error:
        status.update(status='interrupted' if isinstance(error, (InterruptedError, KeyboardInterrupt)) else 'failed',
                      ended_at=now(), error_type=type(error).__name__)
        atomic(directory / 'status.json', status)
        raise
    print(json.dumps({'run_id':args.run_id,'status':status['status'],'elapsed_seconds':status.get('elapsed_seconds',0),'path':str(directory/'status.json')}))


if __name__ == '__main__':main()
