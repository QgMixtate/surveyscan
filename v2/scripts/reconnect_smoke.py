#!/usr/bin/env python3
"""C14 E1-T07: three real local agent processes, quota pressure and simultaneous reconnect.

Separate enrolled sources on one real host, not three physical host identities or a load SLA.
Quota filler is an explicit test file in owned temporary spools; ENOSPC is tested separately.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from dev import ROOT, STATE
from machine_smoke import main as harness
from soak import Relay


def scenario(**s):
    checks = []
    sql, request, save = s['sql'], s['request'], s['save']
    processes = []
    agents = []
    relay = Relay(s['collector_port'])
    binary = str(ROOT / '.dist/surveyscan-agent')
    env = {k: v for k, v in os.environ.items() if not k.startswith('SURVEYSCAN_V2_')}
    def until(predicate, message, timeout=30):
        end = time.monotonic()+timeout
        while time.monotonic() < end:
            if predicate():return
            time.sleep(.2)
        raise RuntimeError(message)
    def console(config, *args):
        p = subprocess.run([binary, *args, '--config', config], env=env, capture_output=True, timeout=25)
        assert p.returncode == 0, 'agent bootstrap failed'
        return p.stdout
    def run(a, stage):
        log = save('agent-'+str(a['number'])+'-'+stage+'.log', '')
        with open(log, 'ab') as output:
            p = subprocess.Popen([binary, 'run', '--config', a['config']], env=env, stdout=output, stderr=output)
        processes.append(p)
        a['process'], a['log'] = p, Path(log)
    try:
        for number in range(3):
            state = s['directory'] / ('agent-'+str(number))
            cfg = {'tenant_id':s['tenant'], 'site_id':s['site'], 'network_scope_id':s['scope'],
                   'collector_url':'https://127.0.0.1:'+str(relay.port), 'collector_source_id':s['collector_source'],
                   'ca_certificate_file':s['ca_file'], 'state_directory':str(state),
                   'inventory_seconds':86400, 'heartbeat_seconds':30, 'jitter_percent':10, 'spool_limit_bytes':524288}
            config = save('agent-'+str(number)+'.json', json.dumps(cfg))
            prep = json.loads(console(config, 'prepare'))
            headers = {'Origin':s['origin'], 'Cookie':s['cookie'], 'X-CSRF-Token':s['session']['csrf_token']}
            code, grant, _ = request(s['tls_port'], s['plain'], 'POST', '/api/v1/enrollments',
                {'tenant_id':s['tenant'], 'source_id':prep['source_id'], 'source_kind':'agent', 'site_id':s['site'],
                 'collector_id':s['collector_id'], 'ttl_seconds':900, 'csr_sha256':prep['csr_sha256'],
                 'signing_public_key':prep['signing_public_key']}, headers)
            assert code == 201
            permission = save('grant-'+str(number)+'.json', json.dumps(grant))
            console(config, 'enroll', '--grant-file', permission)
            Path(permission).unlink()
            agents.append({'number':number, 'source':prep['source_id'], 'state':state, 'config':config})
        assert len({a['source'] for a in agents}) == 3
        relay.set_enabled(False)
        for a in agents:run(a, 'offline')
        until(lambda:all(len(list((a['state']/'spool').glob('*.pending')))==1 for a in agents), 'not all real agents queued offline observations')
        assert sql('SELECT count(*) FROM inventory.observations') == '0'
        for a in agents:
            a['process'].terminate()
            assert a['process'].wait(timeout=10) == 0
            a['original'] = {p.name:p.read_bytes() for p in (a['state']/'spool').glob('*.pending')}
            a['sequences'] = (a['state']/'sequences.json').read_bytes()
            filler = a['state']/'spool'/'.quota-fixture'
            with filler.open('wb') as stream:stream.write(b'Q'*380000)
            filler.chmod(0o600)
        checks.append('three independently enrolled real agent processes retain one original signed observation each while agent TLS link is cut')
        for a in agents:run(a, 'quota')
        until(lambda:all('inventory_failed' in a['log'].read_text() for a in agents), 'small quota did not expose inventory backpressure')
        time.sleep(8)
        attempts = []
        for a in agents:
            assert a['process'].poll() is None
            assert all((a['state']/'spool'/name).read_bytes()==raw for name,raw in a['original'].items())
            current = json.loads((a['state']/'sequences.json').read_text())
            assert current['inventory'] == json.loads(a['sequences'])['inventory'], 'failed admission consumed source sequence'
            n = a['log'].read_text().count('delivery_pending')
            assert 1 <= n <= 12, 'retry loop was absent or busy during real8s outage'
            attempts.append(n)
        checks.append('explicit380000-byte quota fixture triggers real admission failure without changing pending bytes/source inventory sequence; all processes stay alive')
        checks.append('real8s disconnected interval has bounded1..12 delivery retries per agent with production jitter/backoff enabled')
        for a in agents:(a['state']/'spool'/'.quota-fixture').unlink()
        started = time.monotonic()
        relay.set_enabled(True)
        until(lambda:sql('SELECT count(*) FROM inventory.observations')=='3', 'simultaneous reconnect did not commit all three real source observations', 90)
        until(lambda:all(not list((a['state']/'spool').glob('*.pending')) for a in agents) and not list((s['directory']/'spool').glob('*.pending')), 'signed ACKs did not drain all source and relay queues', 90)
        assert sql('SELECT count(*) FROM inventory.observation_results') == '3'
        assert sql('SELECT count(DISTINCT source_id) FROM inventory.observations') == '3'
        assert sql('SELECT max(source_sequence)::text FROM inventory.observations') == '1'
        uid_count = sql('SELECT count(*) FROM assets.assets')
        checks.append('one real network restore commits three source sequence1 observations once, keeps source identities distinct and drains all four queues after signed ACK')
        events = sql('SELECT count(*) FROM messaging.outbox_events')
        for a in agents:
            assert len(list((a['state']/'spool').glob('*.receipt'))) == 1
            # Restore the exact original packet alongside its verified cached receipt.
            for name, raw in a['original'].items():
                temporary = a['state']/'spool'/'.replay-fixture'
                fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, a['state']/'spool'/name)
        until(lambda:all(not list((a['state']/'spool').glob('*.pending')) for a in agents), 'cached ACK replay did not clean original source bytes', 15)
        assert sql('SELECT count(*) FROM inventory.observations') == '3'
        assert sql('SELECT count(*) FROM messaging.outbox_events') == events and sql('SELECT count(*) FROM assets.assets') == uid_count
        checks.append('exact original source replay with verified cached receipt adds no observations/assets/outbox effects and drains again')
        report = {'package':'C14', 'scenario':'E1-T07', 'status':'passed', 'count':len(checks), 'checks':checks,
                  'agents':3, 'hosts':1, 'spool_quota_bytes':524288, 'quota_fixture_bytes':380000,
                  'retry_counts_during8s':attempts, 'reconnect_drain_seconds':round(time.monotonic()-started,3),
                  'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                  'scope':'real compiled Linux read-only agents/collector/center/PG/TLS; own tenant/database/private dirs; quota fixture declared; no mocked observation/clock',
                  'unrun':['three separate physical hosts','large reconnect storm/100-user SLA','ENOSPC in this script (separate diskfault.py report)','24h acceptance']}
        (STATE/'c14-reconnect-smoke.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
    finally:
        relay.close()
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)


if __name__ == '__main__':harness(agent_scenario=scenario)
