#!/usr/bin/env python3
"""C13 partial PG restore rehearsal: real binary/mTLS pipeline, isolated source/restore databases.

Bao Raft and offline filesystem state are not included. No complete-system DR claim.
"""
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import time
import uuid

from dev import ROOT, STATE, DOCKER, ENV
from machine_smoke import main as harness
from pg_backup import Client, backup, restore
from release import digest


def scenario(**s):
    checks = s['checks']
    s['quiesce']()
    sql = s['sql']
    database = sql('SELECT current_database()')
    destination = 'ssv2restore_' + uuid.uuid4().hex
    client = Client({tool: DOCKER + ['exec', '-T', '-e', 'PGUSER=surveyscan_v2', 'db', tool]
                     for tool in ('psql', 'pg_dump', 'pg_restore')}, env=ENV)
    directory = s['directory'] / 'database-backup'
    created = False
    restored_process = None
    def refused(action):
        try:
            action()
        except ValueError:
            return
        raise AssertionError('unsafe backup/restore accepted')
    try:
        # Explicit SQL fixture after quiesce: one retry checkpoint to prove queue state round-trip.
        sql("INSERT INTO messaging.consumer_checkpoints(tenant_id,consumer_name,event_id,state,attempts) SELECT tenant_id,'c13-restore-fixture',event_id,'retry',2 FROM messaging.outbox_events ORDER BY event_id LIMIT 1")
        assert int(sql("SELECT count(*) FROM messaging.consumer_checkpoints WHERE state='retry'")) > 0
        tables = sql("SELECT table_schema||'.'||table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1").splitlines()
        def fingerprint(db, table):
            return client.sql(db, "SELECT encode(sha256(convert_to(coalesce(string_agg(row_to_json(t)::text,E'\\n' ORDER BY row_to_json(t)::text),''),'UTF8')),'hex') FROM " + table + ' t')
        before = {name: fingerprint(database, name) for name in tables}
        assert len(tables) == 48  # 47 owned tables + migration ledger.
        backup(client, database, directory)
        assert directory.stat().st_mode & 0o777 == 0o700
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir())
        checks.append('PG17 custom archive completed privately after actual binary services quiesced')
        assert not json.loads((directory / 'backup.json').read_text())['complete_system_backup']
        checks.append('PG-only manifest never marks complete PG/Bao/filesystem backup or writes system backup-age marker')
        refused(lambda: backup(client, database, directory))
        refused(lambda: restore(client, directory, database))
        checks.append('existing backup and source database restore refused without destructive flags')
        sql('CREATE DATABASE ' + destination)
        created = True
        archive = directory / 'postgres.dump'
        original_hash = digest(archive)
        with archive.open('ab') as stream:
            stream.write(b'bad')
        refused(lambda: restore(client, directory, destination))
        assert client.sql(destination, "SELECT count(*) FROM pg_namespace WHERE nspname='assets'") == '0'
        with archive.open('r+b') as stream:
            stream.truncate(archive.stat().st_size - 3)
        assert digest(archive) == original_hash
        checks.append('corrupt archive refused before writing to clean destination')
        client.sql(destination, 'CREATE TABLE public.restore_guard(id integer)')
        refused(lambda: restore(client, directory, destination))
        assert client.sql(destination, 'SELECT count(*) FROM public.restore_guard') == '0'
        client.sql(destination, 'DROP TABLE public.restore_guard')  # Own empty fixture only.
        checks.append('nonempty restore target refused and pre-existing sentinel table preserved')
        restore(client, directory, destination)
        after = {name: fingerprint(destination, name) for name in tables}
        assert after == before
        checks.append('all48 table fingerprints identical: UID, access/session/hash, history, observations, receipt, retry queue/outbox and migration ledger')
        assert client.sql(destination, 'SELECT asset_uid::text FROM assets.assets') == s['asset']
        assert int(client.sql(destination, "SELECT count(*) FROM messaging.consumer_checkpoints WHERE state='retry'")) > 0
        env = dict(s['server_environment'])
        env['SURVEYSCAN_V2_DATABASE_URL'] = 'postgres://surveyscan_v2@127.0.0.1:55432/' + destination + '?sslmode=disable'
        binary = str(ROOT / '.dist/surveyscan-server')
        result = subprocess.run([binary, 'migrate'], env=env, capture_output=True, timeout=30)
        assert result.returncode == 0 and b'applied_migrations=0' in result.stdout
        checks.append('current binary verifies restored34 migration hashes and applies zero duplicate migrations')
        with (s['directory'] / 'restored-server.log').open('ab') as log:
            restored_process = subprocess.Popen([binary, 'serve'], env=env, stdout=log, stderr=log)
        context = ssl.create_default_context(cafile=s['ca_file'])
        def request(method, path, body=None, headers=None):
            connection = http.client.HTTPSConnection('127.0.0.1', s['center_port'], context=context, timeout=5)
            try:
                h = dict(headers or {})
                if body is not None:
                    body = json.dumps(body).encode()
                    h['Content-Type'] = 'application/json'
                connection.request(method, path, body=body, headers=h)
                response = connection.getresponse()
                raw = response.read()
                return response.status, json.loads(raw) if raw else None, response.getheader('Set-Cookie') or response.getheader('ETag')
            finally:
                connection.close()
        for _ in range(100):
            try:
                if request('GET', '/health/ready')[0] == 200:
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(.1)
        else:
            raise AssertionError('restored server did not become ready')
        status, session, cookie = request('POST', '/api/v1/auth/sessions',
            {'username': s['username'], 'password': s['password']}, {'Origin': s['origin']})
        assert status == 201 and session['tenant_id'] == s['tenant'] and cookie
        status, card, etag = request('GET', '/api/v1/assets/' + s['asset'], headers={'Cookie': cookie.split(';', 1)[0]})
        assert status == 200 and card['asset_uid'] == s['asset'] and card['observed_hostname'] == 'pipeline-host'
        checks.append('restored real server authenticates previous admin credentials and serves same UID/card through TLS API')
        events = int(client.sql(destination, 'SELECT count(*) FROM messaging.outbox_events'))
        audits = int(client.sql(destination, 'SELECT count(*) FROM audit.audit_events'))
        status, changed, _ = request('PATCH', '/api/v1/assets/' + s['asset'], {'display_name': 'restored operator write'},
            {'Cookie': cookie.split(';', 1)[0], 'Origin': s['origin'], 'X-CSRF-Token': session['csrf_token'], 'If-Match': etag})
        assert status == 200 and changed['asset_uid'] == s['asset'] and changed['business']['display_name'] == 'restored operator write'
        assert int(client.sql(destination, 'SELECT count(*) FROM messaging.outbox_events')) == events + 1
        assert int(client.sql(destination, 'SELECT count(*) FROM audit.audit_events')) == audits + 1
        checks.append('restored server accepts authorized CSRF/If-Match mutation with same UID and one new audit/outbox transaction')
        refused(lambda: restore(client, directory, destination))
        checks.append('second restore onto running/nonempty registry refused')
        report = {'package': 'C13', 'task': 'C13.03 PG component preparation', 'status': 'passed',
                  'count': len(checks), 'checks': checks, 'table_count': len(tables),
                  'target': 'real PG17 custom dump/restore into new DB; compiled server/collector, TLS, synthetic signed inventory; explicit SQL retry checkpoint fixture',
                  'unrun': ['Bao Raft snapshot/restore and key operations', 'filesystem/agent/collector identity/spool backup',
                            'complete-system point-in-time consistency', 'schema upgrade from previous release',
                            'clean OS/systemd boot/reboot', 'production/DR/RPO/RTO']}
        (STATE / 'c13-pg-restore-smoke.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))
    finally:
        if restored_process is not None:
            restored_process.terminate()
            try:
                restored_process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                restored_process.kill()
                restored_process.wait(timeout=3)
        if created:
            sql('DROP DATABASE ' + destination + ' WITH (FORCE)')


if __name__ == '__main__':
    harness(web_scenario=scenario)
