#!/usr/bin/env python3
"""Actual C11 binary/schema31 -> current binary/schema35; isolated DB, no schema edits or downgrade."""
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time

CURRENT = Path(__file__).resolve().parents[1]
PREVIOUS = 'b22efa2'


def fixture(old_root):
    sys.path.insert(0, str(old_root / 'scripts'))
    from machine_smoke import main as harness
    from dev import STATE
    def scenario(**s):
        checks, sql = s['checks'], s['sql']
        for process in (s['collector_process'], s['center_process']):
            process.terminate()
            assert process.wait(timeout=8) == 0
        tables = sql("SELECT table_schema||'.'||table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema','platform') ORDER BY 1").splitlines()
        def fingerprint(table):  # колонки inventory_platform (0035) и acquisition (0036) (и позже — merged_*, asset_class, user_id, origin, note, external_id, synced_at, directory_login) добавлены позже и в сравнение старых данных не входит
            return sql("SELECT encode(sha256(convert_to(coalesce(string_agg((to_jsonb(t)-'inventory_platform'-'acquisition'-'merged_into'-'merged_at'-'asset_class'-'user_id'-'origin'-'note'-'external_id'-'synced_at'-'directory_login')::text,E'\\n' ORDER BY (to_jsonb(t)-'inventory_platform'-'acquisition'-'merged_into'-'merged_at'-'asset_class'-'user_id'-'origin'-'note'-'external_id'-'synced_at')::text),''),'UTF8')),'hex') FROM " + table + ' t')
        before = {table: fingerprint(table) for table in tables}
        ledger = sql('SELECT id||owner||sha256 FROM platform.schema_migrations ORDER BY id').splitlines()
        assert len(ledger) == 31
        checks.append('actual previous C11 server/collector populate schema31 with inventory, UID, auth, history and outbox; previous writers stopped')
        env = s['server_environment']
        binary = str(CURRENT / '.dist/surveyscan-server')
        result = subprocess.run([binary, 'migrate'], env=env, capture_output=True, timeout=30)
        assert result.returncode == 0 and b'applied_migrations=20' in result.stdout
        assert {table: fingerprint(table) for table in tables} == before
        assert len(sql('SELECT id FROM platform.schema_migrations').splitlines()) == 51
        assert set(ledger) <= set(sql('SELECT id||owner||sha256 FROM platform.schema_migrations ORDER BY id').splitlines())
        checks.append('current binary appends exactly20 migrations; every previous data table and all31 applied hashes preserved')
        result = subprocess.run([binary, 'migrate'], env=env, capture_output=True, timeout=30)
        assert result.returncode == 0 and b'applied_migrations=0' in result.stdout
        checks.append('second current migrate is a verified no-op; no edited SQL or duplicate upgrade effects')
        process = None
        try:
            with (s['directory'] / 'upgraded-server.log').open('ab') as log:
                process = subprocess.Popen([binary, 'serve'], env=env, stdout=log, stderr=log)
            context = ssl.create_default_context(cafile=s['ca_file'])
            def request(method, path, body=None, headers=None):
                connection = http.client.HTTPSConnection('127.0.0.1', s['center_port'], context=context, timeout=5)
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
            for _ in range(100):
                try:
                    if request('GET', '/health/ready')[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.1)
            else:
                raise AssertionError('upgraded server did not become ready')
            code, session, headers = request('POST', '/api/v1/auth/sessions', {'username': s['username'], 'password': s['password']}, {'Origin': s['origin']})
            assert code == 201 and session['tenant_id'] == s['tenant']
            cookie = headers['set-cookie'].split(';', 1)[0]
            code, card, headers = request('GET', '/api/v1/assets/' + s['asset'], headers={'Cookie': cookie})
            assert code == 200 and card['asset_uid'] == s['asset']
            checks.append('upgraded real TLS server authenticates previous admin and serves same previous asset UID/card')
            code, changed, _ = request('PATCH', '/api/v1/assets/' + s['asset'], {'display_name': 'after C11 upgrade'},
                {'Cookie': cookie, 'Origin': s['origin'], 'X-CSRF-Token': session['csrf_token'], 'If-Match': headers['etag']})
            assert code == 200 and changed['business']['display_name'] == 'after C11 upgrade'
            source = sql("SELECT source_id::text FROM sources.sources WHERE source_kind='agent' LIMIT 1")
            code, profile, _ = request('GET', '/api/v1/sources/' + source + '/profile', headers={'Cookie': cookie})
            assert code == 200 and not profile['managed'] and profile['config']['profile_revision'] == '1'
            checks.append('authorized write works after upgrade; newly introduced profiles expose unmanaged revision1 for existing source')
            report = {'package': 'C13', 'task': 'C13.03', 'status': 'passed', 'count': len(checks), 'checks': checks,
                      'previous_ref': PREVIOUS, 'previous_migrations': 31, 'current_migrations': 37,
                      'target': 'archived actual C11 source compiled into previous server/collector; real PG, TLS and signed synthetic inventory; current migration and API',
                      'fixture_adapter': 'only old test callback extended to expose SQL helper/processes/environment; previous application code/SQL not modified',
                      'unrun': ['live service update/rollback', 'schema downgrade', 'systemd boot/reboot', 'two clean OS systems', 'production/DR']}
            (CURRENT / '.local/c13-upgrade-smoke.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report))
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
    harness(web_scenario=scenario)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--fixture':
        fixture(Path(sys.argv[2]))
        return
    (CURRENT / '.local').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='c13-upgrade-', dir=CURRENT / '.local') as temp:
        work = Path(temp)
        archive = subprocess.check_output(['git', 'archive', PREVIOUS, 'v2'], cwd=CURRENT.parent)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work, filter='data')
        old = work / 'v2'
        (old / '.local').mkdir(mode=0o700)
        shutil.copyfile(CURRENT / '.local/pg_password', old / '.local/pg_password')
        (old / '.local/pg_password').chmod(0o600)
        go = os.environ.get('GO', 'go')
        revision = subprocess.check_output(['git', 'rev-parse', PREVIOUS], cwd=CURRENT, text=True).strip()
        result = subprocess.run(['make', 'build', 'GO=' + go, 'REVISION=' + revision], cwd=old, capture_output=True, timeout=180)
        assert result.returncode == 0, 'previous C11 application build failed'
        # Test-only adapter: previous application sources and applied SQL stay byte-for-byte archived.
        script = old / 'scripts/machine_smoke.py'
        code = script.read_text()
        needle = 'web_scenario(directory='
        assert code.count(needle) == 1
        script.write_text(code.replace(needle, 'web_scenario(sql=lambda query:sql(query,db),center_process=center_process,collector_process=collector_process,server_environment=dict(env),directory='))
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--fixture', str(old)], cwd=old, capture_output=True, timeout=180)
        if result.returncode:
            # Traceback contains only test code/paths; do not forward raw child application logs.
            sys.stderr.buffer.write(result.stderr)
            raise AssertionError('previous-to-current upgrade rehearsal failed')
        print(result.stdout.decode().strip())


if __name__ == '__main__':
    main()
