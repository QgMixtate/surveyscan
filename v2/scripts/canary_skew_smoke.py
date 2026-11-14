#!/usr/bin/env python3
"""C40.02 — обновление без остановки и совместимость версий (N-1 ↔ N) на настоящих процессах.

N-1 — ревизия стенда (PREVIOUS); обвязка machine_smoke из её дерева поднимает старые центр и collector с данными.
1. Миграции N применяются **под работающим** центром N-1: старый код продолжает читать/писать на новой схеме.
2. Канарейка: api версии N рядом со старым центром на той же БД — оба обслуживают те же данные.
3. Collector обновляется до N на прежнем состоянии и продолжает работу (пульс принят центром).
4. Откат: api N остановлен, collector возвращён к N-1 на состоянии, тронутом N, — всё работает.
Отчёт — .local/c40-canary-skew-smoke.json.
"""
import http.client, io, json, os, shutil, ssl, subprocess, sys, tarfile, tempfile, time
from pathlib import Path

CURRENT = Path(__file__).resolve().parents[1]
PREVIOUS = 'a519ffe'  # версия стенда (задание №9)


def fixture(old_root):
    sys.path.insert(0, str(old_root / 'scripts'))
    from machine_smoke import main as harness, freeport

    def scenario(**s):
        checks, sql, env = s['checks'], s['sql'], s['server_environment']
        ctx = ssl.create_default_context(cafile=s['ca_file'])
        new = CURRENT / '.dist'
        procs = []

        def request(port, method, path, body=None, headers=None):
            c = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=8)
            h = dict(headers or {})
            if body is not None:
                body = json.dumps(body).encode(); h['Content-Type'] = 'application/json'
            try:
                c.request(method, path, body=body, headers=h); r = c.getresponse(); raw = r.read()
                return r.status, (json.loads(raw) if raw[:1] in (b'{', b'[') else None), {k.lower(): v for k, v in r.getheaders()}
            finally:
                c.close()

        def login(port):
            code, session, h = request(port, 'POST', '/api/v1/auth/sessions', {'username': s['username'], 'password': s['password']}, {'Origin': s['origin']})
            assert code == 201, code
            return {'Cookie': h['set-cookie'].split(';', 1)[0]}, session['csrf_token']

        def ready(port):
            for _ in range(150):
                try:
                    if request(port, 'GET', '/health/ready')[0] == 200:
                        return
                except OSError:
                    pass
                time.sleep(.1)
            raise AssertionError(f'port {port} not ready')

        def patch(port, name):
            auth, csrf = login(port)
            code, card, h = request(port, 'GET', '/api/v1/assets/' + s['asset'], headers=auth)
            assert code == 200
            code, changed, _ = request(port, 'PATCH', '/api/v1/assets/' + s['asset'], {'display_name': name}, {**auth, 'Origin': s['origin'], 'X-CSRF-Token': csrf, 'If-Match': h['etag']})
            assert code == 200 and changed['business']['display_name'] == name, code
            return name

        def read(port):
            auth, _ = login(port)
            code, card, _ = request(port, 'GET', '/api/v1/assets/' + s['asset'], headers=auth)
            assert code == 200
            return card['business']['display_name']

        collector = s['sql']("SELECT source_id::text FROM sources.sources WHERE source_kind='collector' LIMIT 1")

        def heartbeat_after(t0, timeout=150):
            deadline = time.time() + timeout
            while time.time() < deadline:
                ok = sql(f"SELECT coalesce(max(last_contact_at) > to_timestamp({t0}), false) FROM sources.heartbeat_state WHERE source_id='{collector}'")
                if ok == 't':
                    return
                time.sleep(2)
            raise AssertionError('collector heartbeat not accepted')

        def swap_collector(binary, name):
            old = s['collector_process'] if not procs_collector else procs_collector[-1]
            args = open(f'/proc/{old.pid}/cmdline').read().split('\0')[:-1]
            old.terminate(); old.wait(timeout=10)
            log = (Path(s['directory']) / (name + '.log')).open('ab')
            p = subprocess.Popen([binary, *args[1:]], env=dict(os.environ), stdout=log, stderr=log)
            procs_collector.append(p)
            return p

        procs_collector = []
        port = s['center_port']
        try:
            before = len(sql('SELECT id FROM platform.schema_migrations').splitlines())
            r = subprocess.run([str(new / 'surveyscan-server'), 'migrate'], env=env, capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, r.stderr[-300:]
            after = len(sql('SELECT id FROM platform.schema_migrations').splitlines())
            assert s['center_process'].poll() is None
            assert patch(port, 'N-1 on N schema') == read(port)
            checks.append(f'N migrations ({before}→{after}) applied online under the running N-1 center; N-1 still reads and writes')
            # канарейка: api N рядом, своя копия machine.json с другим портом mTLS
            machine = json.loads(Path(env['SURVEYSCAN_V2_MACHINE_CONFIG']).read_text())
            canary_tls = freeport()
            machine['listen'] = f'127.0.0.1:{canary_tls}'
            mfile = Path(s['directory']) / 'machine-canary.json'
            mfile.write_text(json.dumps(machine)); mfile.chmod(0o600)
            log = (Path(s['directory']) / 'canary.log').open('ab')
            canary = subprocess.Popen([str(new / 'surveyscan-server'), 'serve'], env=dict(env, SURVEYSCAN_V2_ROLE='api', SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{freeport()}', SURVEYSCAN_V2_MACHINE_CONFIG=str(mfile)), stdout=log, stderr=log)
            procs.append(canary)
            ready(canary_tls)
            assert read(canary_tls) == 'N-1 on N schema'
            assert patch(canary_tls, 'written by N canary') == read(port)
            checks.append('canary N api beside N-1 on the same DB: N reads N-1 writes and N-1 reads N writes')
            # collector N на состоянии N-1
            t0 = time.time()
            swap_collector(str(new / 'surveyscan-collector'), 'collector-n')
            heartbeat_after(t0)
            checks.append('collector upgraded to N on N-1 state: heartbeat accepted by the N-1 center')
            # откат
            canary.terminate(); canary.wait(timeout=10)
            t0 = time.time()
            swap_collector(str(Path(old_root) / '.dist/surveyscan-collector'), 'collector-rollback')
            heartbeat_after(t0)
            assert read(port) == 'written by N canary' and patch(port, 'after rollback') == read(port)
            checks.append('rollback: N api stopped, collector back to N-1 on state touched by N; N-1 center serves data written by N and keeps writing')
            report = {'package': 'C40', 'task': 'C40.02', 'status': 'passed', 'previous_ref': PREVIOUS, 'count': len(checks), 'checks': checks,
                      'not_covered_here': ['schema downgrade (migrations are append-only; rollback = N-1 code on N schema)', 'agent N-1↔N skew (agent profile 1.2 unchanged in this range)', 'geo failover — ha_smoke (C38)', 'certificate rotation — CI TLS rotation steps']}
            (CURRENT / '.local/c40-canary-skew-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
            print(json.dumps(report, ensure_ascii=False))
        finally:
            for p in procs + procs_collector:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        p.kill()
    harness(web_scenario=scenario)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--fixture':
        fixture(Path(sys.argv[2]))
        return
    (CURRENT / '.local').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='c40-canary-', dir=CURRENT / '.local') as temp:
        work = Path(temp)
        archive = subprocess.check_output(['git', 'archive', PREVIOUS, 'v2'], cwd=CURRENT.parent)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(work, filter='data')
        old = work / 'v2'
        (old / '.local').mkdir(mode=0o700)
        shutil.copyfile(CURRENT / '.local/pg_password', old / '.local/pg_password')
        (old / '.local/pg_password').chmod(0o600)
        revision = subprocess.check_output(['git', 'rev-parse', PREVIOUS], cwd=CURRENT, text=True).strip()
        r = subprocess.run(['make', 'build', 'GO=' + os.environ.get('GO', 'go'), 'REVISION=' + revision], cwd=old, capture_output=True, timeout=300)
        assert r.returncode == 0, 'previous build failed'
        r = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--fixture', str(old)], cwd=old, capture_output=True, timeout=900)
        if r.returncode:
            sys.stderr.buffer.write(r.stderr[-4000:])
            raise AssertionError('canary/skew rehearsal failed')
        print(r.stdout.decode().strip().splitlines()[-1])


if __name__ == '__main__':
    main()
