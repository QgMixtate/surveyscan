#!/usr/bin/env python3
"""C37.04 — две ячейки на двух кластерах PostgreSQL за surveyscan-router: вход по каталогу, изоляция, перенос
организации (пробный и настоящий) с сохранением сессии и UID, работа после остановки прежней ячейки.

Ячейка A — БД в dev-PostgreSQL (55432), ячейка B — отдельный временный контейнер PostgreSQL 17; каталог — в
dev-PostgreSQL. Пароли — только во временных файлах 0600. Отчёт — .local/c37-shard-smoke.json.
"""
import http.cookiejar, json, os, secrets, socket, subprocess, tempfile, time, urllib.error, urllib.request, uuid
from pathlib import Path
from dev import compose, ROOT, STATE, initialize

IMAGE = 'postgres:17.11-bookworm@sha256:839fbb5a4942a7758dd93e18b42ea5649807491a0545b5eeeb8f0b8bb11857a5'


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def private(directory, name, text):
    p = Path(directory) / name
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    return str(p)


def main():
    initialize()
    checks, procs, created = [], [], []
    suffix = uuid.uuid4().hex[:12]
    db_a, db_cat, container = 'ssv2shard_a_' + suffix, 'ssv2catalog_' + suffix, 'ss-c37-pg-' + suffix
    tenant_a, tenant_b = str(uuid.uuid4()), str(uuid.uuid4())
    pg_b_port, router_port, http_a, http_b = port(), port(), port(), port()
    origin = f'http://127.0.0.1:{router_port}'
    password = secrets.token_urlsafe(24)

    def sql(query, database='surveyscan_v2'):
        return compose('exec', '-T', 'db', 'psql', '-U', 'surveyscan_v2', '-d', database, '-v', 'ON_ERROR_STOP=1', '-Atc', query, capture=True).strip()

    def sql_b(query):
        return subprocess.run(['docker', 'exec', container, 'psql', '-U', 'postgres', '-d', 'surveyscan', '-Atc', query], capture_output=True, text=True, check=True).stdout.strip()

    with tempfile.TemporaryDirectory(prefix='c37-', dir=STATE) as tmp:
        pg_b_password = secrets.token_urlsafe(24)
        pw_b = private(tmp, 'pg_b', pg_b_password + '\n')
        user_pw = private(tmp, 'user', password + '\n')
        route_key = private(tmp, 'route.key', secrets.token_urlsafe(48) + '\n')
        url_a = f'postgres://surveyscan_v2@127.0.0.1:55432/{db_a}?sslmode=disable'
        url_b = f'postgres://postgres@127.0.0.1:{pg_b_port}/surveyscan?sslmode=disable'
        envs = {
            'a': dict(os.environ, SURVEYSCAN_V2_DATABASE_URL=url_a, SURVEYSCAN_V2_DATABASE_PASSWORD_FILE=str(STATE / 'pg_password'), SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{http_a}'),
            'b': dict(os.environ, SURVEYSCAN_V2_DATABASE_URL=url_b, SURVEYSCAN_V2_DATABASE_PASSWORD_FILE=pw_b, SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{http_b}'),
        }
        for e in envs.values():
            e.update(SURVEYSCAN_V2_PUBLIC_ORIGIN=origin, SURVEYSCAN_V2_INSECURE_LOCAL_HTTP='1', SURVEYSCAN_V2_BAO_ADDR='http://127.0.0.1:58200')
            e.pop('SURVEYSCAN_V2_MACHINE_CONFIG', None)
        cfg = private(tmp, 'router.json', json.dumps({
            'listen': f'127.0.0.1:{router_port}', 'secure': False, 'route_key_file': route_key,
            'catalog': {'database_url': f'postgres://surveyscan_v2@127.0.0.1:55432/{db_cat}?sslmode=disable', 'password_file': str(STATE / 'pg_password')},
            'shards': {'cell-a': {'backend': f'http://127.0.0.1:{http_a}', 'database_url': url_a, 'password_file': str(STATE / 'pg_password')},
                       'cell-b': {'backend': f'http://127.0.0.1:{http_b}', 'database_url': url_b, 'password_file': pw_b}}}))

        def server(cell, *args):
            r = subprocess.run([str(ROOT / '.dist/surveyscan-server'), *args], cwd=ROOT, env=envs[cell], capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, ('server console', cell, args[0], r.stderr[-400:])
            assert password not in r.stdout + r.stderr
            return r.stdout

        def router(*args, want=0):
            r = subprocess.run([str(ROOT / '.dist/surveyscan-router'), args[0], '-config', cfg, *args[1:]], cwd=ROOT, capture_output=True, text=True, timeout=120)
            assert r.returncode == want, ('router', args[0], r.stderr[-400:])
            assert password not in r.stdout + r.stderr and pg_b_password not in r.stdout + r.stderr
            return r.stdout

        def start(name, args, env=None):
            log = (Path(tmp) / (name + '.log')).open('ab')
            p = subprocess.Popen(args, cwd=ROOT, env=env or os.environ, stdout=log, stderr=log)
            procs.append(p)
            return p

        def stop(p):
            p.terminate()
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=3)

        class Browser:
            def __init__(self):
                self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                self.csrf = None

            def __call__(self, method, path, data=None, base=origin):
                h = {'Origin': origin}
                if self.csrf and method != 'GET':
                    h['X-CSRF-Token'] = self.csrf
                if data is not None:
                    h['Content-Type'] = 'application/json'
                req = urllib.request.Request(base + path, data=None if data is None else json.dumps(data).encode(), headers=h, method=method)
                try:
                    with self.client.open(req, timeout=10) as r:
                        return r.status, json.loads(r.read() or b'null')
                except urllib.error.HTTPError as e:
                    body = e.read()
                    return e.code, (json.loads(body) if body[:1] == b'{' else None)

            def login(self, user):
                code, body = self('POST', '/api/v1/auth/sessions', {'username': user, 'password': password})
                assert code == 201, (user, code, body)
                self.csrf = body['csrf_token']

        def has(br, sid):
            code, body = br('GET', '/api/v1/subjects')
            assert code == 200, code
            items = body.get('items', body) if isinstance(body, dict) else body
            return any(x.get('subject_id') == sid for x in items)

        def ready(p):
            for _ in range(100):
                try:
                    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f'http://127.0.0.1:{p}/health/ready', timeout=2) as r:
                        if r.status == 200:
                            return
                except OSError:
                    pass
                time.sleep(.2)
            raise AssertionError(f'port {p} not ready')

        try:
            subprocess.run(['docker', 'run', '-d', '--name', container, '-e', 'POSTGRES_PASSWORD=' + pg_b_password, '-e', 'POSTGRES_DB=surveyscan',
                            '-p', f'127.0.0.1:{pg_b_port}:5432', IMAGE], check=True, capture_output=True)
            created.append('container')
            for _ in range(120):
                if subprocess.run(['docker', 'exec', container, 'pg_isready', '-U', 'postgres', '-d', 'surveyscan'], capture_output=True).returncode == 0:
                    break
                time.sleep(.5)
            time.sleep(1)
            sql(f'CREATE DATABASE {db_a}'); created.append(db_a)
            sql(f'CREATE DATABASE {db_cat}'); created.append(db_cat)
            for cell, t, user in (('a', tenant_a, 'alice'), ('b', tenant_b, 'bob')):
                server(cell, 'migrate')
                server(cell, 'bootstrap-admin', '--tenant', t, '--tenant-name', 'C37 ' + user, '--username', user, '--password-file', user_pw)
            checks.append('two cells on two PostgreSQL clusters: migrated, one organization each')
            router('init-catalog')
            router('add-shard', '-id', 'cell-a', '-region', 'ru-1')
            router('add-shard', '-id', 'cell-b', '-region', 'ru-1')
            router('place', '-tenant', tenant_a, '-shard', 'cell-a', '-home', 'ru-1')
            router('place', '-tenant', tenant_b, '-shard', 'cell-b', '-home', 'ru-1', '-dr', 'ru-2')
            assert json.loads(router('sync-logins')) == {'logins': 2, 'conflicts': 0}
            checks.append('catalog: shards, placements and login index synchronized from cells')
            cell_a = start('cell-a', [str(ROOT / '.dist/surveyscan-server'), 'serve'], envs['a'])
            start('cell-b', [str(ROOT / '.dist/surveyscan-server'), 'serve'], envs['b'])
            start('router', [str(ROOT / '.dist/surveyscan-router'), 'serve', '-config', cfg])
            ready(http_a); ready(http_b)
            for _ in range(50):
                try:
                    urllib.request.build_opener(urllib.request.ProxyHandler({})).open(origin + '/router/health', timeout=2)
                    break
                except OSError:
                    time.sleep(.2)
            alice, bob, stranger = Browser(), Browser(), Browser()
            alice.login('alice'); bob.login('bob')
            code, subject = alice('POST', '/api/v1/subjects', {'kind': 'team', 'name': 'C37 команда', 'contact': 'c37@example.invalid'})
            assert code == 201, (code, subject)
            subject = subject.get('subject', subject)
            sid = subject['subject_id']
            assert has(alice, sid) and not has(bob, sid)
            assert stranger('GET', '/api/v1/subjects')[0] == 401
            code, _ = stranger('POST', '/api/v1/auth/sessions', {'username': 'nobody', 'password': 'x'})
            assert code == 401
            checks.append('login routed by catalog; organizations isolated; no route cookie → 401; unknown login → 401')

            dry = json.loads(router('move-tenant', '-tenant', tenant_a, '-to', 'cell-b', '-dry-run'))
            assert dry['outcome'] == 'dry_run_ok' and dry['rows_copied'] > 0, dry
            assert sql_b(f"SELECT count(*) FROM access.tenants WHERE tenant_id='{tenant_a}'") == '0'
            checks.append(f"dry run: {dry['rows_copied']} rows copied in {dry['fence_window_ns'] / 1e9:.2f}s and removed from target")
            moved = json.loads(router('move-tenant', '-tenant', tenant_a, '-to', 'cell-b'))
            assert moved['outcome'] == 'moved' and moved['epoch'] == 2 and moved['tables'], moved
            assert sql(f"SELECT status FROM access.tenants WHERE tenant_id='{tenant_a}'", db_a) == 'disabled'
            checks.append(f"move: {moved['rows_copied']} rows, {len(moved['tables'])} tables verified (count+hash), fence window {moved['fence_window_ns'] / 1e9:.2f}s, epoch 2; source disabled")
            stop(cell_a)
            time.sleep(3)  # кэш размещений маршрутизатора ≤ 2 с
            assert has(alice, sid)
            code, _ = alice('PATCH', '/api/v1/subjects/' + sid, {'name': 'C37 после переноса', 'revision': subject['revision']})
            assert code == 200, code
            assert not has(bob, sid)
            fresh = Browser(); fresh.login('alice')
            summary = json.loads(router('summary'))
            shards = {x['shard_id']: x for x in summary['shards']}
            assert summary['complete'] and not summary['duplicate_asset_uids'] and not summary['misplaced_tenants'], summary
            assert shards['cell-a']['disabled_tenants'] == 1 and shards['cell-a']['active_tenants'] == 0 and shards['cell-b']['active_tenants'] == 2, summary
            checks.append('cell A stopped: same session and route cookie keep working in cell B; subject UID kept; write works; re-login works; isolation kept; cross-shard summary complete, no duplicate UIDs or misplaced tenants')
            report = {'package': 'C37', 'task': 'C37.04', 'status': 'passed', 'count': len(checks), 'checks': checks}
            (STATE / 'c37-shard-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
            print(json.dumps(report, ensure_ascii=False))
        finally:
            for p in procs:
                if p.poll() is None:
                    stop(p)
            if 'container' in created:
                subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
            for db in (db_a, db_cat):
                if db in created:
                    sql(f'DROP DATABASE IF EXISTS {db} WITH (FORCE)')


main()
