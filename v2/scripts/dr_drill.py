#!/usr/bin/env python3
"""C39.04 — учения DR для компонентов E5: ячейка (центр + PostgreSQL), каталог организаций и surveyscan-router.

Исходная среда: ячейка в отдельном кластере PostgreSQL (контейнер), каталог в dev-PostgreSQL, маршрутизатор, данные
через API. Согласованный DR-набор при остановленных писателях: дамп БД ячейки, дамп каталога, конфигурация
маршрутизатора и ключ подписи маршрутов (приватные файлы), манифест SHA-256. Затем исходная среда уничтожается
целиком (контейнер, БД каталога, процессы) и восстанавливается в **новый** кластер и новую БД каталога на других
портах; к старой среде обращений нет (её больше нет). Проверки: те же строки (число + хеш по каждой таблице),
вход с сессией, выданной до копии, UID, запись. Замер — время восстановления (RTO) и потеря (RPO = 0 для
остановленного набора). OpenBao и агенты/collector — учения C13 (bao_restore_smoke, checkpoint_smoke).
Отчёт — .local/c39-dr-drill.json.
"""
import hashlib, http.cookiejar, json, os, secrets, socket, subprocess, tempfile, time, urllib.error, urllib.request, uuid
from pathlib import Path
from dev import compose, ROOT, STATE, initialize

IMAGE = 'postgres:17.11-bookworm@sha256:839fbb5a4942a7758dd93e18b42ea5649807491a0545b5eeeb8f0b8bb11857a5'
TABLES = """SELECT string_agg(format('%I.%I',table_schema,table_name),' ' ORDER BY 1) FROM information_schema.tables
WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema')"""


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def private(directory, name, data):
    p = Path(directory) / name
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    return str(p)


def main():
    initialize()
    sfx = uuid.uuid4().hex[:10]
    tenant, pg_password, password = str(uuid.uuid4()), secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    checks, procs, live = [], [], {'containers': [], 'dbs': []}

    def docker(*a, check=True, inp=None):
        r = subprocess.run(['docker', *a], capture_output=True, check=False, timeout=600, input=inp)
        if check and r.returncode:
            raise AssertionError(('docker', a[:2], r.stderr[-300:]))
        return r.stdout

    def dev_sql(q, db='surveyscan_v2'):
        return compose('exec', '-T', 'db', 'psql', '-U', 'surveyscan_v2', '-d', db, '-v', 'ON_ERROR_STOP=1', '-Atc', q, capture=True).strip()

    def cell_sql(name, q):
        return docker('exec', name, 'psql', '-U', 'postgres', '-d', 'surveyscan', '-v', 'ON_ERROR_STOP=1', '-Atc', q).decode().strip()

    def fingerprint(run):
        out = {}
        for t in run(TABLES).split():
            out[t] = run(f"SELECT count(*)||':'||md5(coalesce(string_agg(x::text,E'\\n' ORDER BY x::text),'')) FROM {t} x")
        return out

    def cluster(name, p):
        docker('run', '-d', '--name', name, '-e', 'POSTGRES_PASSWORD=' + pg_password, '-e', 'POSTGRES_DB=surveyscan', '-p', f'127.0.0.1:{p}:5432', IMAGE)
        live['containers'].append(name)
        for _ in range(240):
            if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres', '-d', 'surveyscan'], capture_output=True).returncode == 0:
                break
            time.sleep(.5)
        time.sleep(1.5)

    def stop(p):
        p.terminate()
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()

    with tempfile.TemporaryDirectory(prefix='c39-', dir=STATE) as tmp, tempfile.TemporaryDirectory(prefix='c39-set-', dir=STATE) as drset:
        pw = private(tmp, 'pg', pg_password + '\n')
        user_pw = private(tmp, 'user', password + '\n')

        def environment(tag, cell_port, catalog_db, route_key_file):
            http_port, router_port = port(), port()
            origin = f'http://127.0.0.1:{router_port}'
            url = f'postgres://postgres@127.0.0.1:{cell_port}/surveyscan?sslmode=disable'
            env = dict(os.environ, SURVEYSCAN_V2_DATABASE_URL=url, SURVEYSCAN_V2_DATABASE_PASSWORD_FILE=pw, SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{http_port}',
                       SURVEYSCAN_V2_PUBLIC_ORIGIN=origin, SURVEYSCAN_V2_INSECURE_LOCAL_HTTP='1', SURVEYSCAN_V2_BAO_ADDR='http://127.0.0.1:58200')
            env.pop('SURVEYSCAN_V2_MACHINE_CONFIG', None)
            cfg = private(tmp, f'router-{tag}.json', json.dumps({
                'listen': f'127.0.0.1:{router_port}', 'secure': False, 'route_key_file': route_key_file,
                'catalog': {'database_url': f'postgres://surveyscan_v2@127.0.0.1:55432/{catalog_db}?sslmode=disable', 'password_file': str(STATE / 'pg_password')},
                'shards': {'cell-1': {'backend': f'http://127.0.0.1:{http_port}', 'database_url': url, 'password_file': pw}}}))
            return {'env': env, 'cfg': cfg, 'origin': origin, 'http': http_port}

        def server(e, *a):
            r = subprocess.run([str(ROOT / '.dist/surveyscan-server'), *a], cwd=ROOT, env=e['env'], capture_output=True, text=True, timeout=120)
            assert r.returncode == 0, ('server', a[0], r.stderr[-300:])
            return r.stdout

        def router(e, *a):
            r = subprocess.run([str(ROOT / '.dist/surveyscan-router'), a[0], '-config', e['cfg'], *a[1:]], cwd=ROOT, capture_output=True, text=True, timeout=120)
            assert r.returncode == 0, ('router', a[0], r.stderr[-300:])
            return r.stdout

        def serve(e, tag):
            for name, args, env in ((f'center-{tag}', [str(ROOT / '.dist/surveyscan-server'), 'serve'], e['env']),
                                    (f'router-{tag}', [str(ROOT / '.dist/surveyscan-router'), 'serve', '-config', e['cfg']], os.environ)):
                log = (Path(tmp) / (name + '.log')).open('ab')
                procs.append(subprocess.Popen(args, cwd=ROOT, env=env, stdout=log, stderr=log))
            plain = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for _ in range(200):
                try:
                    with plain.open(f"http://127.0.0.1:{e['http']}/health/ready", timeout=2) as r1, plain.open(e['origin'] + '/router/health', timeout=2) as r2:
                        if r1.status == 200 and r2.status == 200:
                            return
                except OSError:
                    pass
                time.sleep(.1)
            raise AssertionError('environment not ready')

        class Client:
            def __init__(self, origin, jar=None):
                self.origin, self.jar, self.csrf = origin, jar or http.cookiejar.CookieJar(), None
                self.op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.jar))

            def __call__(self, method, path, data=None):
                h = {'Origin': self.origin}
                if self.csrf and method != 'GET':
                    h['X-CSRF-Token'] = self.csrf
                if data is not None:
                    h['Content-Type'] = 'application/json'
                req = urllib.request.Request(self.origin + path, None if data is None else json.dumps(data).encode(), h, method=method)
                try:
                    with self.op.open(req, timeout=8) as r:
                        return r.status, json.loads(r.read() or b'null')
                except urllib.error.HTTPError as err:
                    err.read()
                    return err.code, None

        try:
            # исходная среда
            src_cell, src_port, src_cat = 'c39-src-' + sfx, port(), 'ssv2c39src_' + sfx
            cluster(src_cell, src_port)
            dev_sql(f'CREATE DATABASE {src_cat}'); live['dbs'].append(src_cat)
            key = private(tmp, 'route.key', secrets.token_urlsafe(48) + '\n')
            src = environment('src', src_port, src_cat, key)
            server(src, 'migrate')
            server(src, 'bootstrap-admin', '--tenant', tenant, '--tenant-name', 'C39', '--username', 'admin', '--password-file', user_pw)
            for a in (('init-catalog',), ('add-shard', '-id', 'cell-1', '-region', 'ru-1'), ('place', '-tenant', tenant, '-shard', 'cell-1', '-home', 'ru-1', '-dr', 'ru-2'), ('sync-logins',)):
                router(src, *a)
            serve(src, 'src')
            c = Client(src['origin'])
            code, body = c('POST', '/api/v1/auth/sessions', {'username': 'admin', 'password': password})
            assert code == 201
            c.csrf = body['csrf_token']
            uids = []
            for i in range(20):
                code, body = c('POST', '/api/v1/subjects', {'kind': 'team', 'name': f'C39-{i}', 'contact': 'c39@example.invalid'})
                assert code == 201, code
                uids.append(body.get('subject', body)['subject_id'])
            checks.append('source: cell on its own PostgreSQL cluster, catalog, router; 20 subjects and a session created via API')
            # согласованный набор: писатели остановлены
            for p in procs:
                stop(p)
            procs.clear()
            before = fingerprint(lambda q: cell_sql(src_cell, q))
            cat_before = fingerprint(lambda q: dev_sql(q, src_cat))
            files = {
                'cell.sql': docker('exec', src_cell, 'pg_dump', '-U', 'postgres', '-d', 'surveyscan', '--no-owner', '--no-privileges'),
                'catalog.sql': compose('exec', '-T', 'db', 'pg_dump', '-U', 'surveyscan_v2', '-d', src_cat, '--no-owner', '--no-privileges', capture=True).encode(),
                'route.key': Path(key).read_bytes(),
                'router.json': Path(src['cfg']).read_bytes(),
            }
            manifest = {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}
            for n, b in files.items():
                private(drset, n, b)
            private(drset, 'manifest.json', json.dumps({'tenant_shards': {tenant: 'cell-1'}, 'files': manifest, 'writers_quiesced': True}))
            checks.append(f'DR set taken with writers stopped: {len(files)} files + manifest ({sum(len(b) for b in files.values())} bytes), private 0600')
            # исходная среда уничтожена
            docker('rm', '-f', src_cell)
            live['containers'].remove(src_cell)
            dev_sql(f'DROP DATABASE {src_cat} WITH (FORCE)')
            live['dbs'].remove(src_cat)
            Path(key).unlink()
            # восстановление в новую среду
            t0 = time.time()
            m = json.loads(Path(drset, 'manifest.json').read_text())
            for n, h in m['files'].items():
                assert hashlib.sha256(Path(drset, n).read_bytes()).hexdigest() == h, 'DR set corrupted: ' + n
            dst_cell, dst_port, dst_cat = 'c39-dst-' + sfx, port(), 'ssv2c39dst_' + sfx
            cluster(dst_cell, dst_port)
            docker('exec', '-i', dst_cell, 'psql', '-U', 'postgres', '-d', 'surveyscan', '-v', 'ON_ERROR_STOP=1', '-q', inp=Path(drset, 'cell.sql').read_bytes())
            dev_sql(f'CREATE DATABASE {dst_cat}'); live['dbs'].append(dst_cat)
            dev_db = compose('ps', '-q', 'db', capture=True).strip()
            docker('exec', '-i', dev_db, 'psql', '-U', 'surveyscan_v2', '-d', dst_cat, '-v', 'ON_ERROR_STOP=1', '-q', inp=Path(drset, 'catalog.sql').read_bytes())
            dst = environment('dst', dst_port, dst_cat, str(Path(drset, 'route.key')))
            assert 'applied_migrations=0' in server(dst, 'migrate')
            serve(dst, 'dst')
            # сессия, выданная до копии: те же cookie (сессия + маршрут) на новый адрес
            restored = Client(dst['origin'])
            for ck in c.jar:
                restored.jar.set_cookie(http.cookiejar.Cookie(0, ck.name, ck.value, None, False, '127.0.0.1', False, False, '/', True, False, None, False, None, None, {}))
            restored.csrf = c.csrf
            code, body = restored('GET', '/api/v1/subjects')
            rto = time.time() - t0
            assert code == 200, code
            got = {x['subject_id'] for x in (body.get('items', body) if isinstance(body, dict) else body)}
            assert set(uids) <= got, 'subjects lost'
            checks.append(f'restored into a new cluster and catalog DB (old environment destroyed): pre-backup session and route cookie accepted, all 20 UIDs present; RTO {rto:.1f}s')
            after = fingerprint(lambda q: cell_sql(dst_cell, q))
            assert after == before, [t for t in before if before[t] != after.get(t)]
            assert fingerprint(lambda q: dev_sql(q, dst_cat)) == cat_before
            checks.append(f'every table identical after restore (count + hash): cell {len(before)} tables, catalog {len(cat_before)} tables; RPO 0 for the quiesced set')
            code, _ = restored('POST', '/api/v1/subjects', {'kind': 'team', 'name': 'C39 после DR', 'contact': 'c39@example.invalid'})
            assert code == 201, code
            fresh = Client(dst['origin'])
            assert fresh('POST', '/api/v1/auth/sessions', {'username': 'admin', 'password': password})[0] == 201
            checks.append('writes and new login work in the restored environment')
            report = {'package': 'C39', 'task': 'C39.04', 'status': 'passed', 'rto_seconds': round(rto, 1), 'rpo': 'zero (writers quiesced)', 'count': len(checks), 'checks': checks,
                      'not_covered_here': ['OpenBao Raft restore — bao_restore_smoke (C13)', 'agent/collector queues and replay without duplicates — checkpoint_smoke (C13)', 'search index — rebuilt from PostgreSQL on start']}
            (STATE / 'c39-dr-drill.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
            print(json.dumps(report, ensure_ascii=False))
        finally:
            for p in procs:
                stop(p)
            for n in live['containers']:
                subprocess.run(['docker', 'rm', '-f', n], capture_output=True)
            for d in live['dbs']:
                dev_sql(f'DROP DATABASE IF EXISTS {d} WITH (FORCE)')


main()
