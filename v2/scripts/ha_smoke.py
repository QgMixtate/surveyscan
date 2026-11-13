#!/usr/bin/env python3
"""C38.04 — HA PostgreSQL ячейки: писатель + потоковая реплика (два контейнера), центр со строкой на два узла
(target_session_attrs=read-write), surveyscan-router со сторожем писателей, поток подтверждённых записей через API.

Сценарии: (1) плановое переключение A→B; (2) потеря писателя B (kill) и переключение на A с -old-unreachable;
(3) возврат B после «разрыва» — сторож ограждает его, запись в B невозможна; (4) возврат (failback) на
пересозданный B. Для каждого: окно недоступности записи (RTO) и потерянные подтверждённые записи (RPO).
Отчёт с метками времени — .local/c38-ha-smoke.json. Секреты — только во временных файлах 0600 и окружении контейнеров.
"""
import http.cookiejar, json, os, secrets, socket, subprocess, tempfile, threading, time, urllib.error, urllib.request, uuid
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


def docker(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check, timeout=300).stdout.strip()


def main():
    initialize()
    suffix = uuid.uuid4().hex[:10]
    net, db_cat = 'c38-' + suffix, 'ssv2catalog_' + suffix
    names = {'a': 'c38a-' + suffix, 'b': 'c38b-' + suffix}
    ports = {'a': port(), 'b': port()}
    router_port, http_port = port(), port()
    origin = f'http://127.0.0.1:{router_port}'
    pg_password, password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    tenant = str(uuid.uuid4())
    report, procs, created = {'package': 'C38', 'task': 'C38.04', 'scenarios': []}, [], []

    def sql(query, database='surveyscan_v2'):
        return compose('exec', '-T', 'db', 'psql', '-U', 'surveyscan_v2', '-d', database, '-v', 'ON_ERROR_STOP=1', '-Atc', query, capture=True).strip()

    def node_sql(node, query, check=True):
        r = subprocess.run(['docker', 'exec', names[node], 'psql', '-U', 'postgres', '-d', 'surveyscan', '-Atc', query], capture_output=True, text=True, timeout=30)
        if check and r.returncode != 0:
            raise AssertionError((node, query, r.stderr[-300:]))
        return r.stdout.strip() if r.returncode == 0 else r.stderr

    def ready(node):
        for _ in range(240):
            if subprocess.run(['docker', 'exec', names[node], 'pg_isready', '-U', 'postgres', '-d', 'surveyscan'], capture_output=True).returncode == 0:
                return
            time.sleep(.5)
        raise AssertionError(node + ' not ready')

    def primary(node):
        docker('run', '-d', '--name', names[node], '--network', net, '-e', 'POSTGRES_PASSWORD=' + pg_password, '-e', 'POSTGRES_DB=surveyscan',
               '-p', f'127.0.0.1:{ports[node]}:5432', IMAGE)
        created.append(names[node])
        ready(node)
        time.sleep(1)
        ready(node)
        docker('exec', names[node], 'bash', '-c', "echo 'host replication all all scram-sha-256' >> /var/lib/postgresql/data/pg_hba.conf")
        node_sql(node, 'SELECT pg_reload_conf()')

    def replica(node, source):
        script = ('set -e; mkdir -p /var/lib/postgresql/standby; chown postgres /var/lib/postgresql/standby; '
                  f'gosu postgres pg_basebackup -h {names[source]} -U postgres -D /var/lib/postgresql/standby -R -X stream; '
                  'chmod 700 /var/lib/postgresql/standby; exec gosu postgres postgres -D /var/lib/postgresql/standby')
        docker('run', '-d', '--name', names[node], '--network', net, '-e', 'PGPASSWORD=' + pg_password,
               '-p', f'127.0.0.1:{ports[node]}:5432', '--entrypoint', 'bash', IMAGE, '-c', script)
        created.append(names[node])
        ready(node)
        assert node_sql(node, 'SELECT pg_is_in_recovery()') == 't'

    def remove(node):
        docker('rm', '-f', names[node], check=False)

    with tempfile.TemporaryDirectory(prefix='c38-', dir=STATE) as tmp:
        pw = private(tmp, 'pg', pg_password + '\n')
        user_pw = private(tmp, 'user', password + '\n')
        route_key = private(tmp, 'route.key', secrets.token_urlsafe(48) + '\n')
        both = f'postgres://postgres@127.0.0.1:{ports["a"]},127.0.0.1:{ports["b"]}/surveyscan?sslmode=disable&target_session_attrs=read-write&connect_timeout=3'
        env = dict(os.environ, SURVEYSCAN_V2_DATABASE_URL=both, SURVEYSCAN_V2_DATABASE_PASSWORD_FILE=pw, SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{http_port}',
                   SURVEYSCAN_V2_PUBLIC_ORIGIN=origin, SURVEYSCAN_V2_INSECURE_LOCAL_HTTP='1', SURVEYSCAN_V2_BAO_ADDR='http://127.0.0.1:58200')
        env.pop('SURVEYSCAN_V2_MACHINE_CONFIG', None)
        node_cfg = {n: {'database_url': f'postgres://postgres@127.0.0.1:{ports[n]}/surveyscan?sslmode=disable&connect_timeout=3', 'password_file': pw} for n in 'ab'}
        cfg = private(tmp, 'router.json', json.dumps({
            'listen': f'127.0.0.1:{router_port}', 'secure': False, 'route_key_file': route_key,
            'catalog': {'database_url': f'postgres://surveyscan_v2@127.0.0.1:55432/{db_cat}?sslmode=disable', 'password_file': str(STATE / 'pg_password')},
            'shards': {'cell-1': {'backend': f'http://127.0.0.1:{http_port}', 'database_url': both, 'password_file': pw, 'nodes': node_cfg}}}))

        def server(*args):
            r = subprocess.run([str(ROOT / '.dist/surveyscan-server'), *args], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
            assert r.returncode == 0, ('server console', args[0], r.stderr[-400:])
            return r.stdout

        def router(*args, want=0):
            r = subprocess.run([str(ROOT / '.dist/surveyscan-router'), args[0], '-config', cfg, *args[1:]], cwd=ROOT, capture_output=True, text=True, timeout=180)
            assert r.returncode == want, ('router', args, r.stdout[-400:], r.stderr[-400:])
            assert pg_password not in r.stdout + r.stderr and password not in r.stdout + r.stderr
            return r.stdout

        def start(name, args, e=None):
            log = (Path(tmp) / (name + '.log')).open('ab')
            p = subprocess.Popen(args, cwd=ROOT, env=e or os.environ, stdout=log, stderr=log)
            procs.append(p)
            return p

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        state = {'csrf': None}

        def api(method, path, data=None):
            h = {'Origin': origin}
            if state['csrf'] and method != 'GET':
                h['X-CSRF-Token'] = state['csrf']
            if data is not None:
                h['Content-Type'] = 'application/json'
            req = urllib.request.Request(origin + path, data=None if data is None else json.dumps(data).encode(), headers=h, method=method)
            try:
                with opener.open(req, timeout=8) as r:
                    return r.status, json.loads(r.read() or b'null')
            except urllib.error.HTTPError as e:
                e.read()
                return e.code, None
            except OSError:
                return 0, None

        acked, errors, stop_writes = [], [], threading.Event()

        def writer():
            n = 0
            while not stop_writes.is_set():
                n += 1
                code, body = api('POST', '/api/v1/subjects', {'kind': 'team', 'name': f'c38-{n}', 'contact': 'c38@example.invalid'})
                now = time.time()
                if code == 201:
                    acked.append((now, body.get('subject', body)['subject_id']))
                else:
                    errors.append((now, code))
                time.sleep(.05)

        def scenario(name, action, writer_node):
            t0 = time.time()
            info = action() or {}
            # окно: от начала действия до первой успешной записи после последней ошибки в окне
            deadline = time.time() + 120
            while time.time() < deadline:
                recent = [t for t, _ in errors if t >= t0]
                last_error = max(recent) if recent else None
                after = [t for t, _ in acked if t > (last_error or t0)]
                if after and time.time() - after[0] > 2:
                    break
                time.sleep(.2)
            recent = [t for t, _ in errors if t >= t0]
            first_ok = min([t for t, _ in acked if t > (max(recent) if recent else t0)], default=None)
            assert first_ok, name + ': writes did not resume'
            time.sleep(1)
            ids = [i for _, i in acked]
            present = set(node_sql(writer_node, f"SELECT subject_id::text FROM responsibility.subjects WHERE tenant_id='{tenant}'").split())
            lost = [i for i in ids if i not in present]
            rec = {'scenario': name, 'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t0)), 'write_unavailable_s': round(first_ok - t0, 2),
                   'failed_requests': len(recent), 'acknowledged_total': len(ids), 'acknowledged_lost': len(lost), **info}
            report['scenarios'].append(rec)
            print(json.dumps(rec, ensure_ascii=False), flush=True)
            return rec

        try:
            docker('network', 'create', net)
            created.append('network')
            primary('a')
            replica('b', 'a')
            sql(f'CREATE DATABASE {db_cat}')
            created.append(db_cat)
            server('migrate')
            server('bootstrap-admin', '--tenant', tenant, '--tenant-name', 'C38', '--username', 'admin', '--password-file', user_pw)
            router('init-catalog')
            router('add-shard', '-id', 'cell-1', '-region', 'ru-1')
            router('set-writer', '-shard', 'cell-1', '-node', 'a')
            router('place', '-tenant', tenant, '-shard', 'cell-1', '-home', 'ru-1', '-dr', 'ru-2')
            router('sync-logins')
            start('center', [str(ROOT / '.dist/surveyscan-server'), 'serve'], env)
            start('router', [str(ROOT / '.dist/surveyscan-router'), 'serve', '-config', cfg])
            for _ in range(150):
                try:
                    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(f'http://127.0.0.1:{http_port}/health/ready', timeout=2) as r:
                        if r.status == 200 and api('GET', '/router/health')[0] == 200:
                            break
                except OSError:
                    pass
                time.sleep(.2)
            else:
                raise AssertionError('center not ready: ' + (Path(tmp) / 'center.log').read_text()[-600:])
            code, body = api('POST', '/api/v1/auth/sessions', {'username': 'admin', 'password': password})
            assert code == 201, code
            state['csrf'] = body['csrf_token']
            th = threading.Thread(target=writer, daemon=True)
            th.start()
            time.sleep(3)
            assert acked, 'no writes before failover'

            r1 = scenario('planned switchover A→B (old writer reachable)', lambda: {'failover': json.loads(router('failover', '-shard', 'cell-1', '-to', 'b'))}, 'b')
            assert r1['acknowledged_lost'] == 0 and r1['failover']['old_fenced'] and r1['failover']['lag_bytes_at_promotion'] == 0
            ro = node_sql('a', "INSERT INTO responsibility.subjects(subject_id) VALUES (gen_random_uuid())", check=False)
            assert 'read-only' in ro, ro
            # A пересоздаётся репликой B
            remove('a')
            replica('a', 'b')

            def kill_b():
                docker('kill', names['b'])
                t = time.time()
                rep = json.loads(router('failover', '-shard', 'cell-1', '-to', 'a', '-old-unreachable'))
                return {'failover': rep, 'operator_decision_s': round(time.time() - t, 2)}
            r2 = scenario('writer loss: B killed, failover to A with -old-unreachable', kill_b, 'a')
            assert r2['failover']['old_unreachable'] and r2['failover']['outcome'] == 'promoted'

            def heal_b():
                t = time.time()
                docker('start', names['b'])
                ready('b')
                was = node_sql('b', 'SELECT pg_is_in_recovery()')
                deadline = time.time() + 30
                while time.time() < deadline and node_sql('b', "SELECT current_setting('default_transaction_read_only')") != 'on':
                    time.sleep(.3)
                fenced_after = round(time.time() - t, 2)
                assert node_sql('b', "SELECT current_setting('default_transaction_read_only')") == 'on', 'watchdog did not fence returning writer'
                ro = node_sql('b', "INSERT INTO responsibility.subjects(subject_id) VALUES (gen_random_uuid())", check=False)
                assert 'read-only' in ro, ro
                return {'returned_as_primary': was == 'f', 'fenced_by_watchdog_after_s': fenced_after}
            r3 = scenario('old writer B returns after partition: watchdog fences it', heal_b, 'a')
            assert r3['acknowledged_lost'] == r2['acknowledged_lost']
            remove('b')
            replica('b', 'a')
            lost_before = r3['acknowledged_lost']
            r4 = scenario('failback A→B onto rebuilt replica (planned)', lambda: {'failover': json.loads(router('failover', '-shard', 'cell-1', '-to', 'b'))}, 'b')
            assert r4['acknowledged_lost'] == lost_before and r4['failover']['lag_bytes_at_promotion'] == 0
            stop_writes.set()
            th.join(timeout=10)
            events = sql("SELECT string_agg(action,',' ORDER BY event_id) FROM catalog.events WHERE action LIKE 'shard.%'", db_cat)
            assert events.count('shard.writer.promoted') == 3 and 'shard.writer.fenced' in events, events
            report.update(status='passed', claims=['planned switchover and failback: 0 acknowledged writes lost (replica caught up before promotion)',
                                                   'writer loss with async replication: loss measured, not claimed zero',
                                                   'fenced writer rejects writes (read-only persisted across restart); returning writer fenced by watchdog'])
            (STATE / 'c38-ha-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
            print(json.dumps({'status': 'passed', 'scenarios': len(report['scenarios'])}))
        finally:
            stop_writes.set()
            for p in procs:
                p.terminate()
                try:
                    p.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    p.kill()
            for n in 'ab':
                remove(n)
            if 'network' in created:
                docker('network', 'rm', net, check=False)
            if db_cat in created:
                sql(f'DROP DATABASE IF EXISTS {db_cat} WITH (FORCE)')


main()
