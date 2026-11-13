#!/usr/bin/env python3
"""C30.02/C30.03 — прогон паспорта «100 активных пользователей» на настоящем центре (обвязка machine_smoke).

Готовит данные (portable-пакеты 1.2, пользователи, субъекты, сервисы и связи), ждёт индекс поиска, запускает генератор
нагрузки, параллельно — фоновый импорт и съём ресурсов/очередей. Отчёт — OUT/report.json.
Окружение: SURVEYSCAN_LOAD_ASSETS (2000), SURVEYSCAN_SEARCH_BIN (сервис поиска), LOADGEN (бинарник генератора).
"""
import http.client, json, os, re, ssl, subprocess, sys, tempfile, threading, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from machine_smoke import main as harness, freeport  # noqa: E402
from dev import ROOT  # noqa: E402

OUT = Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
N = int(os.environ.get('SURVEYSCAN_LOAD_ASSETS', '2000'))
DURATION, WARMUP = float(os.environ.get('SURVEYSCAN_LOAD_SECONDS', '300')), float(os.environ.get('SURVEYSCAN_LOAD_WARMUP', '60'))
PORTABLE = str(ROOT / '.dist/surveyscan-portable')


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


DIST = os.environ.get('SURVEYSCAN_LOAD_DIST') == '1'  # C40.01: маршрутизатор C37 → 2 api → worker (C35)
SPLIT = os.environ.get('SURVEYSCAN_LOAD_SPLIT') == '1' or DIST  # C35.04: центр обвязки — api, фоновая работа — отдельный worker
if SPLIT:
    os.environ['SURVEYSCAN_V2_ROLE'] = 'api'


def scenario(**s):
    work = Path(tempfile.mkdtemp(prefix='c30-'))
    if os.environ.get('SURVEYSCAN_LOAD_PROFILE') == '1':  # C36.02: профиль запросов (нужен shared_preload_libraries)
        s['sql']('CREATE EXTENSION IF NOT EXISTS pg_stat_statements')
    if SPLIT:
        wlog = (Path(s['directory']) / 'worker.log').open('ab')
        worker = subprocess.Popen([str(ROOT / '.dist/surveyscan-server'), 'serve'], cwd=ROOT, stdout=wlog, stderr=wlog,
                                  env=dict(s['server_environment'], SURVEYSCAN_V2_ROLE='worker', SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{freeport()}'))
        import atexit
        atexit.register(worker.terminate)
        log('split mode: api (harness center) + worker pid', worker.pid)
    sql, command, tenant = s['sql'], s['command'], s['tenant']
    site, scope = sql("SELECT site_id::text||' '||scope_id::text FROM scope.network_scopes LIMIT 1").split()
    ctx = ssl.create_default_context(cafile=s['ca_file'])

    def api(method, path, body=None, cookie=None, csrf=None):
        c = http.client.HTTPSConnection('127.0.0.1', s['center_port'], context=ctx, timeout=120)
        h = {'Origin': s['origin'], 'Content-Type': 'application/json'}
        if cookie:
            h['Cookie'] = cookie
        if csrf:
            h['X-CSRF-Token'] = csrf
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse(); raw = r.read(); c.close()
        return r.status, (json.loads(raw) if raw else None), r.getheader('Set-Cookie')

    # 1. данные: portable-источник и пакеты (основной — N хостов, фоновые — 6×50)
    o = subprocess.run([PORTABLE, 'init', '--state', str(work / 'state'), '--tenant', tenant, '--site', site, '--scope', scope], capture_output=True, text=True, check=True)
    source = re.search(r'source_id=(\S+)', o.stdout).group(1); public = re.search(r'public_key=(\S+)', o.stdout).group(1)
    gen = [m.group(1) for m in (re.search(r'"generation_id"\s*:\s*"([0-9a-f-]{36})"', f.read_text()) for f in (work / 'state').rglob('*.json')) if m][0]
    def importing(pkg):  # консольная команда обвязки ограничена 30 с — импорт 1.2-пакета идёт дольше
        r = subprocess.run([str(ROOT / '.dist/surveyscan-server'), 'portable-import', '--tenant', tenant, '--source', source, '--package', str(pkg)],
                           env=s['server_environment'], capture_output=True, text=True, timeout=7200)
        if r.returncode != 0:
            raise SystemExit('import failed: ' + r.stderr[-500:])
    command('portable-register', '--tenant', tenant, '--site', site, '--scope', scope, '--source', source, '--generation', gen, '--public-key', public)

    def package(name, count):
        env = dict(os.environ, SURVEYSCAN_BIGPKG_STATE=str(work / 'state'), SURVEYSCAN_BIGPKG_OUT=str(work / name), SURVEYSCAN_BIGPKG_COUNT=str(count))
        subprocess.run(['go', 'test', '-count=1', '-run', '^TestWriteBigPackage$', './internal/portableaudit'], cwd=ROOT, env=env, check=True, capture_output=True, timeout=1800)
        return work / name
    started = time.time()  # пакеты по 1 000 хостов: пакет на 2 000 упирается в предел импорта portable
    mains = [package(f'main{i}.zip', min(1000, N - i * 1000)) for i in range((N + 999) // 1000)]
    log('packages', N, 'hosts', sum(p.stat().st_size for p in mains) // 1048576, 'MiB', round(time.time() - started), 's')
    background = [package(f'bg{i}.zip', 50) for i in range(6)]
    started = time.time()
    for p in mains:
        importing(p)
    log('import', round(time.time() - started), 's')

    # 2. пользователи, оргструктура, сервисы
    pw = work / 'pw'; pw.write_text('load test passphrase C30 synthetic\n'); os.chmod(pw, 0o600)
    users = []
    for i in range(100):
        role = 'admin' if i < 5 else 'viewer' if i >= 85 else 'operator'
        command('create-user', '--tenant', tenant, '--username', f'load{i:03d}', '--role', role, '--password-file', str(pw))
        users.append({'Username': f'load{i:03d}', 'Password': pw.read_text().strip(), 'Role': role})
    status, sess, cookie = api('POST', '/api/v1/auth/sessions', {'username': s['username'], 'password': s['password']})
    cookie, csrf = cookie.split(';', 1)[0], sess['csrf_token']
    assets, cursor = [], None
    while True:
        st, page, _ = api('GET', '/api/v1/assets?limit=200' + ('&cursor=' + cursor if cursor else ''), cookie=cookie)
        assets += [a['asset_uid'] for a in page['items']]; cursor = page['next_cursor']
        if not cursor:
            break
    subjects = []
    for i in range(100):
        kind = 'team' if i % 10 == 0 else 'person'
        body = {'kind': kind, 'name': f'Субъект {i:03d}', 'contact': f's{i}@example.test'}
        if kind == 'person' and i < 85:
            body['username'] = f'load{i:03d}'
        st, r, _ = api('POST', '/api/v1/subjects', body, cookie, csrf); assert st == 201, (st, r)
        subjects.append(r['subject']['subject_id'])
    for i in range(50):
        st, r, _ = api('POST', '/api/v1/services', {'name': f'Сервис {i:02d}', 'criticality': 'medium'}, cookie, csrf); assert st == 201
        for a in assets[i * 20:i * 20 + 5]:
            api('POST', '/api/v1/relations', {'relation_type': 'runs_on', 'from': {'kind': 'service', 'id': r['service_uid']}, 'to': {'kind': 'asset', 'id': a}}, cookie, csrf)
    log('data ready: assets', len(assets), 'users', len(users), 'subjects', len(subjects))
    # индекс поиска догнал outbox
    for _ in range(600):
        lag = int(sql("SELECT count(*) FROM messaging.outbox_events e WHERE NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='search-index' AND c.state='applied')"))
        if lag == 0 or not os.environ.get('SURVEYSCAN_SEARCH_BIN'):
            break
        time.sleep(2)
    log('search lag before run', lag)

    # 3. нагрузка + фоновый импорт + съём ресурсов
    hostname = sql(f"SELECT value #>> '{{}}' FROM inventory.record_facts12 WHERE section_name='identity' AND field_name='hostname' LIMIT 1")
    base = f"https://127.0.0.1:{s['center_port']}"
    if DIST:
        import atexit, secrets
        env = s['server_environment']
        api2 = freeport()
        alog = (Path(s['directory']) / 'api2.log').open('ab')
        env2 = dict(env, SURVEYSCAN_V2_ROLE='api', SURVEYSCAN_V2_LISTEN=f'127.0.0.1:{api2}')
        machine = json.loads(Path(env['SURVEYSCAN_V2_MACHINE_CONFIG']).read_text())  # та же конфигурация (поиск, 1.2), свой порт mTLS (как split_smoke)
        machine['listen'] = f'127.0.0.1:{freeport()}'
        (work / 'machine-api2.json').write_text(json.dumps(machine)); os.chmod(work / 'machine-api2.json', 0o600)
        env2['SURVEYSCAN_V2_MACHINE_CONFIG'] = str(work / 'machine-api2.json')
        p2 = subprocess.Popen([str(ROOT / '.dist/surveyscan-server'), 'serve'], cwd=ROOT, stdout=alog, stderr=alog, env=env2)
        atexit.register(p2.terminate)
        for _ in range(150):
            try:
                c = http.client.HTTPConnection('127.0.0.1', api2, timeout=2); c.request('GET', '/health/ready')
                if c.getresponse().status == 200:
                    break
            except OSError:
                pass
            time.sleep(.2)
        else:
            raise SystemExit('second api did not start')
        catalog = 'ssv2c40cat_' + secrets.token_hex(6)
        sql('CREATE DATABASE ' + catalog)
        from dev import compose
        atexit.register(lambda: compose('exec', '-T', 'db', 'psql', '-U', 'surveyscan_v2', '-d', 'surveyscan_v2', '-Atc', f'DROP DATABASE IF EXISTS {catalog} WITH (FORCE)', capture=True))
        key = work / 'route.key'; key.write_text(secrets.token_urlsafe(48)); os.chmod(key, 0o600)
        listen = s['origin'].removeprefix('http://')
        rcfg = {'listen': listen, 'secure': False, 'route_key_file': str(key),
                'catalog': {'database_url': re.sub(r'/[^/?]+\?', f'/{catalog}?', env['SURVEYSCAN_V2_DATABASE_URL'], count=1), 'password_file': env['SURVEYSCAN_V2_DATABASE_PASSWORD_FILE']},
                'shards': {'cell-1': {'backend': 'http://' + env['SURVEYSCAN_V2_LISTEN'], 'backends': [f'http://127.0.0.1:{api2}'],
                                      'database_url': env['SURVEYSCAN_V2_DATABASE_URL'], 'password_file': env['SURVEYSCAN_V2_DATABASE_PASSWORD_FILE']}}}
        (work / 'router.json').write_text(json.dumps(rcfg)); os.chmod(work / 'router.json', 0o600)
        rt = lambda *a: subprocess.run([str(ROOT / '.dist/surveyscan-router'), a[0], '-config', str(work / 'router.json'), *a[1:]], check=True, capture_output=True, text=True)
        for a in (('init-catalog',), ('add-shard', '-id', 'cell-1', '-region', 'ru-1'), ('place', '-tenant', tenant, '-shard', 'cell-1', '-home', 'ru-1'), ('sync-logins',)):
            rt(*a)
        rlog = (Path(s['directory']) / 'router.log').open('ab')
        pr = subprocess.Popen([str(ROOT / '.dist/surveyscan-router'), 'serve', '-config', str(work / 'router.json')], cwd=ROOT, stdout=rlog, stderr=rlog)
        atexit.register(pr.terminate)
        for _ in range(100):
            try:
                if http.client.HTTPConnection(listen.split(':')[0], int(listen.split(':')[1]), timeout=2).request('GET', '/router/health') is None:
                    break
            except OSError:
                time.sleep(.2)
        time.sleep(2)
        base = s['origin']
        log('distributed: router', listen, '→ api', env['SURVEYSCAN_V2_LISTEN'], '+ api', api2, '+ worker')
    cfg = {'base_url': base, 'ca_file': s['ca_file'], 'origin': s['origin'], 'users': users, 'assets': assets, 'subjects': subjects,
           'searches': ['openssl', 'python3', 'systemd', 'bigpkg', hostname, 'Сервис 07', 'назначения', 'libssl3', 'curl', 'ubuntu'],
           'virtual_users': 100, 'warmup_seconds': WARMUP, 'duration_seconds': DURATION, 'think_min_seconds': 2, 'think_max_seconds': 6, 'seed': 20261112,
           'mix': {'list': 25, 'card': 20, 'search': 15, 'software': 10, 'section12': 5, 'worklist': 5, 'topology': 5, 'edit': 10, 'assign': 5}}
    (work / 'load.json').write_text(json.dumps(cfg)); os.chmod(work / 'load.json', 0o600)
    stop = threading.Event(); samples, imports = [], []
    center = s['center_process'].pid
    pid_file = Path(s['directory']) / 'search.pid'
    search_pid = [pid_file.read_text().strip()] if pid_file.exists() else []
    db = sql('SELECT current_database()')

    def proc(pid):
        try:
            st = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            rss = [int(x.split()[1]) for x in Path(f'/proc/{pid}/status').read_text().splitlines() if x.startswith('VmRSS')][0]
            return (int(st[11]) + int(st[12])) / os.sysconf('SC_CLK_TCK'), rss // 1024
        except (OSError, IndexError):
            return None, None

    sampler_errors = []

    def sampler():
        while not stop.is_set():
          try:
            c_cpu, c_rss = proc(center)
            q_cpu, q_rss = proc(search_pid[0]) if search_pid else (None, None)
            row = sql(f"""SELECT (SELECT count(*) FROM pg_stat_activity WHERE datname='{db}'),(SELECT count(*) FROM pg_stat_activity WHERE datname='{db}' AND state='active'),
(SELECT count(*) FROM messaging.outbox_events e WHERE NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='registry-version' AND c.state='applied')),
(SELECT count(*) FROM messaging.outbox_events e WHERE NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='search-index' AND c.state='applied')),
(SELECT COALESCE(EXTRACT(EPOCH FROM now()-min(e.occurred_at)),0) FROM messaging.outbox_events e WHERE NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='registry-version' AND c.state='applied'))""").split('|')
            samples.append({'t': time.time(), 'center_cpu_s': c_cpu, 'center_rss_mib': c_rss, 'search_cpu_s': q_cpu, 'search_rss_mib': q_rss,
                            'pg_connections': int(row[0]), 'pg_active': int(row[1]), 'outbox_pending': int(row[2]), 'search_pending': int(row[3]), 'outbox_oldest_s': float(row[4])})
          except Exception as e:  # фиксируем, а не теряем поток съёма
            sampler_errors.append(str(e)[:200])
          stop.wait(5)

    def importer():
        stop.wait(WARMUP)
        for pkg in background:
            if stop.is_set():
                return
            t0 = time.time()
            importing(pkg)
            imports.append(round(time.time() - t0, 1))
            stop.wait(60)
    threads = [threading.Thread(target=sampler, daemon=True), threading.Thread(target=importer, daemon=True)]
    for t in threads:
        t.start()
    started = time.time()
    if os.environ.get('SURVEYSCAN_LOAD_PROFILE') == '1':
        s['sql']('SELECT pg_stat_statements_reset()')  # профиль — только запросы нагрузки, без подготовки данных
    r = subprocess.run([os.environ['LOADGEN'], str(work / 'load.json')], capture_output=True, text=True, timeout=int(WARMUP + DURATION + 600))
    stop.set()
    for t in threads:
        t.join(timeout=600)
    if r.returncode != 0:
        raise SystemExit('loadgen failed: ' + r.stderr[-2000:])
    result = json.loads(r.stdout)
    measured = [x for x in samples if x['t'] >= started + WARMUP]

    def cpu(key):
        pts = [x for x in measured if x[key] is not None]
        return round((pts[-1][key] - pts[0][key]) / (pts[-1]['t'] - pts[0]['t']) * 100, 1) if len(pts) > 1 else None
    resources = {'center_cpu_percent_of_one_core': cpu('center_cpu_s'), 'search_cpu_percent_of_one_core': cpu('search_cpu_s'),
                 'center_rss_mib_max': max((x['center_rss_mib'] or 0) for x in measured) if measured else None,
                 'search_rss_mib_max': max((x['search_rss_mib'] or 0) for x in measured) if measured else None,
                 'pg_connections_max': max(x['pg_connections'] for x in measured) if measured else None,
                 'pg_active_max': max(x['pg_active'] for x in measured) if measured else None,
                 'outbox_pending_max': max(x['outbox_pending'] for x in measured) if measured else None,
                 'outbox_oldest_s_max': max(x['outbox_oldest_s'] for x in measured) if measured else None,
                 'outbox_pending_end': measured[-1]['outbox_pending'] if measured else None,
                 'search_pending_max': max(x['search_pending'] for x in measured) if measured else None,
                 'search_pending_end': measured[-1]['search_pending'] if measured else None,
                 'background_imports_s': imports, 'sampler_errors': sampler_errors[:3], 'stderr_tail': r.stderr[-500:]}
    try:  # без расширения не обращаемся к нему (иначе ошибка в журнале PostgreSQL)
        if sql("SELECT count(*) FROM pg_extension WHERE extname='pg_stat_statements'") != '1':
            raise RuntimeError('extension not installed')
        slow = sql("SELECT string_agg(left(regexp_replace(query,'\\s+',' ','g'),200)||' | calls='||calls||' mean_ms='||round(mean_exec_time::numeric,1),E'\\n' ORDER BY total_exec_time DESC) FROM (SELECT * FROM pg_stat_statements WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) ORDER BY total_exec_time DESC LIMIT 15) x")
    except Exception as e:  # расширение может быть не включено — фиксируем это, а не скрываем
        slow = 'pg_stat_statements unavailable: ' + str(e)[:200]
    report = {'mode': 'split api+worker' if SPLIT else 'combined', 'passport': 'docs/plans/surveyscan-v2/decisions/C30-load-passport.md', 'assets': len(assets), 'load': result, 'resources': resources, 'slow_queries': slow, 'samples': samples}
    (OUT / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=1))
    log('DONE', json.dumps({k: result[k] for k in ('requests', 'throughput_rps', 'p95_ms', 'p99_ms', 'errors')}))


harness(web_scenario=scenario, browser_origin=f'http://127.0.0.1:{freeport()}', inventory12=True)
