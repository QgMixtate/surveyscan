#!/usr/bin/env python3
"""C35.04 — раздельные роли центра на настоящих процессах (обвязка machine_smoke).

Центр обвязки запускается в роли api; к нему добавляются два worker и второй api-экземпляр на той же БД.
Проверяется: api не выполняет фоновую работу; worker не отдаёт UI/API, но обрабатывает очередь событий; два worker не
применяют одно событие дважды; сессия, выданная одним api, работает на другом; после остановки первого api второй
обслуживает чтение и запись, а worker обрабатывает новое событие. Отчёт — .local/c35-split-smoke.json.
"""
import http.client, json, os, ssl, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from machine_smoke import main as harness, freeport  # noqa: E402
from dev import ROOT, STATE  # noqa: E402

os.environ['SURVEYSCAN_V2_ROLE'] = 'api'
SERVER = str(ROOT / '.dist/surveyscan-server')
checks = []


def scenario(**s):
    sql, env, directory = s['sql'], s['server_environment'], Path(s['directory'])
    ctx = ssl.create_default_context(cafile=s['ca_file'])
    processes = []

    def req(port, method, path, body=None, headers=None, tls=True):
        c = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=20) if tls else http.client.HTTPConnection('127.0.0.1', port, timeout=20)
        h = {'Origin': s['origin'], 'Content-Type': 'application/json', **(headers or {})}
        c.request(method, path, body=None if body is None else json.dumps(body), headers=h)
        r = c.getresponse(); raw = r.read(); c.close()
        return r.status, (json.loads(raw) if raw and raw[:1] in b'{[' else None), r.getheader('Set-Cookie')

    def spawn(name, extra):
        log = (directory / (name + '.log')).open('ab')
        p = subprocess.Popen([SERVER, 'serve'], cwd=ROOT, env=dict(env, **extra), stdout=log, stderr=log)
        processes.append(p)
        return p

    def until(what, condition, seconds=40):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if condition():
                return
            time.sleep(0.5)
        raise AssertionError('timeout: ' + what)

    try:
        # 1. api не обрабатывает очередь событий
        time.sleep(5)
        events = int(sql('SELECT count(*) FROM messaging.outbox_events'))
        assert events > 0 and sql("SELECT count(*) FROM messaging.consumer_checkpoints WHERE consumer_name='registry-version'") == '0'
        checks.append(f'api role serves the center but does not consume the outbox ({events} events pending)')

        # 2. два worker: только проверка живости; очередь обработана ровно один раз
        workers = []
        for i in range(2):
            port = freeport()
            spawn(f'worker{i}', {'SURVEYSCAN_V2_ROLE': 'worker', 'SURVEYSCAN_V2_LISTEN': f'127.0.0.1:{port}'})
            workers.append(port)
        for port in workers:
            until('worker ready', lambda port=port: _ok(lambda: req(port, 'GET', '/health/ready', tls=False)[0] == 200))
            assert req(port, 'GET', '/api/v1/assets', tls=False)[0] == 404
        until('outbox consumed', lambda: sql("SELECT count(*) FROM messaging.consumer_checkpoints WHERE consumer_name='registry-version' AND state='applied'") == str(events))
        assert sql("SELECT count(*) FROM assets.consumer_versions v JOIN assets.assets a USING(tenant_id,asset_uid) WHERE v.aggregate_version<>a.aggregate_version") == '0'
        checks.append('two worker processes expose only health, consume every event exactly once (per-tenant advisory lock), versions match')

        # 3. второй api-экземпляр: своя машинная конфигурация с другим портом, та же БД
        machine = json.loads(Path(env['SURVEYSCAN_V2_MACHINE_CONFIG']).read_text())
        api2 = freeport()
        machine['listen'] = f'127.0.0.1:{api2}'
        copy = directory / 'machine-api2.json'
        fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(json.dumps(machine))
        spawn('api2', {'SURVEYSCAN_V2_ROLE': 'api', 'SURVEYSCAN_V2_LISTEN': f'127.0.0.1:{freeport()}', 'SURVEYSCAN_V2_MACHINE_CONFIG': str(copy)})
        until('api2 ready', lambda: _ok(lambda: req(api2, 'GET', '/health/ready')[0] == 200))
        status, session, cookie = req(s['center_port'], 'POST', '/api/v1/auth/sessions', {'username': 'admin', 'password': s['password']})
        assert status == 201
        auth = {'Cookie': cookie.split(';', 1)[0]}
        a1 = req(s['center_port'], 'GET', '/api/v1/assets?limit=50', headers=auth)
        a2 = req(api2, 'GET', '/api/v1/assets?limit=50', headers=auth)
        assert a1[0] == a2[0] == 200 and a1[1] == a2[1]
        checks.append('session issued by api #1 is valid on api #2 (state in PostgreSQL); both return the same registry page')

        # 4. отказ api #1: api #2 обслуживает чтение и запись, worker обрабатывает новое событие
        s['center_process'].terminate()
        s['center_process'].wait(timeout=10)
        uid = s['asset']
        status, asset, _ = req(api2, 'GET', '/api/v1/assets/' + uid, headers=auth)
        assert status == 200
        status, _, _ = req(api2, 'PATCH', '/api/v1/assets/' + uid, {'display_name': 'после отказа api1'},
                           {**auth, 'X-CSRF-Token': session['csrf_token'], 'If-Match': f'"asset:{uid}:business:{asset["business_revision"]}"'})
        assert status == 200, status
        until('new event consumed by a worker', lambda: sql("SELECT count(*) FROM messaging.outbox_events e WHERE NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='registry-version' AND c.state='applied')") == '0')
        checks.append('after api #1 stops, api #2 keeps the session, serves reads and writes; a worker applies the new event')
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
    report = {'package': 'C35', 'task': 'C35.04', 'status': 'passed', 'count': len(checks), 'checks': checks,
              'unrun': ['API SLO under load in split mode (research/load with roles)', 'worker saturation', 'separate hosts']}
    (STATE / 'c35-split-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
    print(json.dumps(report, ensure_ascii=False))


def _ok(fn):
    try:
        return fn()
    except OSError:
        return False


harness(web_scenario=scenario)
