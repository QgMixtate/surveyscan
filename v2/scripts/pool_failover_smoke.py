#!/usr/bin/env python3
"""C36.04 — отказ PostgreSQL под настоящим центром (обвязка machine_smoke, пул pgx).

Перезапуск контейнера БД во время работы центра: запросы API в окне отказа завершаются быстро ошибкой (не висят),
частичных записей нет; после возвращения БД тот же процесс центра (без перезапуска) обслуживает чтение и запись,
сессия пользователя действует, очередь событий догоняет. Отчёт — .local/c36-pool-failover-smoke.json.
"""
import http.client, json, ssl, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from machine_smoke import main as harness  # noqa: E402
from dev import STATE, compose  # noqa: E402

checks = []


def scenario(**s):
    sql, port, uid = s['sql'], s['center_port'], s['asset']
    ctx = ssl.create_default_context(cafile=s['ca_file'])

    def req(method, path, body=None, headers=None, timeout=30):
        c = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=timeout)
        c.request(method, path, body=None if body is None else json.dumps(body), headers={'Origin': s['origin'], 'Content-Type': 'application/json', **(headers or {})})
        r = c.getresponse(); raw = r.read(); c.close()
        return r.status, (json.loads(raw) if raw[:1] in (b'{', b'[') else None), r.getheader('Set-Cookie')

    status, session, cookie = req('POST', '/api/v1/auth/sessions', {'username': 'admin', 'password': s['password']})
    assert status == 201
    auth = {'Cookie': cookie.split(';', 1)[0]}
    write = {**auth, 'X-CSRF-Token': session['csrf_token']}
    status, asset, _ = req('GET', '/api/v1/assets/' + uid, headers=auth)
    assert status == 200
    before = sql("SELECT revision::text FROM assets.asset_business_fields WHERE asset_uid='" + uid + "'")

    compose('stop', 'db')
    try:
        started = time.time()
        status, _, _ = req('GET', '/api/v1/assets?limit=10', headers=auth)
        read_s = time.time() - started
        started = time.time()
        wstatus, _, _ = req('PATCH', '/api/v1/assets/' + uid, {'display_name': 'во время отказа'},
                            {**write, 'If-Match': f'"asset:{uid}:business:{asset["business_revision"]}"'})
        write_s = time.time() - started
        assert status >= 500 and wstatus >= 500, (status, wstatus)
        assert read_s < 25 and write_s < 25, (read_s, write_s)
        checks.append(f'DB down: API fails fast with {status}/{wstatus} (read {read_s:.1f}s, write {write_s:.1f}s), no hang')
    finally:
        compose('start', 'db')
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            if req('GET', '/health/ready', timeout=5)[0] == 200:
                break
        except OSError:
            pass
        time.sleep(1)
    else:
        raise AssertionError('center did not become ready after DB restart')
    assert sql("SELECT revision::text FROM assets.asset_business_fields WHERE asset_uid='" + uid + "'") == before
    checks.append('write attempted during the outage left no partial change')
    status, asset, _ = req('GET', '/api/v1/assets/' + uid, headers=auth)
    assert status == 200, status
    status, _, _ = req('PATCH', '/api/v1/assets/' + uid, {'display_name': 'после отказа БД'},
                       {**write, 'If-Match': f'"asset:{uid}:business:{asset["business_revision"]}"'})
    assert status == 200, status
    deadline = time.time() + 60
    while time.time() < deadline and sql("SELECT count(*) FROM messaging.outbox_events e WHERE NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='registry-version' AND c.state='applied')") != '0':
        time.sleep(1)
    assert sql("SELECT count(*) FROM messaging.outbox_events e WHERE NOT EXISTS(SELECT 1 FROM messaging.consumer_checkpoints c WHERE c.tenant_id=e.tenant_id AND c.event_id=e.event_id AND c.consumer_name='registry-version' AND c.state='applied')") == '0'
    checks.append('same center process (no restart): pool reconnects, session still valid, read/write work, event queue catches up')
    report = {'package': 'C36', 'task': 'C36.04', 'status': 'passed', 'count': len(checks), 'checks': checks}
    (STATE / 'c36-pool-failover-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
    print(json.dumps(report, ensure_ascii=False))


harness(web_scenario=scenario)
