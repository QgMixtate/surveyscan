#!/usr/bin/env python3
"""C51.02 — сквозное обследование сети: настоящие центр и collector (обвязка machine_smoke).

Администратор заводит подсеть 127.0.0.0/30 для collector площадки через Web API, оператор-администратор запускает
обследование; collector без ручной настройки забирает задание (mTLS), выполняет пробы TCP/ARP/ICMP с пределами
D-13 и сдаёт подписанный результат; центр отмечает найденные узлы. Отчёт — .local/c51-discovery-smoke.json.
"""
import http.client, json, ssl, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from machine_smoke import main as harness  # noqa: E402
from dev import STATE  # noqa: E402

checks = []


def scenario(**s):
    ctx = ssl.create_default_context(cafile=s['ca_file'])

    def req(method, path, body=None, headers=None):
        c = http.client.HTTPSConnection('127.0.0.1', s['center_port'], context=ctx, timeout=30)
        c.request(method, path, body=None if body is None else json.dumps(body), headers={'Origin': s['origin'], 'Content-Type': 'application/json', **(headers or {})})
        r = c.getresponse(); raw = r.read(); c.close()
        return r.status, (json.loads(raw) if raw[:1] in (b'{', b'[') else None), r.getheader('Set-Cookie')

    status, session, cookie = req('POST', '/api/v1/auth/sessions', {'username': 'admin', 'password': s['password']})
    assert status == 201
    h = {'Cookie': cookie.split(';', 1)[0], 'X-CSRF-Token': session['csrf_token']}
    collector, site = s['sql']("SELECT source_id::text||' '||site_id::text FROM sources.sources WHERE source_kind='collector' AND state='active' LIMIT 1").split()
    status, net, _ = req('POST', '/api/v1/discovery/networks', {'site_id': site, 'collector_id': collector, 'name': 'loopback', 'cidr': '127.0.0.0/30', 'probes': ['tcp', 'arp', 'icmp']}, h)
    assert status == 201, (status, net)
    status, net2, _ = req('POST', '/api/v1/discovery/networks', {'site_id': site, 'collector_id': collector, 'name': 'wide', 'cidr': '10.0.0.0/16', 'probes': ['tcp']}, h)
    assert status == 422, status
    checks.append('network created from Web API for the site collector; /16 refused by D-13')
    status, run, _ = req('POST', f"/api/v1/discovery/networks/{net['network_id']}/runs", {}, h)
    assert status == 202, status
    started = time.time()
    while time.time() - started < 120:
        status, runs, _ = req('GET', f"/api/v1/discovery/networks/{net['network_id']}/runs", headers={'Cookie': h['Cookie']})
        last = runs['items'][0]
        if last['state'] in ('done', 'failed'):
            break
        time.sleep(2)
    assert last['run_id'] == run['run_id'] and last['state'] == 'done', last
    elapsed = time.time() - started
    status, hosts, _ = req('GET', f"/api/v1/discovery/networks/{net['network_id']}/hosts", headers={'Cookie': h['Cookie']})
    ips = sorted(x['ip'] for x in hosts['items'])
    assert ips == ['127.0.0.1', '127.0.0.2'], hosts
    icmp = [x['ip'] for x in hosts['items'] if x['icmp']]
    checks.append(f"collector claimed the job without manual config, ran probes and submitted a signed result in {elapsed:.0f}s: addresses {last['addresses']}, found {last['found']}, new {last['new_hosts']}, errors {last['errors']}, icmp {icmp}")
    audit = s['sql']("SELECT count(*) FROM audit.audit_events WHERE action LIKE 'discovery.%'")
    assert int(audit) >= 2
    checks.append('network creation and run request audited')
    report = {'package': 'C51', 'task': 'C51.02', 'status': 'passed', 'count': len(checks), 'checks': checks}
    (STATE / 'c51-discovery-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
    print(json.dumps(report, ensure_ascii=False))


harness(web_scenario=scenario)
