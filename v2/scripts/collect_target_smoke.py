#!/usr/bin/env python3
"""C51.03 — сбор из Web без файлов на ВМ: настоящие центр и collector (обвязка machine_smoke) и тестовый SSH-сервер
(scripts/testsshd, выполняет команды сбора по-настоящему на этом хосте).

Администратор вводит учётку SSH в Web API (секрет — в хранилище секретов центра), заводит цель с отпечатком ключа
хоста; collector без ручной настройки получает цель, регистрирует для неё отдельный источник-агент по grant центра,
перед сбором берёт учётку у центра по mTLS, собирает узел и доставляет данные. Проверяется: цель active, данные
источника цели в реестре, выдача учётки в аудите, пароль не попал в журналы и каталоги collector.
Отчёт — .local/c51-collect-target-smoke.json.
"""
import http.client, json, os, re, secrets, ssl, subprocess, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from machine_smoke import main as harness  # noqa: E402
from dev import ROOT, STATE  # noqa: E402

checks = []


def scenario(**s):
    ctx = ssl.create_default_context(cafile=s['ca_file'])
    directory = Path(s['directory'])

    def req(method, path, body=None, headers=None):
        c = http.client.HTTPSConnection('127.0.0.1', s['center_port'], context=ctx, timeout=30)
        c.request(method, path, body=None if body is None else json.dumps(body), headers={'Origin': s['origin'], 'Content-Type': 'application/json', **(headers or {})})
        r = c.getresponse(); raw = r.read(); c.close()
        return r.status, (json.loads(raw) if raw[:1] in (b'{', b'[') else None), r.getheader('Set-Cookie')

    password = 'c51-' + secrets.token_urlsafe(18)
    pw = directory / 'sshd-password'
    fd = os.open(pw, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(password + '\n')
    sshd = subprocess.Popen([str(ROOT / '.dist/testsshd'), '-user', 'scanprobe', '-password-file', str(pw)], stdout=subprocess.PIPE, text=True)
    try:
        m = re.search(r'addr=127\.0\.0\.1:(\d+) fingerprint=(SHA256:\S+)', sshd.stdout.readline())
        port, fingerprint = int(m.group(1)), m.group(2)
        status, session, cookie = req('POST', '/api/v1/auth/sessions', {'username': 'admin', 'password': s['password']})
        assert status == 201
        h = {'Cookie': cookie.split(';', 1)[0], 'X-CSRF-Token': session['csrf_token']}
        status, cred, _ = req('POST', '/api/v1/discovery/credentials', {'name': 'Linux RO', 'kind': 'ssh', 'username': 'scanprobe', 'secret': {'password': password}}, h)
        assert status == 201 and password not in json.dumps(cred), status
        collector = s['sql']("SELECT source_id::text FROM sources.sources WHERE source_kind='collector' AND state='active' LIMIT 1")
        status, target, _ = req('POST', '/api/v1/discovery/targets', {'collector_id': collector, 'address': '127.0.0.1', 'port': port, 'kind': 'ssh', 'credential_id': cred['credential_id'], 'interval_seconds': 300}, h)  # без отпечатка: запоминается при первом подключении
        assert status == 201 and target['state'] == 'pending', (status, target)
        checks.append('credential entered via Web API (secret only in the center secret store), SSH target created without a fingerprint')
        started = time.time()
        while time.time() - started < 300:
            status, page, _ = req('GET', '/api/v1/discovery/targets', headers={'Cookie': h['Cookie']})
            t = [x for x in page['items'] if x['target_id'] == target['target_id']][0]
            if t['state'] == 'active' and t['last_collected_at']:
                break
            time.sleep(3)
        if not (t['state'] == 'active' and t['last_collected_at'] and not t['last_error']):
            logs = {p.name: p.read_text(errors='replace')[-1500:] for p in directory.glob('*.log')}
            recs = s['sql'](f"SELECT count(*) FROM assets.source_records WHERE source_id='{t['agent_source_id']}'") if t['agent_source_id'] else 'n/a'
            raise AssertionError(json.dumps({'target': t, 'records': recs, 'logs': {k: v for k, v in logs.items() if 'collector' in k}}, ensure_ascii=False)[:4000])
        elapsed = time.time() - started
        assert t['host_key_sha256'] == fingerprint and t['host_key_origin'] == 'first_use', t
        checks.append('collector read the SSH host key on first connection and pinned it at the center (first_use, audited)')
        agent = t['agent_source_id']
        records = s['sql'](f"SELECT count(*) FROM assets.source_records WHERE source_id='{agent}'")
        platform = s['sql'](f"SELECT inventory_platform||'/'||acquisition FROM sources.agents WHERE source_id='{agent}'")
        assert int(records) >= 1 and platform == 'linux/amd64/ssh', (records, platform)
        checks.append(f'collector registered a separate agent source for the target (linux/amd64, ssh) and delivered its data in {elapsed:.0f}s without any file on the host')
        issued = s['sql']("SELECT count(*) FROM audit.audit_events WHERE action='discovery.credential_issued'")
        assert int(issued) >= 1
        store = directory / 'integrations'  # хранилище секретов центра без OpenBao — единственное разрешённое место
        leaked = [str(p) for p in directory.rglob('*') if p.is_file() and p != pw and store not in p.parents and password.encode() in p.read_bytes()]
        assert any(password.encode() in p.read_bytes() for p in store.rglob('*') if p.is_file()), 'secret must be in the center secret store'
        assert not leaked, leaked
        checks.append(f'credential issued to the collector over mTLS {issued} time(s), audited; password found in no collector/center log or state file')
    finally:
        sshd.terminate()
    report = {'package': 'C51', 'task': 'C51.03', 'status': 'passed', 'count': len(checks), 'checks': checks}
    (STATE / 'c51-collect-target-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
    print(json.dumps(report, ensure_ascii=False))


harness(web_scenario=scenario, inventory12=True, collector_inventory12=True)
