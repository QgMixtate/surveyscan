#!/usr/bin/env python3
"""Стенд центра для проверки агента с другой машины (Windows/Linux ВМ), НЕ production.

Поднимает тот же стенд, что и c15 relay smoke (PostgreSQL+OpenBao в docker, скомпилированные центр и collector,
профиль 1.2 включён), но collector слушает наружу. Центр остаётся на loopback. Одноразовая синтетическая dev-CA.

Порядок для ВМ: up -> агент делает prepare и кладёт вывод в OUT/prepare.json -> скрипт выдаёт grant в OUT/grant.json
(действует 15 минут) -> агент делает enroll и run. Данные видны в центре; скрипт печатает счётчики.
--selftest: роль агента играет скомпилированный Linux-агент (prepare, enroll, run12 демоном) — проверка самого стенда.
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from bao_fixture import fixture
from dev import ROOT, STATE, bao_request, initialize, unseal
from machine_smoke import main as harness

STOP = False


def _stop(*_):
    global STOP
    STOP = True


def read_json(path):
    raw = Path(path).read_bytes()
    for enc in ('utf-8-sig', 'utf-16'):  # PowerShell 5.1 пишет UTF-16 при перенаправлении
        try:
            return json.loads(raw.decode(enc))
        except (UnicodeError, ValueError):
            continue
    raise ValueError('prepare.json: не удалось разобрать JSON')


def write_private(path, text):
    path = Path(path)
    if path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)


def counters(sql):
    sections = sql("SELECT coalesce(string_agg(section_name||'='||n,' ' ORDER BY section_name),'-') FROM (SELECT section_name,count(*) n FROM inventory.record_facts12 GROUP BY section_name) t")
    return {'observations': int(sql('SELECT count(*) FROM inventory.observations')),
            'assets': int(sql('SELECT count(*) FROM assets.assets')), 'facts_by_section': sections}


def grant_requests(out, default_platform):
    """prepare-файлы в каталоге -> {имя: (платформа, имя grant)}; пустой словарь, если файлов нет."""
    found = {}
    for path in sorted(Path(out).glob('prepare*.json')):
        name = path.name
        if name == 'prepare.json':
            platform = default_platform
        elif name.startswith('prepare-linux'):
            platform = 'linux/amd64'
        elif name.startswith('prepare-windows'):
            platform = 'windows/amd64'
        else:
            continue
        found[name] = (platform, name.replace('prepare', 'grant', 1))
    return found


def acquisition_for(name):
    """Способ получения данных по имени prepare-файла: ...ssh... -> ssh, ...winrm... -> winrm, иначе агент на хосте."""
    low = name.lower()
    return 'ssh' if 'ssh' in low else 'winrm' if 'winrm' in low else 'agent'


def scenario(args, **s):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    ca = Path(s['ca_file']).read_bytes()
    (out / 'ca.pem').write_bytes(ca)
    base = {'tenant_id': s['tenant'], 'site_id': s['site'], 'network_scope_id': s['scope'],
            'collector_url': f'https://{args.public_host}:{args.collector_port}', 'collector_source_id': s['collector_source'],
            'inventory_seconds': 60, 'heartbeat_seconds': 30, 'jitter_percent': 0, 'spool_limit_bytes': 1048576}
    windows = dict(base, ca_certificate_file=args.windows_root + '\\cfg\\ca.pem', state_directory=args.windows_root + '\\state')
    (out / 'agent-config.windows.json').write_text(json.dumps(windows, indent=2))
    (out / 'agent-config.linux.json').write_text(json.dumps(dict(base, ca_certificate_file='/CHANGE/ME/ca.pem', state_directory='/CHANGE/ME/state'), indent=2))
    print(f"READY collector=https://{args.public_host}:{args.collector_port} out={out}", flush=True)
    # Заявки по файлам в OUT: prepare.json -> платформа --platform (grant.json); prepare-linux*.json -> linux/amd64;
    # prepare-windows*.json -> windows/amd64; grant лежит рядом под именем с заменой prepare -> grant. Файлов может быть
    # сколько угодно (несколько агентов/целей за один запуск центра); найденные позже подхватываются на лету.
    for old in list(out.glob('prepare*.json')) + list(out.glob('grant*.json')):
        old.unlink()
    agent = None
    if args.selftest:
        agent = selftest_prepare(args, out, s)
    issued = {}  # имя файла -> source_id, для которого grant уже выдан (новый prepare с другим source_id обрабатывается заново)
    issued_file = out / '.issued.json'  # постоянный стенд помнит выданные grant между перезапусками
    if getattr(args, 'persistent', False) and issued_file.exists():
        issued = json.loads(issued_file.read_text())
    warned = set()
    deadline = time.monotonic() + args.timeout
    last = 0.0
    (out / 'collector-status.json').unlink(missing_ok=True)
    restarts = 0
    if args.selftest:  # проверка присмотра: collector «падает», обвязка его перезапускает, агент регистрируется через новый
        s['collector_process'].kill()
        s['collector_process'].wait()
    while not STOP and time.monotonic() < deadline:
        # Присмотр (замечание стенда, задание №12): collector, упавший с паникой, раньше тихо останавливал доставку всех
        # источников. Теперь выход collector виден в выводе и в collector-status.json, collector перезапускается с
        # нарастающей паузой; выход центра завершает vm_center с ошибкой (перезапускает внешний супервизор).
        collector = s['collector_process']
        if collector.poll() is not None:
            restarts += 1
            status = {'collector_exit_code': collector.returncode, 'restarts': restarts, 'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
            (out / 'collector-status.json').write_text(json.dumps(status))
            print(f'COLLECTOR ВЫШЕЛ (код {collector.returncode}) — перезапуск №{restarts}; журнал collector.log в каталоге обвязки', flush=True)
            time.sleep(min(60, 5 * restarts))
            s['collector_process'] = s['start']('collector', [str(ROOT / '.dist/surveyscan-collector'), 'run', '--config', s['collector_config']])
            for _ in range(60):  # ждём, пока перезапущенный collector начнёт принимать соединения
                try:
                    socket.create_connection(('127.0.0.1', s['collector_port']), timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.5)
        if s['center_process'].poll() is not None:
            print(f"ЦЕНТР ВЫШЕЛ (код {s['center_process'].returncode}) — vm_center завершается с ошибкой", flush=True)
            raise SystemExit(1)
        for prepare_name, (platform, grant_name) in grant_requests(out, args.platform).items():
            if prepare_name in issued:
                try:
                    if read_json(out / prepare_name).get('source_id') == issued[prepare_name]:
                        continue
                except (ValueError, OSError):
                    continue
            time.sleep(0.5)
            try:
                prep = read_json(out / prepare_name)
                prep['source_id'], prep['csr_sha256'], prep['signing_public_key']
            except (ValueError, KeyError, TypeError):
                # файл пустой/недописан (оболочка создаёт его до записи) или от неудачного prepare: ждём, не падаем
                if prepare_name not in warned:
                    warned.add(prepare_name)
                    print(f'WAIT {prepare_name} пока не содержит корректный prepare (повторю проверку)', flush=True)
                continue
            body = {'tenant_id': s['tenant'], 'source_id': prep['source_id'], 'source_kind': 'agent', 'site_id': s['site'],
                    'collector_id': s['collector_id'], 'ttl_seconds': 900, 'csr_sha256': prep['csr_sha256'],
                    'signing_public_key': prep['signing_public_key'], 'inventory_platform': platform}
            if acquisition_for(prepare_name) != 'agent':
                body['acquisition'] = acquisition_for(prepare_name)
            headers = {'Origin': s['origin'], 'Cookie': s['cookie'], 'X-CSRF-Token': s['session']['csrf_token']}
            code, grant, _ = s['request'](s['tls_port'], s['plain'], 'POST', '/api/v1/enrollments', body, headers)
            if code != 201:
                # отказ (например, источник уже зарегистрирован) не должен ронять центр с чужими агентами
                issued[prepare_name] = prep['source_id']
                print(f'GRANT REFUSED for {prepare_name}: HTTP {code}', flush=True)
                continue
            write_private(out / grant_name, json.dumps(grant))
            issued[prepare_name] = prep['source_id']
            if getattr(args, 'persistent', False):
                write_private(issued_file, json.dumps(issued))
            print(f"GRANT issued for source {prep['source_id']} platform {platform} acquisition {acquisition_for(prepare_name)} (valid 15 min) -> {out / grant_name}", flush=True)
            if args.selftest:
                agent = selftest_enroll_run(args, out, agent)
        if time.monotonic() - last > 20:
            last = time.monotonic()
            c = counters(s['sql'])
            print('STATUS', json.dumps(c), flush=True)
            if args.selftest and c['observations'] >= 1 and c['facts_by_section'].count('=') >= 8:
                return selftest_finish(args, c, agent, s)
        time.sleep(1)
    if args.selftest:
        raise AssertionError('selftest: данные агента не дошли до центра за отведённое время')


def agent_bin():
    return str(ROOT / '.dist/surveyscan-agent')


def selftest_prepare(args, out, s):
    work = Path(tempfile.mkdtemp(prefix='vmc-agent-', dir=STATE))
    os.chmod(work, 0o700)
    cfgdir = work / 'cfg'
    cfgdir.mkdir(mode=0o700)
    cfg = json.loads((out / 'agent-config.linux.json').read_text())
    cfg.update(collector_url=f'https://127.0.0.1:{args.collector_port}', ca_certificate_file=str(cfgdir / 'ca.pem'), state_directory=str(work / 'state'))
    write_private(cfgdir / 'ca.pem', (out / 'ca.pem').read_text())
    write_private(cfgdir / 'agent.json', json.dumps(cfg))
    prepared = subprocess.run([agent_bin(), 'prepare', '--config', str(cfgdir / 'agent.json')], capture_output=True, timeout=30)
    assert prepared.returncode == 0, 'selftest agent prepare failed'
    (out / 'prepare.json').write_bytes(prepared.stdout)
    return {'config': str(cfgdir / 'agent.json'), 'process': None}


def selftest_enroll_run(args, out, agent):
    enrolled = subprocess.run([agent_bin(), 'enroll', '--config', agent['config'], '--grant-file', str(out / 'grant.json')], capture_output=True, timeout=60)
    assert enrolled.returncode == 0, 'selftest agent enroll failed: ' + enrolled.stderr.decode()[:200]
    agent['process'] = subprocess.Popen([agent_bin(), 'run12', '--config', agent['config']], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return agent


def selftest_finish(args, c, agent, s):
    status = json.loads((Path(args.out) / 'collector-status.json').read_text()) if (Path(args.out) / 'collector-status.json').exists() else {}
    assert status.get('restarts') == 1 and s['collector_process'].poll() is None, 'collector supervision: killed collector was not restarted'
    c['collector_restarted'] = True
    process = agent['process']
    assert process.poll() is None, 'selftest run12 daemon exited: ' + process.stderr.read().decode()[:300]
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=20) == 0, 'run12 daemon did not stop cleanly on SIGTERM'
    assert s['sql']("SELECT count(*) FROM sources.agents WHERE inventory_platform='linux/amd64'") == '1'
    print('SELFTEST PASS ' + json.dumps(c), flush=True)


def ensure_stack():
    # PostgreSQL и OpenBao (docker compose) нужны стенду; если OpenBao не отвечает — поднимаем тем же dev.py up, что и CI.
    try:
        bao_request('/v1/sys/init')
        return
    except Exception:
        pass
    print('PostgreSQL/OpenBao не запущены: выполняю scripts/dev.py up (первый раз скачивает образы)', flush=True)
    subprocess.run([sys.executable, str(ROOT / 'scripts/dev.py'), 'up'], cwd=ROOT, check=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--public-host', default='127.0.0.1', help='адрес collector, который увидит агент (IP/имя Linux-ВМ)')
    p.add_argument('--bind', default=None, help='адрес прослушивания collector (по умолчанию 0.0.0.0 при внешнем host, иначе 127.0.0.1)')
    p.add_argument('--collector-port', type=int, default=18443)
    p.add_argument('--platform', default='windows/amd64', choices=['windows/amd64', 'linux/amd64'])
    p.add_argument('--out', default=str(ROOT / '.local/vm-center'))
    p.add_argument('--windows-root', default='C:\\surveyscan\\vm')
    p.add_argument('--timeout', type=int, default=7 * 24 * 3600, help='через сколько секунд центр завершится и УДАЛИТ временную БД (по умолчанию 7 суток; для soak не уменьшать)')
    p.add_argument('--selftest', action='store_true')
    p.add_argument('--persistent', action='store_true', help='постоянный стенд: БД, CA, ключи OpenBao и регистрации агентов сохраняются между перезапусками (обновление центра без переподключения агентов)')
    p.add_argument('--state', default=str(ROOT / '.local/vm-center-state'), help='каталог постоянного стенда (секреты, 0700; не публиковать)')
    p.add_argument('--backup-marker', default=None, help='файл метки резервной копии (запоминается в постоянном стенде)')
    args = p.parse_args()
    if args.selftest:
        args.platform = 'linux/amd64'
        args.timeout = 420
    os.environ['C15_COLLECTOR_BIND'] = args.bind or ('127.0.0.1' if args.public_host in ('127.0.0.1', 'localhost') else '0.0.0.0')
    os.environ['C15_COLLECTOR_PORT'] = str(args.collector_port)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    initialize()
    ensure_stack()
    if args.persistent and not args.selftest:
        persistent(args)
        return
    with tempfile.TemporaryDirectory(prefix='vmc-', dir=STATE) as temp:
        directory = Path(temp)
        with fixture(directory) as f:
            issuer = directory / 'issuer'
            r = subprocess.run([str(ROOT / '.dist/surveyscan-server'), 'bootstrap-issuer', '--config', f['config'], '--output-directory', str(issuer)], capture_output=True, timeout=30)
            assert r.returncode == 0, 'scoped issuer bootstrap failed'
            settings = {'config': f['config'], 'ca_certificate': str(issuer / 'ca.pem'), 'server_certificate': str(issuer / 'server.pem'),
                        'server_private': str(issuer / 'server.key'), 'center_id': __import__('uuid').uuid4().__str__(), 'center_public': f['profile']['keys']['center']['public_key']}
            harness(agent_scenario=lambda **s: scenario(args, **s), bao_settings=settings, report_directory=STATE, inventory12=True, collector_inventory12=True)


def fresh_token(config_path):
    # Токен центра периодический (1 ч): пока центр стоял, он мог истечь. Выпускаем новый с той же узкой политикой.
    cfg = json.loads(Path(config_path).read_text())
    root = json.loads((STATE / 'bao-init.json').read_text())['root_token']
    import urllib.request
    request = urllib.request.Request('http://127.0.0.1:58200/v1/auth/token/create', method='POST', headers={'X-Vault-Token': root, 'Content-Type': 'application/json'},
                                     data=json.dumps({'policies': [cfg['policy']], 'no_default_policy': True, 'period': '1h', 'renewable': True, 'no_parent': True}).encode())
    with urllib.request.urlopen(request, timeout=10) as response:
        token = json.load(response)['auth']['client_token']
    path = Path(cfg['token_file'])
    temp = path.with_suffix('.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(token + '\n')
    os.replace(temp, path)


def ensure_integrations(config_path):
    # C31.05: интеграции включаются из Web — центру нужен раздел OpenBao KV для их секретов. Стенд, созданный до
    # C31.05, получает правило политики и integrations_path автоматически (ручной правки не требуется).
    cfg = json.loads(Path(config_path).read_text())
    if cfg.get('integrations_path'):
        return
    import urllib.request
    root = json.loads((STATE / 'bao-init.json').read_text())['root_token']
    def call(method, path, body=None):
        req = urllib.request.Request('http://127.0.0.1:58200/v1/' + path, method=method, headers={'X-Vault-Token': root, 'Content-Type': 'application/json'},
                                     data=None if body is None else json.dumps(body).encode())
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    policy = call('GET', 'sys/policies/acl/' + cfg['policy'])['data']['policy']
    rule = 'path ' + json.dumps(cfg['kv_mount'] + '/data/server/integrations/*') + ' { capabilities = ["create","update","read"] }'
    if rule not in policy:
        call('PUT', 'sys/policies/acl/' + cfg['policy'], {'policy': policy.rstrip('\n') + '\n' + rule})
    cfg['integrations_path'] = 'server/integrations'
    temp = Path(config_path).with_suffix('.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(json.dumps(cfg))
    os.replace(temp, config_path)
    print('OpenBao: раздел секретов интеграций включён (server/integrations)', flush=True)


SERVER_VALIDITY = '168h'  # максимум bootstrap-issuer; сертификат перевыпускается при каждом старте постоянного центра


def renew_server_certificate(settings):
    # Стенд R-027 (12.11): сертификат сервера центра выпускался один раз при создании стенда на 24 ч и при перезапуске
    # не обновлялся — через сутки центр перестал стартовать («server certificate not trusted by configured CA»).
    # Новый сертификат подписывается тем же ключом CA в OpenBao и с тем же именем издателя, поэтому прежний ca.pem у
    # агентов и коллектора ему доверяет; сам ca.pem стенда не меняется. Временный каталог (с закрытым ключом) удаляется.
    import shutil
    work = Path(tempfile.mkdtemp(prefix='renew-', dir=Path(settings['server_certificate']).parent.parent))
    try:
        out = work / 'issuer'
        r = subprocess.run([str(ROOT / '.dist/surveyscan-server'), 'bootstrap-issuer', '--config', settings['config'], '--output-directory', str(out),
                            '--server-validity', SERVER_VALIDITY], capture_output=True, timeout=30)
        assert r.returncode == 0, 'server certificate renewal failed'
        for name, target in (('server.pem', settings['server_certificate']), ('server.key', settings['server_private'])):
            temp = Path(target).with_suffix('.new')
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write((out / name).read_bytes())
            os.replace(temp, target)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(f'сертификат сервера центра перевыпущен на {SERVER_VALIDITY}', flush=True)


def persistent(args):
    # Постоянный стенд: первый запуск создаёт ресурсы OpenBao (без удаления при выходе), CA центра, БД, админа и collector;
    # последующие — только новые миграции, свежий токен OpenBao и новые бинарники. Агентов переподключать не нужно.
    state = Path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    vm, settings_file = state / 'bao', state / 'vm.json'
    unseal()
    if not settings_file.exists():
        vm.mkdir(exist_ok=True)
        with fixture(vm, keep=True) as f:
            issuer = vm / 'issuer'
            r = subprocess.run([str(ROOT / '.dist/surveyscan-server'), 'bootstrap-issuer', '--config', f['config'], '--output-directory', str(issuer), '--server-validity', SERVER_VALIDITY], capture_output=True, timeout=30)
            assert r.returncode == 0, 'scoped issuer bootstrap failed'
            settings = {'config': f['config'], 'ca_certificate': str(issuer / 'ca.pem'), 'server_certificate': str(issuer / 'server.pem'),
                        'server_private': str(issuer / 'server.key'), 'center_id': __import__('uuid').uuid4().__str__(), 'center_public': f['profile']['keys']['center']['public_key']}
        settings_file.write_text(json.dumps(settings))
        print('PERSISTENT стенд создан:', state, flush=True)
    else:
        print('PERSISTENT стенд найден, агентов переподключать не нужно:', state, flush=True)
    settings = json.loads(settings_file.read_text())
    # Метка резервной копии (задание №8, замечание пилота №9): путь запоминается в vm.json и подставляется при каждом
    # запуске — ручной перезапуск центра больше не теряет SURVEYSCAN_V2_BACKUP_MARKER.
    marker = args.backup_marker or os.environ.get('SURVEYSCAN_V2_BACKUP_MARKER') or settings.get('backup_marker')
    if marker and settings.get('backup_marker') != marker:
        settings['backup_marker'] = marker
        settings_file.write_text(json.dumps(settings))
    if marker:
        os.environ['SURVEYSCAN_V2_BACKUP_MARKER'] = marker
        print('метка резервной копии:', marker, flush=True)
    ensure_integrations(settings['config'])
    fresh_token(settings['config'])
    renew_server_certificate(settings)
    (state / 'harness').mkdir(exist_ok=True)
    harness(agent_scenario=lambda **s: scenario(args, **s), bao_settings=settings, report_directory=STATE, inventory12=True, collector_inventory12=True, persist=state / 'harness')


if __name__ == '__main__':
    main()
