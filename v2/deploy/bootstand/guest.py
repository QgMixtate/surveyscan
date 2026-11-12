"""Test operator inside a disposable VM. Root custody here is not product auto-unseal."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import subprocess
import time
import uuid

BIN = Path('/opt/surveyscan/current/bin')
SEED = Path('/root/boot-seed')
STATE = Path('/root/boot-phase.json')
CHECKS = []
CLI_TIMINGS = []
PHASE = 'initializing'
LOGIN_PRESSURE = None


def phase(name):
    global PHASE
    PHASE = name
    print('SURVEYSCAN_BOOT_PHASE ' + name, flush=True)


class BaoFailure(RuntimeError):
    def __init__(self, operation, status):
        super().__init__('test Bao operation failed: ' + operation)
        self.operation, self.status = operation, status


class CommandFailure(RuntimeError):
    def __init__(self, program, code, elapsed, stderr):
        super().__init__('test command failed')
        names = {'systemctl','python3','surveyscanctl','surveyscan-server','surveyscan-agent','openssl','psql','systemd-run'}
        self.program = program if program in names else 'test_command'
        self.code, self.elapsed = code, round(elapsed,3)
        self.cli_error = None
        if program == 'surveyscanctl':
            try:
                value = json.loads(stderr).get('error')
                allowed = {'NETWORK_OR_TLS_UNAVAILABLE','CONTEXT_ALREADY_EXISTS_OR_UNAVAILABLE',
                           'PRIVATE_PASSWORD_FILE_REQUIRED','INVALID_PASSWORD_FILE','INVALID_SESSION_RESPONSE',
                           'SESSION_COOKIE_MISSING','INVALID_SESSION_COOKIE','CONTEXT_DURABILITY_UNAVAILABLE',
                           'INVALID_CA_FILE','INVALID_SERVER_ORIGIN','HTTPS_REQUIRED','INVALID_JSON_RESPONSE',
                           'INVALID_RESPONSE','CONTEXT_UNAVAILABLE','INVALID_PRIVATE_CONTEXT','SESSION_EXPIRED',
                           'OUTPUT_UNAVAILABLE','OPERATION_UNAVAILABLE','INVALID_ARGUMENTS'}
                if isinstance(value,str) and (value in allowed or re.fullmatch(r'HTTP_[1-5][0-9]{2}',value)):
                    self.cli_error = value
            except (ValueError,AttributeError,TypeError):
                pass


def command(args, env=None, timeout=60):
    started = time.monotonic()
    result = subprocess.run([str(x) for x in args], env=env, capture_output=True, timeout=timeout)
    if result.returncode:
        print('TEST_COMMAND_STDERR ' + result.stderr.decode(errors='replace')[:2048], flush=True)
        raise CommandFailure(Path(args[0]).name, result.returncode, time.monotonic()-started, result.stderr)
    if Path(args[0]).name == 'surveyscanctl':
        operation = str(args[1]) if len(args)>1 and args[1] in ('login','assets','logout') else 'other'
        CLI_TIMINGS.append({'operation':operation,'elapsed_seconds':round(time.monotonic()-started,3)})
    return result.stdout


def auth_diagnostics(raw):
    """Only a fixed backend event vocabulary and bounded numbers reach proof."""
    safe = []
    stages = {'rate','user_lookup','password_verify','session_begin','user_recheck',
              'active_sessions','session_insert','audit','commit','unknown'}
    reasons = {'deadline_exceeded','request_cancelled','dependency_unavailable'}
    for line in raw.splitlines():
        try:
            item = json.loads(line)
            if item.get('component') != 'access' or item.get('event') != 'login_unavailable':
                continue
            if item.get('stage') not in stages or item.get('reason') not in reasons:
                continue
            if any(type(item.get(key)) is not int or not 0 <= item[key] <= 3600000 for key in ('elapsed_ms','verify_ms')):
                continue
            safe.append({key:item[key] for key in ('stage','reason','elapsed_ms','verify_ms')})
        except (ValueError,TypeError,AttributeError):
            continue
    return safe[-3:]


def save(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    path.chmod(mode)
    with path.open('rb') as stream:
        os.fsync(stream.fileno())


def queue_diagnostics(agent=Path('/var/lib/surveyscan-agent/spool'), collector=Path('/var/lib/surveyscan-collector/spool')):
    # Counts and a closed reason vocabulary only; never IDs, raw frames or logs.
    out = {}
    reasons = {k: 0 for k in ('SCHEMA_INVALID', 'SEQUENCE_CONFLICT', 'SOURCE_NOT_AUTHORIZED', 'other')}
    for role, directory in (('agent', agent), ('collector', collector)):
        for suffix in ('pending', 'receipt'):
            files = list(directory.glob('*.' + suffix))
            out[role + '_' + suffix] = min(len(files), 1000000)
            if suffix != 'receipt':
                continue
            for path in files[:100]:
                try:
                    if path.is_symlink() or path.stat().st_size > 2097152:
                        continue
                    value = json.loads(path.read_text())
                    if role == 'collector':
                        value = value.get('receipt', {})
                    for result in value.get('payload', {}).get('results', [])[:100]:
                        if result.get('spool_action') == 'retain':
                            key = result.get('reason_code')
                            reasons[key if key in reasons else 'other'] += 1
                except (OSError, ValueError, AttributeError, TypeError):
                    pass
    out.update({'retained_' + k: v for k, v in reasons.items()})
    return out


def until(predicate, message, seconds=120):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(.5)
    raise RuntimeError(message)


def request(port, tls, method, path, body=None, headers=None, timeout=10, server_name=None):
    connection = http.client.HTTPSConnection('127.0.0.1', port, context=tls, timeout=timeout)
    if server_name:
        connection.sock = tls.wrap_socket(socket.create_connection(('127.0.0.1', port), timeout=timeout),
                                          server_hostname=server_name)
    h = dict(headers or {})
    if body is not None:
        body = json.dumps(body).encode()
        h['Content-Type'] = 'application/json'
    try:
        connection.request(method, path, body=body, headers=h)
        response = connection.getresponse()
        raw = response.read(1024 * 1024)
        try:
            value = json.loads(raw) if raw else None
        except ValueError:
            value = raw.decode(errors='replace')
        return response.status, value, {k.lower(): v for k, v in response.getheaders()}
    finally:
        connection.close()


def sql(query, db='surveyscan_v2'):
    return command(['/usr/lib/postgresql/17/bin/psql', '-h', '/run/postgresql', '-U', 'surveyscan_v2', '-d', db,
                    '-v', 'ON_ERROR_STOP=1', '-Atc', query]).decode().strip()


def bao(path, body=None, token=None):
    headers = {'X-Vault-Token': token} if token else {}
    code, data, _ = request(8200, ssl.create_default_context(cafile='/etc/surveyscan-bao/ca.pem'),
                            'GET' if body is None else 'POST', '/v1/' + path, body, headers, timeout=60 if path == 'sys/init' else 10)
    if code not in (200, 204):
        raise BaoFailure(path, code)
    return data or {}


def unseal(custody):
    for key in custody['keys_base64']:
        state = bao('sys/unseal', {'key': key})
        if not state['sealed']:
            # Unseal response precedes Raft active-node/post-unseal readiness.
            # Do not retry provisioning writes or recreate storage/custody.
            def active():
                code, health, _ = request(8200, ssl.create_default_context(cafile='/etc/surveyscan-bao/ca.pem'),
                                          'GET', '/v1/sys/health')
                return code == 200 and health.get('initialized') is True and health.get('sealed') is False and health.get('standby') is False
            until(active, 'unsealed Bao did not become an active ready node')
            return
    raise RuntimeError('test operator unseal failed')


def owned(path, user):
    account = pwd.getpwnam(user)
    os.chown(path, account.pw_uid, account.pw_gid)


def as_agent(*args):
    unit = 'c13-bootstrap-' + uuid.uuid4().hex[:12] + '.service'
    return command(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + unit,
                    '-p', 'User=surveyscan-agent', '-p', 'Group=surveyscan-agent', '-p', 'StateDirectory=surveyscan-agent',
                    '-p', 'StateDirectoryMode=0700', '-p', 'LoadCredential=config:/etc/surveyscan-agent/config.json',
                    str(BIN / 'surveyscan-agent'), *args, '--config', '/run/credentials/' + unit + '/config'])


def first_boot(seed):
    phase('first_infra_setup')
    command(['python3', '/usr/local/lib/surveyscan-boot/updater.py', 'status', '--root', '/', '--public-key', str(SEED / 'release.pub')])
    until(lambda: sql('SELECT 1', 'postgres') == '1', 'PG17 not ready')
    sql('CREATE DATABASE surveyscan_v2', 'postgres')
    until(lambda: not bao('sys/init')['initialized'], 'Bao not ready')
    phase('first_bao_init')
    custody = bao('sys/init', {'secret_shares': 1, 'secret_threshold': 1})
    save('/root/operator-custody.json', custody)
    unseal(custody)
    root_token = custody['root_token']
    def admin(path, body=None):
        return bao(path, body, root_token)
    admin('sys/mounts/transit', {'type': 'transit'})
    keys = {}
    for name in ('ca', 'center'):
        admin('transit/keys/' + name, {'type': 'ed25519', 'exportable': False, 'allow_plaintext_backup': False})
        metadata = admin('transit/keys/' + name)['data']
        keys[name] = {'name': name, 'version': 1, 'public_key': base64.urlsafe_b64encode(base64.b64decode(metadata['keys']['1']['public_key'])).rstrip(b'=').decode()}
    paths = {'auth/token/lookup-self': ['read'], 'auth/token/renew-self': ['update']}
    for name in keys:
        paths['transit/keys/' + name] = ['read']
        paths['transit/sign/' + name] = ['update']
    policy = '\n'.join('path ' + json.dumps(path) + ' { capabilities=' + json.dumps(caps) + ' }' for path, caps in paths.items())
    admin('sys/policies/acl/surveyscan-server', {'policy': policy})
    token = admin('auth/token/create', {'policies': ['surveyscan-server'], 'no_default_policy': True, 'no_parent': True, 'period': '1h', 'renewable': True})['auth']['client_token']
    save('/etc/surveyscan-server/bao_token', token + '\n')
    bao_config = {'address': 'https://127.0.0.1:8200', 'tls_ca_file': '/etc/surveyscan-bao/ca.pem',
                  'token_file': '/etc/surveyscan-server/bao_token', 'policy': 'surveyscan-server',
                  'transit_mount': 'transit', 'kv_mount': 'kv', 'keys': keys, 'secrets': {}}
    save('/root/issuer-config.json', bao_config)
    phase('first_issuer')
    command([BIN / 'surveyscan-server', 'bootstrap-issuer', '--config', '/root/issuer-config.json', '--output-directory', '/root/issuer'])
    for name in ('ca.pem', 'server.pem', 'server.key'):
        shutil.copyfile('/root/issuer/' + name, '/etc/surveyscan-server/' + name)
        Path('/etc/surveyscan-server/' + name).chmod(0o600 if name.endswith('.key') else 0o644)
    bao_config['token_file'] = '/run/credentials/surveyscan-server.service/bao_token'
    save('/etc/surveyscan-server/bao.json', bao_config)
    machine = {'listen': '127.0.0.1:8443', 'ca_certificate_file': '/etc/surveyscan-server/ca.pem',
               'server_certificate_file': '/etc/surveyscan-server/server.pem',
               'server_private_key_file': '/run/credentials/surveyscan-server.service/server_key',
               'openbao_config_file': '/run/credentials/surveyscan-server.service/bao_config',
               'center_signing_key_id': str(uuid.uuid4())}
    save('/etc/surveyscan-server/machine.json', machine)
    save('/etc/surveyscan-server/pg_password', seed['pg_password'] + '\n')
    save('/etc/surveyscan-server/server.env', 'SURVEYSCAN_V2_DATABASE_URL=postgres://surveyscan_v2@127.0.0.1:5432/surveyscan_v2?sslmode=disable\nSURVEYSCAN_V2_LISTEN=127.0.0.1:8080\nSURVEYSCAN_V2_PUBLIC_ORIGIN=https://127.0.0.1:8444\nSURVEYSCAN_V2_BAO_ADDR=https://127.0.0.1:8200\n')
    command(['systemctl', 'start', 'surveyscan-migrate.service'])
    env = dict(os.environ, SURVEYSCAN_V2_DATABASE_URL='postgres://surveyscan_v2@127.0.0.1:5432/surveyscan_v2?sslmode=disable',
               SURVEYSCAN_V2_DATABASE_PASSWORD_FILE='/etc/surveyscan-server/pg_password')
    save('/root/admin-password', seed['admin_password'] + '\n')
    command([BIN / 'surveyscan-server', 'bootstrap-admin', '--tenant', seed['tenant'], '--tenant-name', 'Boot synthetic', '--username', 'admin', '--password-file', '/root/admin-password'], env=env)
    sql(f"INSERT INTO responsibility.subjects(tenant_id,subject_id,kind,name,contact) VALUES('{seed['tenant']}','{seed['subject']}','team','fallback','boot@example.invalid'); INSERT INTO scope.sites(tenant_id,site_id,name,fallback_subject_id) VALUES('{seed['tenant']}','{seed['site']}','boot','{seed['subject']}'); INSERT INTO scope.network_scopes(tenant_id,scope_id,site_id,namespace) VALUES('{seed['tenant']}','{seed['scope']}','{seed['site']}','default');")
    phase('first_center_start')
    command(['systemctl', 'enable', '--now', 'surveyscan-server.service'])
    tls = ssl.create_default_context(cafile='/etc/surveyscan-server/ca.pem')
    until(lambda: request(8443, tls, 'GET', '/health/ready')[0] == 200, 'systemd server not ready')
    origin = 'https://127.0.0.1:8444'
    status, session, headers = request(8443, tls, 'POST', '/api/v1/auth/sessions', {'username': 'admin', 'password': seed['admin_password']}, {'Origin': origin})
    assert status == 201
    cookie = headers['set-cookie'].split(';', 1)[0]
    user_headers = {'Origin': origin, 'Cookie': cookie, 'X-CSRF-Token': session['csrf_token']}
    phase('first_collector_enroll')
    collector = Path('/var/lib/surveyscan-collector')
    collector.mkdir(exist_ok=True, mode=0o700)
    command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', collector / 'tls.key'])
    command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', collector / 'signing.key'])
    command(['openssl', 'req', '-new', '-key', collector / 'tls.key', '-subj', '/CN=untrusted', '-out', collector / 'request.pem'])
    public = command(['openssl', 'pkey', '-in', collector / 'signing.key', '-pubout', '-outform', 'DER'])[-32:]
    der = command(['openssl', 'req', '-in', collector / 'request.pem', '-outform', 'DER'])
    source = str(uuid.uuid4())
    material = {'tenant_id': seed['tenant'], 'source_id': source, 'source_kind': 'collector', 'site_id': seed['site'], 'collector_id': None,
                'ttl_seconds': 900, 'csr_sha256': hashlib.sha256(der).hexdigest(), 'signing_public_key': base64.urlsafe_b64encode(public).rstrip(b'=').decode()}
    code, grant, _ = request(8443, tls, 'POST', '/api/v1/enrollments', material, user_headers)
    assert code == 201
    code, result, _ = request(8443, tls, 'POST', '/api/v1/machine/enroll', {'grant_id': grant['grant_id'], 'source_id': source,
        'csr_pem': (collector / 'request.pem').read_text(), 'signing_public_key': material['signing_public_key']}, {'Authorization': 'Bearer ' + grant['enrollment_token']})
    assert code == 201
    save(collector / 'tls.pem', result['certificate_chain_pem'])
    text = command(['openssl', 'x509', '-in', collector / 'tls.pem', '-noout', '-ext', 'subjectAltName']).decode()
    collector_id = re.search(r'/kind/collector/collector/([0-9a-f-]{36})', text).group(1)
    for path in collector.iterdir():
        path.chmod(0o600)
        owned(path, 'surveyscan-collector')
    owned(collector, 'surveyscan-collector')
    save('/etc/surveyscan-collector/config.json', {'source_id': source, 'credential_directory': str(collector / 'credentials'),
        'signing_private_key_file': str(collector / 'signing.key'), 'listen': '127.0.0.1:8445', 'center_url': 'https://127.0.0.1:8443',
        'certificate_file': str(collector / 'tls.pem'), 'private_key_file': str(collector / 'tls.key'),
        'ca_certificate_file': '/etc/surveyscan-server/ca.pem', 'spool_directory': str(collector / 'spool'), 'spool_limit_bytes': 4194304})
    phase('first_collector_start')
    command(['systemctl', 'enable', '--now', 'surveyscan-collector.service'])
    # Type=simple reports active before the TLS listener is ready. Verify CA and
    # the collector identity DNS name before issuing the first enrollment request.
    until(lambda: request(8445, tls, 'GET', '/health/live', server_name=source+'.collector.invalid')[0] == 200,
          'collector TLS listener not live')
    save('/etc/surveyscan-agent/config.json', {'tenant_id': seed['tenant'], 'site_id': seed['site'], 'network_scope_id': seed['scope'],
        'collector_url': 'https://127.0.0.1:8445', 'collector_source_id': source, 'ca_certificate_file': '/etc/surveyscan-server/ca.pem',
        'state_directory': '/var/lib/surveyscan-agent', 'inventory_seconds': 60, 'heartbeat_seconds': 30, 'jitter_percent': 0, 'spool_limit_bytes': 4194304})
    phase('first_agent_enroll')
    prep = json.loads(as_agent('prepare').decode().strip())
    body = {'tenant_id': seed['tenant'], 'source_id': prep['source_id'], 'source_kind': 'agent', 'site_id': seed['site'],
            'collector_id': collector_id, 'ttl_seconds': 900, 'csr_sha256': prep['csr_sha256'], 'signing_public_key': prep['signing_public_key']}
    code, grant, _ = request(8443, tls, 'POST', '/api/v1/enrollments', body, user_headers)
    assert code == 201
    save('/var/lib/surveyscan-agent/grant.json', grant)
    owned('/var/lib/surveyscan-agent/grant.json', 'surveyscan-agent')
    as_agent('enroll', '--grant-file', '/var/lib/surveyscan-agent/grant.json')
    Path('/var/lib/surveyscan-agent/grant.json').unlink()
    phase('first_agent_delivery')
    command(['systemctl', 'enable', '--now', 'surveyscan-agent.service'])
    until(lambda: sql('SELECT count(*) FROM inventory.observations') == '1', 'first systemd inventory missing')
    until(lambda: not list(Path('/var/lib/surveyscan-agent/spool').glob('*.pending')) and not list((collector / 'spool').glob('*.pending')), 'first signed ACK missing')
    asset = sql('SELECT asset_uid::text FROM assets.assets')
    phase('first_edge_start')
    for name in ('edge.pem', 'edge.key'):
        shutil.copyfile(SEED / name, '/etc/nginx/' + name)
        Path('/etc/nginx/' + name).chmod(0o600 if name.endswith('.key') else 0o644)
    for path in Path('/etc/nginx/sites-enabled').iterdir():
        path.unlink()
    save('/etc/nginx/sites-enabled/surveyscan', 'server { listen 127.0.0.1:8444 ssl; ssl_certificate /etc/nginx/edge.pem; ssl_certificate_key /etc/nginx/edge.key; root /opt/surveyscan/current/web; location /api/ { proxy_pass http://127.0.0.1:8080; } location /health/ { proxy_pass http://127.0.0.1:8080; } location /contracts/ { alias /opt/surveyscan/current/contracts/; } location / { try_files $uri /index.html; } }\n', 0o644)
    command(['systemctl', 'enable', '--now', 'nginx.service'])
    edge = ssl.create_default_context(cafile=str(SEED / 'infra-ca.pem'))
    until(lambda: request(8444, edge, 'GET', '/')[0] == 200, 'first edge TLS listener not live')
    # Leave a real packet durable on both hops, then reboot the kernel with all services enabled.
    phase('first_pre_reboot_pending')
    command(['systemctl', 'stop', 'surveyscan-server.service'])
    command(['systemctl', 'restart', 'surveyscan-agent.service'])
    until(lambda: list(Path('/var/lib/surveyscan-agent/spool').glob('*.pending')) and list((collector / 'spool').glob('*.pending')), 'pre-reboot pending missing')
    pending = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/var/lib/surveyscan-agent/spool').glob('*.pending')}
    save(STATE, {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'asset_uid': asset, 'source_id': prep['source_id'], 'cookie': cookie, 'pending': pending})
    print('SURVEYSCAN_BOOT_PHASE actual_kernel_reboot_requested', flush=True)
    command(['systemctl', 'reboot'])


def second_boot(seed):
    global LOGIN_PRESSURE
    phase('second_autostart')
    old = json.loads(STATE.read_text())
    assert old['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    CHECKS.append('real QEMU kernel reboot changes boot_id; PID1 is systemd, not a static parser/container init')
    services = ('postgresql', 'surveyscan-bao', 'surveyscan-migrate', 'surveyscan-server', 'surveyscan-collector', 'surveyscan-agent', 'nginx')
    for name in services:
        until(lambda name=name: subprocess.run(['systemctl', 'is-active', '--quiet', name + '.service']).returncode == 0, 'service did not autostart: ' + name)
        command(['systemctl', 'is-enabled', name + '.service']) if name != 'surveyscan-migrate' else None
    CHECKS.append('actual PG17/Bao/migrate/server/collector/agent/TLS static edge start automatically after reboot')
    phase('second_uid_sandbox')
    for name in ('server', 'collector', 'agent', 'bao'):
        pid = int(command(['systemctl', 'show', '-p', 'MainPID', '--value', 'surveyscan-' + name + '.service']))
        status = Path('/proc/' + str(pid) + '/status').read_text()
        assert int(re.search(r'^Uid:\s+(\d+)', status, re.M).group(1)) == pwd.getpwnam('surveyscan-' + name).pw_uid != 0
        assert re.search(r'^NoNewPrivs:\s+1', status, re.M)
    CHECKS.append('all four application/Bao services run as distinct static nonroot users with NoNewPrivileges and real LoadCredential')
    phase('second_sealed_startup')
    sealed = bao('sys/seal-status')
    assert sealed['sealed']
    tls = ssl.create_default_context(cafile='/etc/surveyscan-server/ca.pem')
    until(lambda: request(8443, tls, 'GET', '/health/live')[0] == 200, 'autostarted server TLS listener not live')
    assert request(8443, tls, 'GET', '/health/ready')[0] == 503
    code, card, _ = request(8443, tls, 'GET', '/api/v1/assets/' + old['asset_uid'], headers={'Cookie': old['cookie']})
    assert code == 200 and card['asset_uid'] == old['asset_uid']
    CHECKS.append('cold Bao is sealed: actual restarted center reports degraded readiness and still serves preserved registry/session')
    # Explicit test operator action, not an app service auto-unseal key.
    phase('second_unseal_replay')
    unseal(json.loads(Path('/root/operator-custody.json').read_text()))
    phase('second_center_readiness')
    until(lambda: request(8443, tls, 'GET', '/health/ready')[0] == 200, 'operator unseal did not restore readiness')
    phase('second_inventory_resume')
    until(lambda: int(sql('SELECT count(*) FROM inventory.observations')) >= 3, 'autostart did not continue source inventory')
    phase('second_queue_drain')
    until(lambda: not list(Path('/var/lib/surveyscan-agent/spool').glob('*.pending')) and not list(Path('/var/lib/surveyscan-collector/spool').glob('*.pending')), 'reboot queues did not drain')
    assert sql('SELECT asset_uid::text FROM assets.assets') == old['asset_uid']
    assert sql('SELECT count(*) FROM assets.assets') == '1'
    assert int(sql('SELECT max(source_sequence)::text FROM inventory.observations')) >= 3
    CHECKS.append('operator-owned unseal restores key ops; actual enabled daemons replay pre-reboot pending and continue >=sequence3 to one unchanged UID')
    env = dict(os.environ, SURVEYSCAN_V2_DATABASE_URL='postgres://surveyscan_v2@127.0.0.1:5432/surveyscan_v2?sslmode=disable', SURVEYSCAN_V2_DATABASE_PASSWORD_FILE='/etc/surveyscan-server/pg_password')
    phase('second_schema_check')
    command([BIN / 'surveyscan-server', 'schema-check'], env=env)
    assert sql('SELECT count(*) FROM platform.schema_migrations') == '47'
    CHECKS.append('all36 applied SQL hashes verify after real boot without duplicate migration or identity regeneration')
    phase('second_checked_update')
    script = '/usr/local/lib/surveyscan-boot/updater.py'
    command(['python3', script, 'prepare', '--root', '/', '--public-key', str(SEED / 'release.pub'), '--bundle', '/root/candidate'])
    command(['python3', script, 'apply', '--root', '/', '--public-key', str(SEED / 'release.pub'), '--health-url', 'https://127.0.0.1:8444/health/ready', '--ca-file', str(SEED / 'infra-ca.pem'), '--components', 'server', 'collector', 'agent'], timeout=180)
    current = json.loads(command([BIN / 'surveyscan-server', 'version']))
    assert current['version'] == '0.0.1-c13'
    assert not Path('/opt/surveyscan/update.fence').exists()
    assert json.loads(Path('/opt/surveyscan/update.json').read_text())['phase'] == 'complete'
    for name in ('server', 'collector', 'agent'):
        pid = int(command(['systemctl', 'show', '-p', 'MainPID', '--value', 'surveyscan-' + name + '.service']))
        assert '/releases/0.0.1-c13/' in os.readlink('/proc/' + str(pid) + '/exe')
    code, card, _ = request(8443, tls, 'GET', '/api/v1/assets/' + old['asset_uid'], headers={'Cookie': old['cookie']})
    assert code == 200 and card['asset_uid'] == old['asset_uid']
    CHECKS.append('actual systemd updater uses transient LoadCredential schema/migrate tasks, switches verified release and restarts healthy server with same session/UID')
    edge = ssl.create_default_context(cafile=str(SEED / 'infra-ca.pem'))
    assert request(8444, edge, 'GET', '/')[0] == 200
    CHECKS.append('separate static Web UI and TLS/API edge remain available after boot and verified server update')
    phase('second_edge_cli')
    assert shutil.which('go') is None and shutil.which('node') is None
    context = '/root/cli-session.json'
    cli = BIN / 'surveyscanctl'
    command([cli, 'login', '--server', 'https://127.0.0.1:8444', '--username', 'admin', '--password-file', '/root/admin-password',
             '--ca-file', str(SEED / 'infra-ca.pem'), '--context-file', context])
    card = json.loads(command([cli, 'assets', 'get', '--id', old['asset_uid'], '--context-file', context]))
    assert card['asset_uid'] == old['asset_uid']
    command([cli, 'logout', '--context-file', context])
    CHECKS.append('guest has no Go/Node build tools; separately shipped CLI logs in over TLS edge, reads preserved UID and revokes its session')
    if seed.get('login_pressure_probe'):
        import login_pressure
        phase('controlled_login_cpu_pressure')
        login_seconds = next(x['elapsed_seconds'] for x in CLI_TIMINGS if x['operation']=='login')
        matched, LOGIN_PRESSURE = login_pressure.probe(command, request, auth_diagnostics, sql, tls, seed, login_seconds)
        assert matched, 'controlled CPU profile did not establish the expected bounded login result'
        phase('controlled_login_cpu_recovery')
        command([cli, 'login', '--server', 'https://127.0.0.1:8444', '--username', 'admin', '--password-file', '/root/admin-password',
                 '--ca-file', str(SEED / 'infra-ca.pem'), '--context-file', context])
        command([cli, 'logout', '--context-file', context])
        CHECKS.append('opt-in CPU pressure matches the declared login result and credential conservation; test session revoked and explicit recovery succeeds')
    return {'package': 'C13', 'status': 'passed', 'count': len(CHECKS), 'checks': CHECKS, 'cli_timings': CLI_TIMINGS,
            'login_pressure': LOGIN_PRESSURE,
            'target': 'actual private QEMU TCG Debian/systemd VM with PG17/Bao2.7.2/nonroot app units, kernel reboot, HTTPS/mTLS and scoped non-exportable Transit PKI',
            'custody': 'explicit development test operator unseal after cold reboot; recovery keys never in app UID/unit/env',
            'unrun': ['two independently clean OS installations', 'schema-changing update through updater', 'physical power loss', 'production KMS/split custody/DR/RPO/RTO/100users']}


def main():
    try:
        seed = json.loads((SEED / 'seed.json').read_text())
        if STATE.exists():
            result = second_boot(seed)
            print('SURVEYSCAN_BOOT_RESULT ' + json.dumps(result), flush=True)
            command(['systemctl', 'poweroff'])
        else:
            first_boot(seed)
    except Exception as error:
        import traceback
        traceback.print_exc()
        debug = subprocess.run(['journalctl','-b','--no-pager','-n','100','-u','surveyscan-*'],capture_output=True)
        print(debug.stdout.decode(errors='replace'), flush=True)
        frames = [f for f in traceback.extract_tb(error.__traceback__) if Path(f.filename).name == 'guest.py']
        diagnostic = {'status': 'failed', 'error_type': type(error).__name__, 'phase': PHASE,
                      'failed_guest_line': frames[-1].lineno if frames else 0,
                      'guest_call_lines': [f.lineno for f in frames], 'completed_checks': len(CHECKS)}
        if PHASE == 'second_queue_drain':
            diagnostic['queue_diagnostics'] = queue_diagnostics()
        if isinstance(error, BaoFailure):
            diagnostic.update(bao_operation=error.operation, bao_http_status=error.status)
        if isinstance(error, CommandFailure):
            diagnostic.update(command_program=error.program, command_exit=error.code,
                              command_elapsed_seconds=error.elapsed, cli_error=error.cli_error)
            if error.program == 'surveyscanctl' and error.cli_error == 'HTTP_503':
                logs = subprocess.run(['journalctl','-b','--no-pager','-n','100','-o','cat',
                                       '-u','surveyscan-server.service'],capture_output=True)
                diagnostic['auth_diagnostics'] = auth_diagnostics(logs.stdout)
        if LOGIN_PRESSURE is not None:
            diagnostic['login_pressure'] = LOGIN_PRESSURE
        print('SURVEYSCAN_BOOT_RESULT ' + json.dumps(diagnostic), flush=True)
        command(['systemctl', 'poweroff'])


if __name__ == '__main__':main()
