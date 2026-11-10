#!/usr/bin/env python3
# Сквозная проверка C23.03 HTTPS-загрузки portable настоящим центром (обвязка machine_smoke, профиль 1.2 включён):
#  1) медленная загрузка тела (дольше серверного ReadTimeout) напрямую в центр — продление дедлайнов;
#  2) клиент surveyscanctl `sources portable-import` через edge-прокси с deploy/nginx.conf (лимит/таймауты location);
#  3) с --big-count N: пакет из N наблюдений (десятки МиБ) через тот же nginx и CLI.
import argparse, http.client, json, os, re, socket, subprocess, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev import ROOT
from machine_smoke import main as harness

NGINX_IMAGE = 'nginxinc/nginx-unprivileged:1.30-alpine'


def freeport():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run(args, timeout, env=None):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=ROOT, env=env)
    assert p.returncode == 0, (args[:3], p.stdout[-2000:], p.stderr[-2000:])
    return p.stdout


def scenario(args, nginx_port, command, tenant, site, scope, tls_port, plain, origin, cookie, session, checks, directory, sql, server_environment, **_):
    work = Path(tempfile.mkdtemp())
    portable = str(ROOT / '.dist/surveyscan-portable')
    if not Path(portable).is_file():  # make build не собирает portable
        run(['go', 'build', '-trimpath', '-o', portable, './cmd/surveyscan-portable'], 300)
    out = run([portable, 'init', '--state', str(work / 'state'), '--tenant', tenant, '--site', site, '--scope', scope], 30)
    source = re.search(r'source_id=(\S+)', out).group(1)
    public = re.search(r'public_key=(\S+)', out).group(1)
    generation = None
    for f in (work / 'state').rglob('*.json'):
        m = re.search(r'"generation_id"\s*:\s*"([0-9a-f-]{36})"', f.read_text())
        if m:
            generation = m.group(1)
    assert generation, 'generation not found in state'
    pkg = work / 'audit.zip'
    run([portable, 'collect', '--state', str(work / 'state'), '--out', str(pkg)], 600)
    data = pkg.read_bytes()
    command('portable-register', '--tenant', tenant, '--site', site, '--scope', scope, '--source', source, '--generation', generation, '--public-key', public)
    path = f'/api/v1/sources/{source}/portable-import'

    # 1) медленная загрузка напрямую в центр
    def upload(trickle):
        c = http.client.HTTPSConnection('127.0.0.1', tls_port, context=plain, timeout=60)
        c.putrequest('POST', path)
        for k, v in {'Origin': f'http://127.0.0.1:{nginx_port}', 'Cookie': cookie, 'X-CSRF-Token': session['csrf_token'], 'Content-Type': 'application/zip', 'Content-Length': str(len(data))}.items():
            c.putheader(k, v)
        c.endheaders()
        start = time.monotonic(); parts = 17 if trickle else 1; step = -(-len(data) // parts)
        for i in range(0, len(data), step):
            c.send(data[i:i + step])
            if trickle:
                time.sleep(1)
        r = c.getresponse(); body = r.read(); c.close()
        return r.status, body, time.monotonic() - start
    status, body, took = upload(True)
    assert status == 200, (status, body[:300])
    report = json.loads(body)
    disp = [r['disposition'] for r in report['records']]
    assert report['source_id'] == source and disp and all(d == 'applied' for d in disp), report
    checks.append(f'direct upload: {len(data)} bytes trickled over {took:.1f}s (> server ReadTimeout) applied={len(disp)}')
    print('E2E', checks[-1], flush=True)

    # 2) CLI через nginx (deploy/nginx.conf, backend → человеческий API центра)
    http_port = server_environment['SURVEYSCAN_V2_LISTEN'].rsplit(':', 1)[1]
    conf = (ROOT / 'deploy/nginx.conf').read_text()
    assert 'listen 8080;' in conf and 'http://backend:8080' in conf
    conf = conf.replace('listen 8080;', f'listen 127.0.0.1:{nginx_port};').replace('http://backend:8080', f'http://127.0.0.1:{http_port}')
    (work / 'nginx.conf').write_text(conf)
    os.chmod(work, 0o755); os.chmod(work / 'nginx.conf', 0o644)
    name = 'ssv2-portable-edge-' + str(nginx_port)
    run(['docker', 'run', '-d', '--rm', '--name', name, '--network', 'host', '-v', f'{work}/nginx.conf:/etc/nginx/nginx.conf:ro', NGINX_IMAGE], 120)
    try:
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', nginx_port), timeout=1).close(); break
            except OSError:
                time.sleep(0.2)
        cli = str(ROOT / '.dist/surveyscanctl')
        ctx = work / 'cli-context.json'
        run([cli, 'login', '--server', f'http://127.0.0.1:{nginx_port}', '--dev-loopback-http', '--username', 'admin', '--password-file', str(directory / 'password'), '--context-file', str(ctx)], 30)
        out = json.loads(run([cli, 'sources', 'portable-import', '--context-file', str(ctx), '--id', source, '--package', str(pkg)], 60))
        assert out['source_id'] == source and all(r['disposition'] == 'duplicate' for r in out['records']), out
        checks.append('surveyscanctl sources portable-import via nginx: repeat of the same package = duplicate')
        print('E2E', checks[-1], flush=True)

        # 3) большой пакет через nginx и CLI
        if args.big_count:
            big = work / 'big.zip'
            env = dict(os.environ, SURVEYSCAN_BIGPKG_STATE=str(work / 'state'), SURVEYSCAN_BIGPKG_OUT=str(big), SURVEYSCAN_BIGPKG_COUNT=str(args.big_count))
            run(['go', 'test', '-count=1', '-run', '^TestWriteBigPackage$', '-v', './internal/portableaudit'], 900, env)
            size = big.stat().st_size
            start = time.monotonic()
            out = json.loads(run([cli, 'sources', 'portable-import', '--context-file', str(ctx), '--id', source, '--package', str(big)], 2400))
            took = time.monotonic() - start
            disp = {}
            for r in out['records']:
                disp[r['disposition']] = disp.get(r['disposition'], 0) + 1
            assert out['complete'] and len(out['records']) == args.big_count and disp.get('applied') == args.big_count, disp
            stored = int(sql(f"SELECT count(*) FROM inventory.observations WHERE source_id='{source}'"))
            assert stored == args.big_count + 1, stored
            checks.append(f'big package via nginx+CLI: {size} bytes, {args.big_count} observations applied in {took:.1f}s over {out["attempts"]} request(s); stored={stored}')
            print('E2E', checks[-1], flush=True)
    finally:
        subprocess.run(['docker', 'logs', '--tail', '5', name], cwd=ROOT)
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, cwd=ROOT)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--big-count', type=int, default=0, help='число наблюдений большого пакета (0 — не проверять)')
    args = parser.parse_args()
    nginx_port = freeport()
    harness(agent_scenario=lambda **s: scenario(args, nginx_port, **s), inventory12=True, browser_origin=f'http://127.0.0.1:{nginx_port}')
