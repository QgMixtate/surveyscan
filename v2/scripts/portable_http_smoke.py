#!/usr/bin/env python3
# Сквозная проверка C23.03 HTTPS-загрузки настоящим центром (обвязка machine_smoke, профиль 1.2 включён).
import http.client, json, re, subprocess, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from dev import ROOT
from machine_smoke import main as harness

def scenario(command, request, tenant, site, scope, tls_port, plain, origin, cookie, session, checks, **_):
    work = Path(tempfile.mkdtemp())
    portable = str(ROOT / '.dist/surveyscan-portable')
    if not Path(portable).is_file():  # make build не собирает portable
        subprocess.run(['go', 'build', '-trimpath', '-o', portable, './cmd/surveyscan-portable'], cwd=ROOT, check=True, timeout=300)
    out = subprocess.run([portable, 'init', '--state', str(work/'state'), '--tenant', tenant, '--site', site, '--scope', scope], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    source = re.search(r'source_id=(\S+)', out.stdout).group(1)
    public = re.search(r'public_key=(\S+)', out.stdout).group(1)
    generation = None
    for f in (work/'state').rglob('*.json'):
        m = re.search(r'"generation_id"\s*:\s*"([0-9a-f-]{36})"', f.read_text())
        if m: generation = m.group(1)
    assert generation, 'generation not found in state'
    pkg = work/'audit.zip'
    out = subprocess.run([portable, 'collect', '--state', str(work/'state'), '--out', str(pkg)], capture_output=True, text=True, timeout=600)
    assert out.returncode == 0 and pkg.is_file(), out.stdout + out.stderr
    data = pkg.read_bytes()
    command('portable-register', '--tenant', tenant, '--site', site, '--scope', scope, '--source', source, '--generation', generation, '--public-key', public)
    path = f'/api/v1/sources/{source}/portable-import'
    def upload(trickle):
        c = http.client.HTTPSConnection('127.0.0.1', tls_port, context=plain, timeout=60)
        c.putrequest('POST', path)
        for k, v in {'Origin': origin, 'Cookie': cookie, 'X-CSRF-Token': session['csrf_token'], 'Content-Type': 'application/zip', 'Content-Length': str(len(data))}.items():
            c.putheader(k, v)
        c.endheaders()
        start = time.monotonic(); parts = 15 if trickle else 1; step = -(-len(data)//parts)
        for i in range(0, len(data), step):
            c.send(data[i:i+step])
            if trickle: time.sleep(1)
        r = c.getresponse(); body = r.read(); c.close()
        return r.status, body, time.monotonic() - start
    status, body, took = upload(True)
    assert status == 200, (status, body[:300])
    report = json.loads(body)
    disp = [r['disposition'] for r in report['records']]
    assert report['source_id'] == source and disp and all(d == 'applied' for d in disp), report
    status, body, _ = upload(False)
    assert status == 200 and all(r['disposition'] == 'duplicate' for r in json.loads(body)['records']), body[:300]
    checks.append(f'portable HTTPS upload: {len(data)} bytes trickled over {took:.1f}s (> server ReadTimeout 10s) applied={len(disp)}; repeat duplicate')
    print('E2E', checks[-1], flush=True)

harness(agent_scenario=lambda **s: scenario(**s), inventory12=True)
