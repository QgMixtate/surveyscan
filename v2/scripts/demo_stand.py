#!/usr/bin/env python3
# Демо-стенд (только для показа, НЕ проверка):  настоящий центр (обвязка machine_smoke) + Web UI + данные: синтетический агент 1.0 и portable-аудит хоста песочницы.
import http.server, json, os, re, subprocess, sys, tempfile, threading, urllib.parse
from pathlib import Path
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent))
import web_smoke
from machine_smoke import main as harness, freeport
from dev import ROOT
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / '.local/demo'
OUT.mkdir(parents=True, exist_ok=True)
DEMO_JS = str(Path(__file__).resolve().parents[1] / 'web/scripts/demo.mjs')
SPEC = str(Path(__file__).resolve().parent / 'demo_network.json')

def scenario(**s):
    work = Path(tempfile.mkdtemp())
    portable = str(ROOT / '.dist/surveyscan-portable')
    # site/scope берём из БД (обвязка web_scenario их не передаёт)
    site, scope = s['sql']("SELECT site_id::text||' '||scope_id::text FROM scope.network_scopes LIMIT 1").split()
    o = subprocess.run([portable, 'init', '--state', str(work/'state'), '--tenant', s['tenant'], '--site', site, '--scope', scope], capture_output=True, text=True, check=True)
    source = re.search(r'source_id=(\S+)', o.stdout).group(1); public = re.search(r'public_key=(\S+)', o.stdout).group(1)
    gen = [re.search(r'"generation_id"\s*:\s*"([0-9a-f-]{36})"', f.read_text()) for f in (work/'state').rglob('*.json')]
    gen = [g.group(1) for g in gen if g][0]
    collect = subprocess.run([portable, 'collect', '--state', str(work/'state'), '--out', str(work/'audit.zip')], capture_output=True, text=True, check=True)
    (OUT/'portable-collect.txt').write_text(collect.stdout)
    s['command']('portable-register', '--tenant', s['tenant'], '--site', site, '--scope', scope, '--source', source, '--generation', gen, '--public-key', public)
    imp = s['command']('portable-import', '--tenant', s['tenant'], '--source', source, '--package', str(work/'audit.zip'))
    (OUT/'portable-import.json').write_text(imp)
    # ДЕМО-набор синтетических хостов (схема сети/карточка 1.2) — отдельный portable-источник
    o = subprocess.run([portable, 'init', '--state', str(work/'demo'), '--tenant', s['tenant'], '--site', site, '--scope', scope], capture_output=True, text=True, check=True)
    dsource = re.search(r'source_id=(\S+)', o.stdout).group(1); dpublic = re.search(r'public_key=(\S+)', o.stdout).group(1)
    dgen = [g.group(1) for g in (re.search(r'"generation_id"\s*:\s*"([0-9a-f-]{36})"', f.read_text()) for f in (work/'demo').rglob('*.json')) if g][0]
    env = dict(os.environ, SURVEYSCAN_DEMOPKG_STATE=str(work/'demo'), SURVEYSCAN_DEMOPKG_OUT=str(work/'demo.zip'), SURVEYSCAN_DEMOPKG_SPEC=SPEC)
    subprocess.run(['go', 'test', '-count=1', '-run', '^TestWriteDemoPackage$', './internal/portableaudit'], cwd=ROOT, env=env, check=True, capture_output=True, timeout=600)
    s['command']('portable-register', '--tenant', s['tenant'], '--site', site, '--scope', scope, '--source', dsource, '--generation', dgen, '--public-key', dpublic)
    (OUT/'demo-import.json').write_text(s['command']('portable-import', '--tenant', s['tenant'], '--source', dsource, '--package', str(work/'demo.zip')))
    # CLI-представление (как у оператора)
    # Web UI через тот же прокси, что web_smoke (статический бандл + /api → центр)
    orig_run = subprocess.run
    def fake_node(cmd, **kw):
        if cmd[:2] == ['node', 'scripts/smoke.mjs']:
            cli = str(ROOT/'.dist/surveyscanctl'); ctxf = work/'ctx.json'; pw = work/'pw'; pw.write_text(s['password'] + '\n'); os.chmod(pw, 0o600)
            orig_run([cli, 'login', '--server', s['origin'], '--dev-loopback-http', '--username', 'admin', '--password-file', str(pw), '--context-file', str(ctxf)], check=True, capture_output=True)
            with open(OUT/'cli.txt', 'w') as f:
                for args in (['assets', 'list', '--output', 'table'], ['sources', 'list', '--output', 'table'], ['status']):
                    r = orig_run([cli, *args, '--context-file', str(ctxf)], capture_output=True, text=True)
                    f.write('$ surveyscanctl ' + ' '.join(args) + '\n' + r.stdout + r.stderr + '\n')
                assets = json.loads(orig_run([cli, 'assets', 'list', '--context-file', str(ctxf)], capture_output=True, text=True).stdout)
                for a in assets.get('items', []):
                    r = orig_run([cli, 'assets', 'get', '--id', a['asset_uid'], '--context-file', str(ctxf)], capture_output=True, text=True)
                    f.write('$ surveyscanctl assets get --id ' + a['asset_uid'] + '\n' + r.stdout + '\n')
            return orig_run(['node', DEMO_JS, cmd[2], str(OUT)], **kw)
        return orig_run(cmd, **kw)
    web_smoke.subprocess.run = fake_node
    try:
        web_smoke.browser_scenario(**s)
    finally:
        web_smoke.subprocess.run = orig_run

harness(web_scenario=scenario, browser_origin=f'http://127.0.0.1:{freeport()}', inventory12=True)
