"""Opt-in controlled CPU contention in a disposable VM, never on the host."""
import http.client
import subprocess
import time


def probe(command, request, parse_diagnostics, sql, tls, seed, login_seconds):
    # Conservative CLI startup allowance; target ~7s verification, between the
    # original 5s auth deadline and the server's 10s write timeout.
    quota = max(25, min(75, round((login_seconds - .8) / 7 * 100)))
    if seed.get('login_pressure_quota_percent'):
        quota = seed['login_pressure_quota_percent']
        if type(quota) is not int or not 25 <= quota <= 75:
            raise ValueError('invalid test CPU quota')
    expected = seed.get('login_pressure_expect_status',503)
    before = int(sql('SELECT count(*) FROM access.credentials'))
    code = None
    body, headers = None, {}
    diagnostics = []
    command(['systemctl','set-property','--runtime','surveyscan-server.service',f'CPUQuota={quota}%'])
    try:
        started = time.monotonic()
        try:
            code, body, headers = request(8443, tls, 'POST', '/api/v1/auth/sessions',
                                 {'username':'admin','password':seed['admin_password']},
                                 {'Origin':'https://127.0.0.1:8444'}, timeout=20)
        except (OSError,http.client.HTTPException):
            pass  # The allowlisted backend trace, not raw exception, is retained.
        elapsed_ms = round((time.monotonic()-started)*1000)
        until = time.monotonic() + 12
        while code != 201 and time.monotonic() < until:
            logs = subprocess.run(['journalctl','-b','--no-pager','-n','100','-o','cat',
                                   '-u','surveyscan-server.service'],capture_output=True)
            diagnostics = parse_diagnostics(logs.stdout)
            if diagnostics:
                break
            time.sleep(.2)
    finally:
        # Far above this two-vCPU VM's capacity; restore unconstrained execution
        # for the recovery check. No persistent unit or host cgroup is modified.
        command(['systemctl','set-property','--runtime','surveyscan-server.service','CPUQuota=10000%'])
    after = int(sql('SELECT count(*) FROM access.credentials'))
    revoked = False
    if code == 201 and isinstance(body,dict) and 'csrf_token' in body and 'set-cookie' in headers:
        # Test-owned session only; never export the cookie/CSRF or response body.
        cookie = headers['set-cookie'].split(';',1)[0]
        revoked = request(8443,tls,'DELETE','/api/v1/auth/session',headers={
            'Origin':'https://127.0.0.1:8444','Cookie':cookie,'X-CSRF-Token':body['csrf_token']})[0] == 204
    evidence = {'kind':'controlled-native-CPU-pressure','vm_cpu_quota_percent':quota,
                'http_status':code,'expected_http_status':expected,'elapsed_ms':elapsed_ms,
                'credential_count_unchanged':before==after,'credential_count_delta':after-before,
                'created_session_revoked':revoked,
                'auth_diagnostics':diagnostics,'historical_cause_proven':False}
    matched = expected == 503 and code == 503 and before == after and any(
        item['reason'] == 'deadline_exceeded' and item['verify_ms'] >= 5000 and
        item['stage'] in {'session_begin','user_recheck','active_sessions','session_insert','audit','commit'}
        for item in diagnostics)
    if expected == 201:
        matched = code == 201 and after == before+1 and revoked and elapsed_ms >= 5500
    return matched, evidence
