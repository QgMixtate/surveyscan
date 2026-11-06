"""Opt-in controlled CPU contention in a disposable VM, never on the host."""
import http.client
import subprocess
import time


def probe(command, request, parse_diagnostics, sql, tls, seed, login_seconds):
    # Conservative CLI startup allowance; target ~7s verification, between the
    # original 5s auth deadline and the server's 10s write timeout.
    quota = max(25, min(75, round((login_seconds - .8) / 7 * 100)))
    before = int(sql('SELECT count(*) FROM access.credentials'))
    code = None
    diagnostics = []
    command(['systemctl','set-property','--runtime','surveyscan-server.service',f'CPUQuota={quota}%'])
    try:
        try:
            code, _, _ = request(8443, tls, 'POST', '/api/v1/auth/sessions',
                                 {'username':'admin','password':seed['admin_password']},
                                 {'Origin':'https://127.0.0.1:8444'}, timeout=20)
        except (OSError,http.client.HTTPException):
            pass  # The allowlisted backend trace, not raw exception, is retained.
        until = time.monotonic() + 12
        while time.monotonic() < until:
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
    evidence = {'kind':'controlled-native-CPU-pressure','vm_cpu_quota_percent':quota,
                'http_status':code,'credential_count_unchanged':before==after,
                'auth_diagnostics':diagnostics,'historical_cause_proven':False}
    matched = code == 503 and before == after and any(
        item['reason'] == 'deadline_exceeded' and item['verify_ms'] >= 5000 and
        item['stage'] in {'session_begin','user_recheck','active_sessions','session_insert','audit','commit'}
        for item in diagnostics)
    return matched, evidence
