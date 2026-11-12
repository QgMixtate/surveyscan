#!/usr/bin/env python3
"""C34.03 — еженедельный отчёт пилота по API центра (только чтение; ничего не меняет).

  pilot_report.py --url https://127.0.0.1:<порт центра> --ca ca.pem --origin http://10.170.108.2:8090 --user admin --password-file /root/.pilot-pw [--out report.json]

Показатели: активы и свежесть, доля с ответственным (не резервная команда), конфликты, источники, синхронизация с
каталогом, уведомления, предупреждения диагностики. Пароль — только из приватного файла (0600), в вывод не попадает.
Сессия закрывается в конце (не копит сессии пользователя).
"""
import argparse, http.client, json, os, ssl, stat, sys, urllib.parse
from datetime import datetime, timezone


class API:
    def __init__(self, url, ca, origin=None):
        u = urllib.parse.urlparse(url)
        assert u.scheme == 'https', 'https only'
        self.host, self.port = u.hostname, u.port or 443
        self.ctx = ssl.create_default_context(cafile=ca)
        self.origin, self.cookie, self.csrf = origin or f'{u.scheme}://{u.netloc}', None, None

    def call(self, method, path, body=None):
        c = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=60)
        h = {'Origin': self.origin, 'Content-Type': 'application/json'}
        if self.cookie:
            h['Cookie'] = self.cookie
        if self.csrf and method != 'GET':
            h['X-CSRF-Token'] = self.csrf
        c.request(method, path, body=None if body is None else json.dumps(body), headers=h)
        r = c.getresponse()
        raw = r.read()
        cookie = r.getheader('Set-Cookie')
        c.close()
        if r.status >= 400:
            raise SystemExit(f'{method} {path}: HTTP {r.status}')
        return (json.loads(raw) if raw else None), cookie

    def pages(self, path, key='items'):
        cursor, out = None, []
        while True:
            sep = '&' if '?' in path else '?'
            data, _ = self.call('GET', path + (sep + 'cursor=' + urllib.parse.quote(cursor) if cursor else ''))
            out += data[key]
            cursor = data.get('next_cursor')
            if not cursor:
                return out


def private(path):
    info = os.stat(path)
    assert stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077, 'password file must be private (0600)'
    return open(path).read().strip()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--url', required=True)
    p.add_argument('--ca', required=True)
    p.add_argument('--user', required=True)
    p.add_argument('--password-file', required=True)
    p.add_argument('--origin', help='адрес Web-интерфейса, как в браузере (центр сверяет Origin), например http://10.170.108.2:8090')
    p.add_argument('--out')
    a = p.parse_args()
    api = API(a.url, a.ca, a.origin)
    session, cookie = api.call('POST', '/api/v1/auth/sessions', {'username': a.user, 'password': private(a.password_file)})
    api.cookie, api.csrf = cookie.split(';', 1)[0], session['csrf_token']
    try:
        assets = api.pages('/api/v1/assets?limit=200')
        subjects = api.pages('/api/v1/subjects?limit=200&include_inactive=true')
        fallback = {s['subject_id'] for s in subjects if s['site_fallback']}
        conflicts = api.pages('/api/v1/reconciliation/conflicts?state=open&limit=50')
        diagnostics, _ = api.call('GET', '/api/v1/diagnostics')
        directory, _ = api.call('GET', '/api/v1/directory-sync')
        webhooks, _ = api.call('GET', '/api/v1/webhooks')
    finally:
        api.call('DELETE', '/api/v1/auth/session')
    n = len(assets)
    fresh = sum(1 for x in assets if x['freshness'] == 'fresh')
    owned = sum(1 for x in assets if x['accountable_subject_id'] not in fallback)
    pct = lambda k: round(100 * k / n, 1) if n else None
    sources = diagnostics.get('sources', [])
    last_run = directory['runs'][0] if directory['runs'] else None
    report = {
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'assets': n,
        'fresh': fresh, 'fresh_pct': pct(fresh), 'target_fresh_pct': 95,
        'with_owner': owned, 'with_owner_pct': pct(owned), 'target_owner_pct': 90,
        'stale_or_unknown': [x.get('observed_hostname') or x['asset_uid'] for x in assets if x['freshness'] != 'fresh'][:50],
        'open_conflicts': len(conflicts),
        'sources': len(sources),
        'people_and_teams': {'active': sum(1 for s in subjects if s['active']), 'from_directory': sum(1 for s in subjects if s.get('origin') == 'ldap')},
        'directory_sync': None if not directory['configured'] else {'last_status': last_run and last_run['status'], 'last_started_at': last_run and last_run['started_at'], 'last_error': last_run and last_run['error']},
        'webhooks': {'enabled': webhooks['enabled'], 'subscriptions': len(webhooks['items']), 'dead': sum(w['dead'] for w in webhooks['items'])},
        'alerts': [x['code'] for x in diagnostics.get('alerts', [])],
        'backup_age_hours': None if diagnostics.get('backup_age_seconds') is None else round(diagnostics['backup_age_seconds'] / 3600, 1),
    }
    text = json.dumps(report, ensure_ascii=False, indent=1)
    if a.out:
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(text + '\n')
    print(text)


if __name__ == '__main__':
    sys.exit(main())
