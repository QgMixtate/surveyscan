#!/usr/bin/env python3
"""C28 PoC: детерминированный корпус активов, обновления/удаления и запросы с ожидаемыми ответами.

Ожидания вычисляются по данным генератора (не по движкам). Запуск: corpus.py OUT_DIR [N]
Выход: corpus.jsonl, updates.jsonl, deletes.txt, queries.json (фаза A — до изменений, фаза B — после).
"""
import json, random, sys, uuid
from pathlib import Path

out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
N = int(sys.argv[2]) if len(sys.argv) > 2 else 100_000
rnd = random.Random(20261111)
TENANTS = [str(uuid.UUID(int=rnd.getrandbits(128), version=4)) for _ in range(5)]
TENANT_WEIGHTS = [50, 25, 12, 8, 5]
ROLES_EN = ['db', 'app', 'web', 'mail', 'file', 'dc', 'proxy', 'backup', 'build', 'mon']
ROLES_RU = ['бухгалтерия', 'склад', 'касса', 'кадры', 'приёмная', 'юристы', 'снабжение', 'логистика']
SOFTWARE = ['openssl 3.0.13', 'nginx 1.24', 'postgresql 16', 'docker-ce 27', 'python3 3.12', 'curl 8.5', 'git 2.43',
            'Microsoft Office 2021', '7-Zip 23.01', 'Google Chrome 130', 'Mozilla Firefox 132', 'Notepad++ 8.6',
            '1С:Предприятие 8.3', 'КриптоПро CSP 5.0', 'Консультант Плюс', 'Касперский Endpoint Security 12',
            'VipNet Client 4.5', 'Гарант-Аналитик', 'libssl3 3.0.13', 'python3-openssl 24.0', 'zabbix-agent 6.4',
            'Adobe Acrobat Reader 2024', 'Zoom 6.2', 'Яндекс Браузер 24.10', 'МойОфис Стандартный 2.8']
SURNAMES = ['Иванов', 'Петров', 'Сидоров', 'Кузнецов', 'Смирнов', 'Попов', 'Волков', 'Соколов', 'Лебедев', 'Козлов']
NAMES = ['Иван', 'Пётр', 'Анна', 'Мария', 'Сергей', 'Ольга', 'Дмитрий', 'Елена']
# назначение — русский текст с разными словоформами основы (для проверки морфологии)
PURPOSES = {
    'бухгалтер': ['Рабочее место бухгалтерии', 'Сервер бухгалтерского учёта', 'Терминал для бухгалтеров', 'Учёт в бухгалтерии филиала'],
    'склад': ['Учёт на складе', 'Терминал складского учёта', 'Сканер для складов'],
    'касс': ['Кассовый сервер', 'Рабочее место кассира', 'Обслуживание касс'],
    'резерв': ['Резервное копирование данных', 'Сервер резервных копий', 'Резервирование каналов'],
}


def doc(i):
    tenant = rnd.choices(TENANTS, TENANT_WEIGHTS)[0]
    os_ = rnd.choice(['linux', 'linux', 'windows', 'windows', 'windows', 'network'])
    if os_ == 'windows' and rnd.random() < 0.5:
        host = f'{rnd.choice(ROLES_RU)}-пк-{i:05d}'
    else:
        host = f'srv-{rnd.choice(ROLES_EN)}-{i:05d}'
    a, b, c = rnd.randrange(10, 12), rnd.randrange(0, 40), rnd.randrange(0, 250)
    ips = sorted({f'10.{a}.{b}.{c}'} | {f'10.{a}.{b}.{rnd.randrange(1, 254)}' for _ in range(rnd.randrange(0, 3))})
    stem = rnd.choice(list(PURPOSES))
    software = rnd.sample(SOFTWARE, rnd.randrange(5, 16))
    if os_ != 'windows':
        software = [s for s in software if not s.startswith(('Microsoft', '1С', 'КриптоПро', 'Консультант', 'Касперский', 'VipNet', 'Гарант', 'Adobe', 'Zoom', 'Яндекс', 'МойОфис', '7-Zip', 'Google', 'Mozilla', 'Notepad'))] or ['openssl 3.0.13']
    serial = ''.join(rnd.choice('ABCDEFGHJKLMNPQRSTUVWXYZ0123456789') for _ in range(10))
    serial = ''.join(ch.lower() if rnd.random() < 0.3 else ch for ch in serial)
    return {'id': str(uuid.UUID(int=rnd.getrandbits(128), version=4)), 'tenant': tenant, 'site': f'site-{rnd.randrange(1, 4)}', 'os': os_,
            'host': host, 'fqdn': f'{host}.corp.example.test' if host.isascii() else f'pc{i:05d}.corp.example.test', 'ips': ips,
            'mac': ':'.join(f'{rnd.randrange(256):02x}' for _ in range(6)), 'serial': serial,
            'owner': f'{rnd.choice(SURNAMES)} {rnd.choice(NAMES)}', 'purpose': rnd.choice(PURPOSES[stem]), '_stem': stem, 'software': software}


docs = [doc(i) for i in range(N)]
by_id = {d['id']: d for d in docs}
# изменения: 1 000 обновлений (новое имя хоста, + ПО zabbix), 2 000 удалений; не пересекаются
shuffled = docs[:]
rnd.shuffle(shuffled)
updates, deleted = [], set()
for d in shuffled[:1000]:
    u = dict(d)
    u['host'] = 'renamed-' + d['host'] if d['host'].isascii() else 'переименован-' + d['host']
    u['software'] = sorted(set(d['software']) | {'zabbix-agent 6.4'})
    updates.append(u)
for d in shuffled[1000:3000]:
    deleted.add(d['id'])
after = {**by_id, **{u['id']: u for u in updates}}
for i in deleted:
    del after[i]


def public(d):
    return {k: v for k, v in d.items() if not k.startswith('_')}


with open(out / 'corpus.jsonl', 'w') as f:
    for d in docs:
        f.write(json.dumps(public(d), ensure_ascii=False) + '\n')
with open(out / 'updates.jsonl', 'w') as f:
    for u in updates:
        f.write(json.dumps(public(u), ensure_ascii=False) + '\n')
(out / 'deletes.txt').write_text('\n'.join(sorted(deleted)) + '\n')

# --- запросы и ожидания ---
queries = []


def add(phase, qid, tenant, kind, field, value, expect, mode, cls, k=200000, filters=None):
    queries.append({'phase': phase, 'qid': qid, 'tenant': tenant, 'kind': kind, 'field': field, 'value': value,
                    'filters': filters or {}, 'k': k, 'expect': sorted(expect), 'mode': mode, 'class': cls})


def pick(pool, cond):
    for d in pool:
        if cond(d):
            return d
    raise SystemExit('generator: no document for condition')


for phase, pool in (('A', by_id), ('B', after)):
    vals = list(pool.values())
    t0 = TENANTS[0]
    d = pick(vals, lambda d: d['tenant'] == t0 and d['host'].startswith('srv-db-'))
    add(phase, 'host_exact', t0, 'term', 'host', d['host'], [d['id']], 'top1', 'identifier')
    pre = d['host'][:-2]  # srv-db-0xx
    add(phase, 'host_prefix', t0, 'prefix', 'host', pre, [x['id'] for x in vals if x['tenant'] == t0 and x['host'].startswith(pre)], 'recall', 'identifier')
    ip = d['ips'][0]
    add(phase, 'ip_exact', t0, 'term', 'ip', ip, [x['id'] for x in vals if x['tenant'] == t0 and ip in x['ips']], 'recall', 'identifier')
    subnet = ip.rsplit('.', 1)[0] + '.'
    add(phase, 'ip_subnet', t0, 'prefix', 'ip', subnet, [x['id'] for x in vals if x['tenant'] == t0 and any(i.startswith(subnet) for i in x['ips'])], 'recall', 'identifier')
    part = d['fqdn'].split('.', 1)[0].split('-', 1)[1] + '.corp'  # db-01234.corp
    add(phase, 'fqdn_part', t0, 'phrase', 'fqdn', part, [x['id'] for x in vals if x['tenant'] == t0 and ('-' + part + '.') in ('-' + x['fqdn'])], 'top10', 'identifier', k=10)
    add(phase, 'serial_ci', t0, 'term', 'serial', d['serial'].swapcase(), [d['id']], 'top1', 'identifier')
    ru = pick(vals, lambda x: x['tenant'] == t0 and x['host'].startswith('бухгалтерия-пк-'))
    add(phase, 'host_cyrillic', t0, 'term', 'host', ru['host'], [ru['id']], 'top1', 'identifier')
    add(phase, 'ru_morph', t0, 'match', 'text', 'бухгалтерии', [x['id'] for x in vals if x['tenant'] == t0 and x['_stem'] == 'бухгалтер' and x['purpose'] != 'Сервер бухгалтерского учёта'], 'recall', 'morphology')  # прилагательное — другая основа (стемминг, не лемматизация)
    add(phase, 'ru_morph2', t0, 'match', 'text', 'резервного копирования', [x['id'] for x in vals if x['tenant'] == t0 and x['purpose'] == 'Резервное копирование данных'], 'recall', 'morphology')
    add(phase, 'sw_en', t0, 'match', 'text', 'openssl', [x['id'] for x in vals if x['tenant'] == t0 and any(s.split()[0].lower() in ('openssl',) for s in x['software'])], 'recall', 'software')
    add(phase, 'sw_ru', t0, 'match', 'text', '1С Предприятие', [x['id'] for x in vals if x['tenant'] == t0 and '1С:Предприятие 8.3' in x['software']], 'recall', 'software')
    add(phase, 'sw_filter', t0, 'match', 'text', 'nginx', [x['id'] for x in vals if x['tenant'] == t0 and x['os'] == 'linux' and 'nginx 1.24' in x['software']], 'recall', 'software', filters={'os': 'linux'})
    add(phase, 'owner_ru', t0, 'match', 'text', 'Кузнецова', [x['id'] for x in vals if x['tenant'] == t0 and x['owner'].startswith('Кузнецов ')], 'recall', 'morphology')
    add(phase, 'typo', t0, 'fuzzy', 'text', 'opensl', [], 'nonempty_openssl', 'bonus', k=10)
    # тенант: запрос хоста чужого тенанта ничего не находит
    other = pick(vals, lambda x: x['tenant'] == TENANTS[1])
    add(phase, 'tenant_isolation', t0, 'term', 'host', other['host'], [], 'exact', 'gate')

# фаза B: переименованные, удалённые
u = next(x for x in updates if x['tenant'] == TENANTS[0] and x['host'].isascii())
add('B', 'renamed_new', TENANTS[0], 'term', 'host', u['host'], [u['id']], 'top1', 'change')
add('B', 'renamed_old', TENANTS[0], 'term', 'host', by_id[u['id']]['host'], [], 'exact', 'change')
dd = next(by_id[i] for i in sorted(deleted) if by_id[i]['tenant'] == TENANTS[0])
add('B', 'deleted_host', TENANTS[0], 'term', 'host', dd['host'], [], 'exact', 'gate')
add('B', 'zabbix_after_update', TENANTS[0], 'match', 'text', 'zabbix', [x['id'] for x in after.values() if x['tenant'] == TENANTS[0] and any(s.startswith('zabbix') for s in x['software'])], 'recall', 'change')

# доступ: 100 активов тенанта 0 «переданы» тенанту 1 в источнике истины без переиндексации
moved = [x['id'] for x in after.values() if x['tenant'] == TENANTS[0]][:100]
(out / 'queries.json').write_text(json.dumps({'tenants': TENANTS, 'queries': queries, 'acl_moved': moved,
                                              'openssl_ids': sorted(x['id'] for x in after.values() if any(s.startswith(('openssl', 'libssl', 'python3-openssl')) for s in x['software']))}, ensure_ascii=False))
(out / 'truth.json').write_text(json.dumps({x['id']: x['tenant'] for x in after.values()}))
print(json.dumps({'docs': N, 'updates': len(updates), 'deletes': len(deleted), 'queries': len(queries)}))
