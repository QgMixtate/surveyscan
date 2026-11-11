#!/usr/bin/env python3
"""C28.03: прогон обоих PoC на одном корпусе, проверки-«ворота», утечка доступа, баллы по весам C28-search-criteria.md.

compare.py WORK_DIR N REPEAT BLUGE_BIN TANTIVY_BIN → WORK_DIR/report.json и таблица в stdout.
Пиковая RSS — resource.getrusage(RUSAGE_CHILDREN) после завершения каждого процесса (отдельный python на движок).
"""
import json, resource, subprocess, sys
from pathlib import Path

work, N, repeat, bins = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3], {'bluge': sys.argv[4], 'tantivy': sys.argv[5]}
here = Path(__file__).resolve().parent
corpus = work / f'corpus{N}'
subprocess.run([sys.executable, str(here / 'corpus.py'), str(corpus), str(N)], check=True, stdout=subprocess.DEVNULL)
qf = json.loads((corpus / 'queries.json').read_text())
queries = {(q['phase'], q['qid']): q for q in qf['queries']}
truth = json.loads((corpus / 'truth.json').read_text())
openssl = set(qf['openssl_ids'])

# Шкала эксплуатационной пригодности (20) — зафиксирована до замеров производительности на 100 000 (R-027):
# сборка/поставка 8: встраивается в Go-монолит без CGO = 8; отдельный Rust-процесс (sidecar) или CGO = 4.
# кросс-сборка Linux/Windows 4: чистый Go = 4; Rust-цель Windows собирается отдельным тулчейном = 3.
# сопровождение 6: релиз за последние 12 мес. = 6; 12–24 мес. = 3; старше 24 мес. = 1.
# лицензия 2: разрешительная (MIT/Apache-2.0) = 2.
OPS = {
    'bluge': {'build': 8, 'cross': 4, 'maintenance': 1, 'license': 2,
              'facts': 'Go, встраивается в монолит без CGO; последний релиз v0.2.2 — 2022-07-04 (>24 мес.); Apache-2.0'},
    'tantivy': {'build': 4, 'cross': 3, 'maintenance': 6, 'license': 2,
                'facts': 'Rust: отдельный процесс (sidecar) или FFI через CGO; 0.27.0 — 2026-10-17, частые релизы; MIT'},
}


def passed(q, ids):
    exp, mode = q['expect'], q['mode']
    if mode == 'top1':
        return bool(ids) and ids[0] == exp[0]
    if mode == 'top10':
        return set(exp) <= set(ids[:10])
    if mode == 'recall':
        return set(exp) <= set(ids)
    if mode == 'exact':
        return set(ids) == set(exp)
    if mode == 'nonempty_openssl':
        return any(i in openssl for i in ids[:10])
    raise ValueError(mode)


report = {}
for engine, binary in bins.items():
    out = work / f'{engine}{N}.json'
    run = (f'import resource,subprocess,sys;r=subprocess.run(sys.argv[1:],stdout=open({str(out)!r},"w"));'
           f'print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss);sys.exit(r.returncode)')
    p = subprocess.run([sys.executable, '-c', run, binary, 'run', str(work / f'{engine}-idx'), str(corpus / 'corpus.jsonl'),
                        str(corpus / 'updates.jsonl'), str(corpus / 'deletes.txt'), str(corpus / 'queries.json'), repeat],
                       capture_output=True, text=True, check=True)
    r = json.loads(out.read_text())
    r['peak_rss_kib'] = int(p.stdout.strip())
    checks, gates = {}, {}
    for x in r['results']:
        q = queries[(x['Phase'], x['QID'])]
        checks[f"{x['Phase']}:{x['QID']}"] = {'pass': passed(q, x['IDs']), 'class': q['class'], 'p95_us': x['P95'], 'p50_us': x['P50'], 'found': len(x['IDs'])}
        # ворота 1: ни одного документа другого тенанта (по истине после изменений; удалённых в истине нет)
        foreign = [i for i in x['IDs'] if truth.get(i, q['tenant']) != q['tenant']]
        gates.setdefault('tenant_isolation', True)
        gates['tenant_isolation'] &= not foreign
        if x['Phase'] == 'B':  # ворота 2: удалённые не находятся
            gates.setdefault('deletes_invisible', True)
            gates['deletes_invisible'] &= all(i in truth for i in x['IDs'])
    # ворота 3: отзыв доступа без переиндексации — 100 активов тенанта 0 переданы тенанту 1 в источнике истины
    authority = dict(truth)
    for i in qf['acl_moved']:
        authority[i] = qf['tenants'][1]
    stale = [i for x in r['results'] if x['Phase'] == 'B' for i in x['IDs'] if i in set(qf['acl_moved'])]
    rechecked = [i for x in r['results'] if x['Phase'] == 'B' for i in x['IDs'] if authority[i] == queries[('B', x['QID'])]['tenant'] and i in set(qf['acl_moved'])]
    gates['acl_recheck_no_leak'] = not rechecked
    r['acl'] = {'stale_index_hits_without_recheck': len(stale), 'after_recheck': len(rechecked)}
    r['checks'], r['gates'] = checks, gates
    del r['results']
    report[engine] = r

# баллы
def frac(engine, pred):
    c = [v for v in report[engine]['checks'].values() if pred(v)]
    return sum(v['pass'] for v in c) / len(c)


def norm(values, lower_better=True):
    best = min(values.values()) if lower_better else max(values.values())
    return {k: (best / v if lower_better else v / best) if v else 1.0 for k, v in values.items()}


scores = {e: {} for e in report}
lat = {e: sum(v['p95_us'] for v in report[e]['checks'].values()) / len(report[e]['checks']) for e in report}
build = {e: report[e]['index_seconds'] + report[e]['rebuild_seconds'] for e in report}
size = {e: report[e]['index_bytes'] for e in report}
rss = {e: report[e]['peak_rss_kib'] for e in report}
for e in report:
    s = scores[e]
    s['correctness'] = 30 * frac(e, lambda v: v['class'] != 'bonus')
    s['morph_identifiers'] = 15 * frac(e, lambda v: v['class'] in ('identifier', 'morphology'))
    s['latency_p95'] = 15 * norm(lat)[e]
    s['indexing'] = 10 * norm(build)[e]
    s['resources'] = 5 * norm(size)[e] + 5 * norm(rss)[e]
    s['operations'] = sum(v for k, v in OPS[e].items() if k != 'facts')
    s['total'] = round(sum(s.values()), 1)
    s['gates_passed'] = all(report[e]['gates'].values())
summary = {'docs': N, 'repeat': int(repeat), 'ops_rubric': OPS, 'scores': scores,
           'metrics': {e: {'mean_p95_us': round(lat[e]), 'index_s': round(report[e]['index_seconds'], 2), 'rebuild_s': round(report[e]['rebuild_seconds'], 2),
                           'update_delete_s': round(report[e]['update_delete_seconds'], 3), 'index_mib': round(size[e] / 1048576, 1), 'peak_rss_mib': round(rss[e] / 1024),
                           'acl': report[e]['acl'], 'gates': report[e]['gates']} for e in report},
           'per_query': {e: {k: (v['pass'], v['p95_us']) for k, v in report[e]['checks'].items()} for e in report}}
(work / 'report.json').write_text(json.dumps(summary, ensure_ascii=False, indent=1))
print(json.dumps({k: summary[k] for k in ('scores', 'metrics')}, ensure_ascii=False, indent=1))
