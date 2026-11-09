#!/usr/bin/env python3
"""Диагностика стенда: проверяет наблюдения из файла collector *.pending схемой наблюдения C15 и печатает, какие поля
не прошли (путь, правило, короткий кусок значения). Читает только локальный файл, ничего не отправляет.
Запуск: .contract-tools/bin/python scripts/validate_pending.py <путь к *.pending>
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


def short(v, n=90):
    t = json.dumps(v, ensure_ascii=False)
    return t if len(t) <= n else t[:n] + '...'


def main():
    pending = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    batch = pending['batch']
    if isinstance(batch, str):
        batch = json.loads(batch)
    schema = json.loads((ROOT / 'contracts/c15.schema.json').read_text(encoding='utf-8'))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for number, record in enumerate(batch['records']):
        payload = record['payload']
        errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
        sections = {s['name']: s for s in payload.get('sections', [])}
        print(f"record {number}: observation {payload.get('observation_id')} sections={len(sections)} schema_errors={len(errors)}")
        # Проверки Go-валидатора сверх схемы: count==len(records), collected_at секции не позже наблюдения.
        for s in payload.get('sections', []):
            if s.get('record_count') != len(s.get('records', [])):
                print(f"  section {s['name']}: record_count {s.get('record_count')} != records {len(s.get('records', []))}")
            if s.get('collected_at', '') > payload.get('collected_at', ''):
                print(f"  section {s['name']}: collected_at later than observation")
        shown = 0
        for e in errors:
            path = '/'.join(str(p) for p in e.absolute_path)
            # самый глубокий причинный вариант для anyOf/oneOf
            leaf = e
            while leaf.context:
                leaf = sorted(leaf.context, key=lambda c: len(list(c.absolute_path)), reverse=True)[0]
            leafpath = '/'.join(str(p) for p in leaf.absolute_path)
            print(f"  ERROR at {path or '(root)'}: {e.message[:140]}")
            if leaf is not e:
                print(f"    deepest cause at {leafpath}: {leaf.message[:160]}")
            shown += 1
            if shown >= 12:
                print('  ... (остальные ошибки скрыты)')
                break


if __name__ == '__main__':
    main()
