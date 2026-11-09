#!/usr/bin/env python3
"""Диагностика стенда: проверяет digest и подпись наблюдения из *.pending открытым ключом агента, который центр хранит
в sources.ingest_bindings (как это делает приём в IngestAuthorized). Ничего не изменяет и не отправляет.
Запуск: .contract-tools/bin/python scripts/verify_pending_signature.py <*.pending> <имя БД ssv2machine_...>
"""
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def psql(db, query):
    return subprocess.run(['docker', 'exec', 'surveyscan-v2-c04-db-1', 'psql', '-U', 'surveyscan_v2', '-d', db, '-At', '-F', '|', '-c', query],
                          capture_output=True, text=True, check=True).stdout.strip()


def main():
    pending = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    db = sys.argv[2]
    batch = pending['batch']
    if isinstance(batch, str):
        batch = json.loads(batch)
    for number, record in enumerate(batch['records']):
        payload = record['payload']
        canonical = rfc8785.dumps(payload)
        digest_ok = hashlib.sha256(canonical).hexdigest() == record['digest']
        key_id = record['key_id']
        rows = psql(db, f"select key_id, active, encode(public_key,'base64') from sources.ingest_bindings where source_id='{payload['origin']['source_id']}'")
        print(f"record {number}: key_id in record={key_id}; digest matches canonical: {digest_ok}")
        found = False
        for line in rows.splitlines():
            stored_id, active, b64 = line.split('|')
            match = stored_id == key_id
            print(f"  binding key_id={stored_id} active={active} matches_record={match}")
            if not match:
                continue
            found = True
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))
            signature = base64.urlsafe_b64decode(record['signature'] + '=' * (-len(record['signature']) % 4))
            try:
                public.verify(signature, b'SURVEYSCAN-OBSERVATION-V1\n' + canonical)
                print('  signature: VALID for the stored key')
            except Exception as exc:  # noqa: BLE001
                print('  signature: INVALID for the stored key', type(exc).__name__)
        if not found:
            print('  NO binding with the record key_id: center cannot verify this signature')


if __name__ == '__main__':
    main()
