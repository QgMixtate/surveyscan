#!/usr/bin/env python3
"""Opt-in center1.2, real mTLS/Transit/PG/API; synthetic delegated agent inventory.

Default mode uses the compiled collector for enrollment only. The optional relay
mode also exercises1.2upload, durable replay and cold restart; actual Windows
collection/service and authenticated agent negotiation are not claimed.
"""
import base64
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import ssl
import tempfile
import time
import uuid

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from bao_fixture import fixture
from dev import ROOT, STATE, initialize
from machine_smoke import main as harness, b64, rawpublic


def scenario(relay12=False, **s):
    checks, request, sql = s['checks'], s['request'], s['sql']
    collector = s['collector_result']
    center_public = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(collector['center_result_public_key'] + '=='))
    nonce = b64(os.urandom(32))
    code, frame, _ = request(s['tls_port'], s['collector_client'], 'POST',
                            '/api/v1/machine/inventory-capabilities', {'nonce': nonce})
    assert code == 200
    p = frame['payload']
    canonical = rfc8785.dumps(p)
    center_public.verify(base64.urlsafe_b64decode(frame['signature'] + '=='),
                         b'SURVEYSCAN-INVENTORY-CAPABILITIES-V1\n' + canonical)
    assert frame['key_id'] == collector['center_result_key_id'] and frame['digest'] == hashlib.sha256(canonical).hexdigest()
    assert p['tenant_id'] == s['tenant'] and p['nonce'] == nonce
    assert p['audience'] == {'source_id': s['collector_source'], 'source_kind': 'collector', 'generation_id': collector['generation_id']}
    assert p['observation_versions'] == p['batch_versions'] == [{'major': 1, 'minor': 0}, {'major': 1, 'minor': 2}]
    assert p['inventory12_snapshot_modes'] == ['partial'] and p['inventory12_limits']['canonical_bytes'] == 524288
    checks.append('configured compiled center advertises1.2 only with matching admission/registry; actual Transit signature verifies against enrollment-pinned key/nonce/audience')

    agent_tls_key, agent_sign, csr = s['enroll_material']()
    source = str(uuid.uuid4())
    permission = s['grant'](source, 'agent', s['collector_id'], agent_sign, csr)
    body = {'grant_id': permission['grant_id'], 'source_id': source,
            'csr_pem': csr.public_bytes(serialization.Encoding.PEM).decode(),
            'signing_public_key': b64(rawpublic(agent_sign))}
    code, identity, _ = request(s['collector_port'], s['plain'], 'POST', '/api/v1/machine/enroll', body,
                                {'Authorization': 'Bearer ' + permission['enrollment_token']},
                                s['collector_source'] + '.collector.invalid')
    assert code == 201
    corpus = json.loads((ROOT.parent / 'docs/plans/surveyscan-v2/contracts/C15/fixtures.json').read_text(encoding='utf-8'))
    payload = copy.deepcopy(next(f['payload'] for f in corpus if f['id'] == 'all-sections'))
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    payload.update(observation_id=str(uuid.uuid4()), tenant_id=s['tenant'], source_sequence='1',
                   collected_at=stamp, origin={'source_id': source, 'source_kind': 'agent', 'generation_id': identity['generation_id']},
                   source_record={'namespace': 'host', 'source_local_id': 'synthetic-windows12'},
                   scope={'site_id': s['site'], 'network_scope_id': s['scope']})
    for section in payload['sections']:
        section.update(collected_at=stamp, status='partial', collection_complete=False)
    canonical = rfc8785.dumps(payload)
    record = {'payload': payload, 'digest': hashlib.sha256(canonical).hexdigest(),
              'key_id': identity['signing_key_id'],
              'signature': b64(agent_sign.sign(b'SURVEYSCAN-OBSERVATION-V1\n' + canonical))}
    batch = {'schema_version': {'major': 1, 'minor': 2}, 'tenant_id': s['tenant'],
             'delivery_id': str(uuid.uuid4()), 'records': [record]}
    port, client, sni = s['tls_port'], s['collector_client'], None
    if relay12:
        cert = s['save']('c15-agent.pem', identity['certificate_chain_pem'])
        private = s['save']('c15-agent.key', agent_tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        client = ssl.create_default_context(cafile=s['ca_file']);client.load_cert_chain(cert, private)
        port, sni = s['collector_port'], s['collector_source'] + '.collector.invalid'
    code, receipt, _ = request(port, client, 'POST', '/api/v1/machine/observations', batch, sni=sni)
    assert code == 202, f"center1.2 response status={code} code={receipt.get('code', 'none')}"
    for _ in range(80):
        if 'payload' in receipt:
            break
        time.sleep(.2)
        code, receipt, _ = request(port, client, 'GET', '/api/v1/machine/deliveries/' + batch['delivery_id'], sni=sni)
        assert code == 200
    else:
        raise AssertionError('center1.2 final signed receipt not ready')
    result = receipt['payload']
    center_public.verify(base64.urlsafe_b64decode(receipt['signature'] + '=='),
                         b'SURVEYSCAN-CENTER-RESULT-V1\n' + rfc8785.dumps(result))
    assert result['schema_version'] == {'major': 1, 'minor': 0}
    assert receipt['key_id'] == collector['center_result_key_id']
    assert receipt['digest'] == hashlib.sha256(rfc8785.dumps(result)).hexdigest()
    assert result['delivery_id'] == batch['delivery_id'] and result['batch_digest'] == hashlib.sha256(rfc8785.dumps(batch)).hexdigest()
    applied = result['results'][0]
    assert applied['origin_source_id'] == source and applied['observation_id'] == payload['observation_id']
    assert applied['observation_digest'] == record['digest'] and applied['disposition'] == 'applied' and applied['spool_action'] == 'remove'
    asset = applied['asset_uid']
    assert sql('SELECT count(*) FROM inventory.observations') == '1'
    assert sql('SELECT count(DISTINCT section_name) FROM inventory.record_facts12') == '12'
    checks.append('actual mTLS courier forwards delegated signed synthetic agent1.2 to compiled center; all12sections commit inPG with history/audit/outbox and verified unchanged ACK1.0')
    path = '/api/v1/assets/' + asset + '/inventory/facts/services'
    code, page, _ = request(s['tls_port'], s['plain'], 'GET', path, headers={'Cookie': s['cookie']})
    assert code == 200 and page['schema_version'] == {'major': 1, 'minor': 2} and page['items']
    assert all(f['evidence']['observation_id'] == payload['observation_id'] for f in page['items'])
    code, old, _ = request(s['tls_port'], s['plain'], 'GET', '/api/v1/assets/' + asset + '/inventory', headers={'Cookie': s['cookie']})
    assert code == 200 and old['facts'] == [] and old['sections'] == []
    checks.append('authenticated typed1.2API serves admitted field provenance while legacyC09shape stays valid and separate')
    code, replay, _ = request(port, client, 'POST', '/api/v1/machine/observations', batch, sni=sni)
    assert code == 202
    if relay12:
        code, replay, _ = request(port, client, 'GET', '/api/v1/machine/deliveries/' + batch['delivery_id'], sni=sni)
        assert code == 200
        assert not (s['directory'] / 'spool' / (batch['delivery_id'] + '.pending')).exists()
        checks.append('compiled collector verifies final1.0ACK against original1.2batch before pending removal; authenticated cached replay keeps one UID')
    assert rfc8785.dumps(replay) == rfc8785.dumps(receipt)
    assert sql('SELECT count(*) FROM inventory.observations') == '1'
    checks.append('real HTTPS delivery replay returns the same canonical signed ACK with one observation/asset')
    if relay12:
        # Only this harness's processes are interrupted. Shared dev services and
        # scoped Transit stay running; keys/config/UID must survive cold restart.
        s['center_process'].terminate();assert s['center_process'].wait(timeout=8) == 0
        next_payload = copy.deepcopy(payload)
        next_stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
        next_payload.update(observation_id=str(uuid.uuid4()), source_sequence='2', collected_at=next_stamp)
        for section in next_payload['sections']:
            section['collected_at'] = next_stamp
        canonical = rfc8785.dumps(next_payload)
        next_record = {'payload': next_payload, 'digest': hashlib.sha256(canonical).hexdigest(),
                       'key_id': identity['signing_key_id'],
                       'signature': b64(agent_sign.sign(b'SURVEYSCAN-OBSERVATION-V1\n' + canonical))}
        next_batch = {'schema_version': {'major': 1, 'minor': 2}, 'tenant_id': s['tenant'],
                      'delivery_id': str(uuid.uuid4()), 'records': [next_record]}
        code, transport, _ = request(port, client, 'POST', '/api/v1/machine/observations', next_batch, sni=sni)
        assert code == 202 and transport['spool_action'] == 'retain'
        pending = s['directory'] / 'spool' / (next_batch['delivery_id'] + '.pending')
        assert pending.exists()
        stored = json.loads(pending.read_text(encoding='utf-8'))
        assert rfc8785.dumps(stored['batch']) == rfc8785.dumps(next_batch)
        checks.append('center offline: real collector durably retains original signed1.2batch without downgrade or premature removal')
        s['collector_process'].terminate();assert s['collector_process'].wait(timeout=8) == 0
        s['start']('c15-center-restart', [str(ROOT / '.dist/surveyscan-server'), 'serve'])
        s['start']('c15-collector-restart', [str(ROOT / '.dist/surveyscan-collector'), 'run', '--config', s['collector_config']])
        for _ in range(100):
            try:
                code, final, _ = request(port, client, 'GET', '/api/v1/machine/deliveries/' + next_batch['delivery_id'], sni=sni)
                if code == 200 and 'payload' in final:
                    break
            except OSError:
                pass
            time.sleep(.2)
        else:
            raise AssertionError('cold restarted1.2collector did not replay pending data')
        center_public.verify(base64.urlsafe_b64decode(final['signature'] + '=='),
                             b'SURVEYSCAN-CENTER-RESULT-V1\n' + rfc8785.dumps(final['payload']))
        assert final['key_id'] == collector['center_result_key_id']
        assert final['digest'] == hashlib.sha256(rfc8785.dumps(final['payload'])).hexdigest()
        assert final['payload']['batch_digest'] == hashlib.sha256(rfc8785.dumps(next_batch)).hexdigest()
        assert final['payload']['delivery_id'] == next_batch['delivery_id']
        applied = final['payload']['results'][0]
        assert applied['observation_id'] == next_payload['observation_id'] and applied['observation_digest'] == next_record['digest']
        assert applied['origin_source_id'] == source and applied['disposition'] == 'applied'
        assert applied['asset_uid'] == asset and applied['spool_action'] == 'remove'
        assert sql('SELECT count(*) FROM inventory.observations') == '2' and sql('SELECT count(*) FROM assets.assets') == '1'
        assert not pending.exists()
        checks.append('actual collector+center cold restart reloads same signing identity and pending1.2bytes; automatic reconnect commits sequence2 to unchanged UID, removes only after verified ACK')
    report = {'package': 'C15', 'task': 'C15.02', 'status': 'passed', 'count': len(checks), 'checks': checks,
              'target': 'compiled opt-in center, real mTLS enrolled courier/delegated synthetic agent, scoped nonexportable OpenBao Transit, PostgreSQL, typed humanAPI/ACK/replay',
              'unrun': ['collector1.2upload relay/agent three-hop negotiation', 'actual Windows collection/delivery/service/rights/reboot', 'complete provider coverage/scoped deletion', 'independent collection/heartbeat']}
    if relay12:
        report['target'] = 'synthetic enrolled agent→actualmTLS compiledcollector1.2 durable spool/relay→compiledcenter/scopedTransit/PG/all12sections→typedAPI/verifiedACK/replay'
        report['unrun'][0] = 'authenticated agent three-hop capability negotiation'
        report['checks'] = [text.replace('courier forwards delegated', 'compiled collector relays delegated') for text in checks]
    name = 'c15-relay-smoke.json' if relay12 else 'c15-center-smoke.json'
    (STATE / name).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


def main(relay12=False):
    initialize()
    report_path = STATE / ('c15-relay-smoke.json' if relay12 else 'c15-center-smoke.json')
    report_path.write_text(json.dumps({'package':'C15','status':'in_progress','mode':'relay' if relay12 else 'center','started_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}) + '\n')
    with tempfile.TemporaryDirectory(prefix='c15-center-', dir=STATE) as temp:
        directory = Path(temp)
        with fixture(directory) as f:
            output = directory / 'issuer'
            p = subprocess.run([str(ROOT / '.dist/surveyscan-server'), 'bootstrap-issuer', '--config', f['config'],
                                '--output-directory', str(output)], capture_output=True, timeout=30)
            assert p.returncode == 0, 'scoped issuer bootstrap failed'
            settings = {'config': f['config'], 'ca_certificate': str(output / 'ca.pem'),
                        'server_certificate': str(output / 'server.pem'), 'server_private': str(output / 'server.key'),
                        'center_id': str(uuid.uuid4()), 'center_public': f['profile']['keys']['center']['public_key']}
            harness(agent_scenario=lambda **s: scenario(relay12=relay12, **s), bao_settings=settings, report_directory=STATE, inventory12=True, collector_inventory12=relay12)


if __name__ == '__main__':
    main()
