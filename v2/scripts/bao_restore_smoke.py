#!/usr/bin/env python3
"""Real C13 Raft restore in a separate disposable Bao node; never restore/seal/reset the source.

Development custody only, temporary snapshot contains real development secrets and is deleted.
No complete-system, production HTTPS/KMS or clean-OS claim.
"""
import base64
import contextlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from bao_fixture import fixture
from dev import STATE, ENV
from machine_smoke import freeport

DOCKER = ['docker', '--host=unix:///var/run/docker.sock']
IMAGE = 'openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main(report_directory=None):
    report_state = Path(report_directory) if report_directory is not None else STATE
    report_state.mkdir(exist_ok=True)
    checks = []
    name = 'surveyscan-c13-restore-' + uuid.uuid4().hex[:16]
    created = False
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    # All URLs below are fixed literal loopback endpoints; no external/proxy policy bypass.
    def request(address, path, body=None, token=None, binary=False):
        headers = {}
        if token:
            headers['X-Vault-Token'] = token
        data = body if isinstance(body, bytes) else None if body is None else json.dumps(body).encode()
        if data is not None:
            headers['Content-Type'] = 'application/octet-stream' if isinstance(body, bytes) else 'application/json'
        req = urllib.request.Request(address + '/v1/' + path, data=data, headers=headers,
                                     method='GET' if body is None else 'POST')
        try:
            with opener.open(req, timeout=60) as response:
                raw = response.read(512 * 1024 * 1024 + 1)
                assert len(raw) <= 512 * 1024 * 1024, 'test snapshot exceeds bound'
                return response.status, raw if binary else json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            # Status only; error bodies may contain operational details.
            return error.code, {}
    def docker(*args):
        result = subprocess.run(DOCKER + list(args), env=ENV, capture_output=True, timeout=60)
        assert result.returncode == 0, 'owned disposable Docker operation failed'
        return result.stdout
    def remove():
        nonlocal created
        if created:
            docker('rm', '--force', name)
            created = False
    def healthy(address):
        for _ in range(150):
            try:
                status, result = request(address, 'sys/health')
                if status == 200 and result.get('initialized') is True and result.get('sealed') is False and result.get('standby') is False:
                    return result
            except OSError:
                pass
            time.sleep(.1)
        raise AssertionError('unsealed restored node did not become active')
    try:
        with contextlib.ExitStack() as cleanup:
            directory = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix='c13-bao-restore-', dir=report_state)))
            with fixture(directory) as source:
                source_address = 'http://127.0.0.1:58200'
                custody = json.loads((STATE / 'bao-init.json').read_text())
                old_root = custody['root_token']
                # The existing dev fixture's selected bootstrap material is used, never printed.
                old_shares = custody.get('keys_base64', custody.get('keys'))
                status, source_health = request(source_address, 'sys/health')
                assert status == 200 and not source_health['sealed']
                status, snapshot = request(source_address, 'sys/storage/raft/snapshot', token=old_root, binary=True)
                assert status == 200 and len(snapshot) > 100
                fd = os.open(directory / 'raft.snapshot', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(snapshot)
                    stream.flush()
                    os.fsync(stream.fileno())
                checks.append('real source Bao2.7.2 Raft snapshot stored only in temporary private file')
                data = directory / 'data'
                data.mkdir(mode=0o700)
                config = directory / 'restore.hcl'
                config.write_text('disable_mlock = true\nui = false\napi_addr = "http://127.0.0.1:8200"\ncluster_addr = "https://127.0.0.1:8201"\nstorage "raft" {\n path = "/openbao/file"\n node_id = "c13-isolated-restore"\n}\nlistener "tcp" {\n address = "0.0.0.0:8200"\n tls_disable = true\n}\n')
                config.chmod(0o644)
                port = freeport()
                destination = 'http://127.0.0.1:' + str(port)
                docker('run', '--detach', '--name', name, '--user', f'{os.getuid()}:{os.getgid()}',
                       '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                       '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
                       '--publish', f'127.0.0.1:{port}:8200',
                       '--mount', f'type=bind,src={data},dst=/openbao/file',
                       '--mount', f'type=bind,src={config},dst=/config.hcl,readonly',
                       '--entrypoint', 'bao', IMAGE, 'server', '-config=/config.hcl')
                created = True
                cleanup.callback(remove)  # Stop writer before deleting its bind-mounted private state.
                for _ in range(150):
                    try:
                        if request(destination, 'sys/init')[0] == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(.1)
                else:
                    raise AssertionError('clean isolated Bao node did not start')
                status, fresh = request(destination, 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
                assert status == 200
                for share in fresh['keys_base64']:
                    status, state = request(destination, 'sys/unseal', {'key': share})
                assert status == 200 and not state['sealed']
                checks.append('separate initially empty Raft node initialized/unsealed with temporary independent custody')
                # Unseal response is not an active-leader readiness assertion.
                # Do not retry a force-restore write or recreate custody on error.
                healthy(destination)
                status, _ = request(destination, 'sys/storage/raft/snapshot-force', snapshot, fresh['root_token'])
                assert status in (200, 204), f'restore into own clean node failed: HTTP{status}'
                # Force restore changes barrier/root custody. It must use source recovery material.
                for _ in range(150):
                    try:
                        status, state = request(destination, 'sys/seal-status')
                        if status == 200 and state.get('sealed'):
                            break
                    except OSError:
                        pass
                    time.sleep(.1)
                else:
                    raise AssertionError('restored node did not seal with source barrier')
                for share in old_shares:
                    status, state = request(destination, 'sys/unseal', {'key': share})
                    if status == 200 and not state['sealed']:
                        break
                assert status == 200 and not state['sealed']
                checks.append('snapshot restored only into isolated target; source custody unseals restored barrier')
                restored_health = healthy(destination)
                assert request(destination, 'auth/token/lookup-self', token=fresh['root_token'])[0] == 403
                checks.append('restored node becomes active and unrelated fresh-node token cannot authenticate')
                token = source['token']
                status, kv = request(destination, source['kv'] + '/data/server/runtime', token=token)
                assert status == 200 and kv['data']['data']['canary'] == source['canary']
                checks.append('restored scoped server policy/token retrieves identical KV value without root app token')
                def prove_key(key):
                    status, metadata = request(destination, source['transit'] + '/keys/' + key, token=token)
                    assert status == 200 and metadata['data']['exportable'] is False
                    public = base64.b64decode(metadata['data']['keys']['1']['public_key'])
                    expected = source['profile']['keys'][key]['public_key']
                    assert base64.urlsafe_b64encode(public).rstrip(b'=').decode() == expected
                    message = b'SURVEYSCAN-C13-ISOLATED-RESTORE-PROOF\n' + key.encode()
                    status, signed = request(destination, source['transit'] + '/sign/' + key,
                                             {'input': base64.b64encode(message).decode()}, token)
                    assert status == 200
                    Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(signed['data']['signature'].split(':')[-1]), message)
                prove_key('ca')
                prove_key('center')
                checks.append('both non-exportable Transit CA/receipt keys retain public IDs and actually sign verifiable challenges')
                assert request(destination, source['transit'] + '/sign/forbidden', {'input': 'eA=='}, token)[0] == 403
                checks.append('restored scoped policy still refuses forbidden signing key')
                docker('restart', name)
                for _ in range(100):
                    try:
                        status, state = request(destination, 'sys/seal-status')
                        if status == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(.1)
                assert status == 200 and state['sealed']
                for share in old_shares:
                    status, state = request(destination, 'sys/unseal', {'key': share})
                    if status == 200 and not state['sealed']:
                        break
                assert status == 200 and not state['sealed']
                restarted_health = healthy(destination)
                prove_key('center')
                checks.append('actual restored-container restart seals normally; source custody unseals and Transit still signs')
                status, unchanged = request(source_address, 'sys/health')
                assert status == 200 and unchanged['cluster_id'] == source_health['cluster_id']
                source['audit_check']()
                checks.append('original source remains active/unmodified by restore; original audit retains masked secrets')
                report = {'package': 'C13', 'task': 'C13.03 Bao component preparation', 'status': 'passed',
                          'count': len(checks), 'checks': checks,
                          'cluster_id_matches_source_before_restart': restored_health['cluster_id'] == source_health['cluster_id'],
                          'cluster_id_matches_source_after_restart': restarted_health['cluster_id'] == source_health['cluster_id'],
                          'target': 'real OpenBao2.7.2 Raft snapshot and separate initially empty node; actual Transit cryptographic proof and restart',
                          'unrun': ['complete PG/Bao/filesystem checkpoint', 'production HTTPS/KMS/split custody',
                                    'CA leaf issuance plus application replay after full restore', 'systemd/clean OS boot', 'DR/RPO/RTO']}
                source['assert_redacted'](json.dumps(report))
                (report_state / 'c13-bao-restore-smoke.json').write_text(json.dumps(report, indent=2) + '\n')
                print(json.dumps(report))
    finally:
        remove()


if __name__ == '__main__':
    main()
