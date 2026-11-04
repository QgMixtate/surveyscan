"""Isolated local-only Bao restore helper for C13 rehearsals. Never writes source storage."""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import uuid

from dev import ENV
from machine_smoke import freeport

IMAGE = 'openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(address, path, body=None, token=None, binary=False):
    # Only explicit local development endpoints. Never forward a token through a redirect.
    assert address.startswith('http://127.0.0.1:')
    headers = {'X-Vault-Token': token} if token else {}
    data = body if isinstance(body, bytes) else None if body is None else json.dumps(body).encode()
    if data is not None:
        headers['Content-Type'] = 'application/octet-stream' if isinstance(body, bytes) else 'application/json'
    req = urllib.request.Request(address + '/v1/' + path, data=data, headers=headers,
                                 method='GET' if body is None else 'POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=60) as response:
            raw = response.read(512 * 1024 * 1024 + 1)
            assert len(raw) <= 512 * 1024 * 1024
            return response.status, raw if binary else json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        return error.code, {}


@contextlib.contextmanager
def restored_node(directory, snapshot, custody):
    name = 'surveyscan-c13-checkpoint-' + uuid.uuid4().hex[:16]
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    def command(*args):
        result = subprocess.run(docker + list(args), env=ENV, capture_output=True, timeout=60)
        assert result.returncode == 0, 'isolated Bao Docker operation failed'
    directory.mkdir(mode=0o700)
    data = directory / 'data'
    data.mkdir(mode=0o700)
    config = directory / 'bao.hcl'
    config.write_text('disable_mlock = true\nui = false\napi_addr = "http://127.0.0.1:8200"\ncluster_addr = "https://127.0.0.1:8201"\nstorage "raft" {\n path = "/openbao/file"\n node_id = "c13-checkpoint-restore"\n}\nlistener "tcp" {\n address = "0.0.0.0:8200"\n tls_disable = true\n}\n')
    config.chmod(0o600)
    port = freeport()
    address = 'http://127.0.0.1:' + str(port)
    created = False
    try:
        command('run', '--detach', '--name', name, '--user', f'{os.getuid()}:{os.getgid()}',
                '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', '--publish', f'127.0.0.1:{port}:8200',
                '--mount', f'type=bind,src={data},dst=/openbao/file',
                '--mount', f'type=bind,src={config},dst=/config.hcl,readonly',
                '--entrypoint', 'bao', IMAGE, 'server', '-config=/config.hcl')
        created = True
        def wait(path, predicate):
            for _ in range(150):
                try:
                    status, value = call(address, path)
                    if status == 200 and predicate(value):
                        return value
                except OSError:
                    pass
                time.sleep(.1)
            raise AssertionError('isolated Bao readiness timeout')
        wait('sys/init', lambda value: not value['initialized'])
        status, fresh = call(address, 'sys/init', {'secret_shares': 1, 'secret_threshold': 1})
        assert status == 200
        for share in fresh['keys_base64']:
            status, state = call(address, 'sys/unseal', {'key': share})
        assert status == 200 and not state['sealed']
        wait('sys/health', lambda value: not value['sealed'])
        status, _ = call(address, 'sys/storage/raft/snapshot-force', snapshot.read_bytes(), fresh['root_token'])
        assert status in (200, 204)
        wait('sys/seal-status', lambda value: value['sealed'])
        for share in custody.get('keys_base64', custody.get('keys')):
            status, state = call(address, 'sys/unseal', {'key': share})
            if status == 200 and not state['sealed']:
                break
        assert status == 200 and not state['sealed']
        wait('sys/health', lambda value: not value['sealed'])
        yield address
    finally:
        if created:
            command('rm', '--force', name)
