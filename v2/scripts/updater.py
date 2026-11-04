#!/usr/bin/env python3
"""Verified forward release updates with persistent fence/journal and schema-safe recovery.

prepare/status work on a verified installation root. apply/recover CLI use the fixed systemd
server controller only on /. Library tests supply a real isolated process controller instead.
No backup generation, unseal, schema downgrade, state deletion or arbitrary manifest commands.
"""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

from release import digest, read_json, require, verify, verify_payload, VERSION


def sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, value):
    temporary = path.parent / ('.journal-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync(path.parent)


def version(value):
    require(VERSION.fullmatch(value), 'invalid release version')
    base, _, pre = value.partition('-')
    return (*map(int, base.split('.')), not bool(pre),
            tuple((0, int(x)) if x.isdigit() else (1, x) for x in pre.split('.')))


def schema(directory):
    data = read_json(directory / 'schema.json')
    rows = data.get('migrations')
    require(data.get('format') == 'surveyscan-schema-v1' and isinstance(rows, list) and 0 < len(rows) <= 500,
            'compiled schema catalog required')
    ids = []
    for row in rows:
        require(set(row) == {'id', 'owner', 'sha256'} and row['owner']
                and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'invalid schema catalog entry')
        ids.append(row['id'])
    require(ids == sorted(set(ids)), 'schema catalog must be unique and ordered')
    return rows


def prefix(root):
    require(root.is_dir() and not root.is_symlink(), 'regular installation root required')
    result = root / 'opt/surveyscan'
    for directory in (root / 'opt', result, result / 'releases'):
        require(directory.is_dir() and not directory.is_symlink(), 'regular program directories required')
        require(directory.stat().st_uid == os.getuid() and not directory.stat().st_mode & 0o022,
                'program directories must be owned by updater user and not group/world writable')
    return result


@contextlib.contextmanager
def locked(root):
    base = prefix(root)
    fd = os.open(base / 'update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield base
    finally:
        os.close(fd)


def installed(base, name, key):
    require(VERSION.fullmatch(name), 'invalid installed version')
    directory = base / 'releases' / name
    require(directory.is_dir() and not directory.is_symlink(), 'regular release directory required')
    manifest = read_json(directory / 'release-manifest.json')
    verify_payload(manifest, directory / 'release-manifest.json', directory / 'release-manifest.sig', directory, key, installed=True)
    require(manifest['version'] == name, 'installed version mismatch')
    schema(directory)
    return directory, manifest


def active(base):
    link = base / 'current'
    require(link.is_symlink(), 'current must be a relative release symlink')
    value = os.readlink(link)
    require(value.startswith('releases/') and VERSION.fullmatch(value[len('releases/'):]), 'unsafe current symlink')
    return value[len('releases/'):]


def select(base, name):
    link = base / ('.current-' + uuid.uuid4().hex)
    os.symlink('releases/' + name, link)
    os.replace(link, base / 'current')
    sync(base)


def fence(base, enabled):
    path = base / 'update.fence'
    if enabled:
        save(path, {'reason': 'release update in progress; do not start writers manually'})
    elif path.exists():
        path.unlink()
        sync(base)


def state(base, record, phase):
    record['phase'] = phase
    save(base / 'update.json', record)


def prepare(root, bundle, key, checkpoint=None):
    incoming = verify(bundle, key)
    with locked(root) as base:
        if (base / 'update.json').exists():
            old = read_json(base / 'update.json')
            require(old.get('phase') in ('complete', 'rolled_back'), 'pending update requires explicit recovery')
        previous = active(base)
        current, old = installed(base, previous, key)
        require(version(incoming['version']) > version(previous), 'only a strictly newer release can be prepared')
        target = base / 'releases' / incoming['version']
        exists = target.exists() or target.is_symlink()
        if exists:
            _, existing = installed(base, incoming['version'], key)
            require(existing == incoming and digest(target / 'release-manifest.json') == digest(bundle / 'manifest.json'),
                    'release version already exists with different content')
        with tempfile.TemporaryDirectory(prefix='.update-', dir=base) as temp:
            snapshot = Path(temp) / 'bundle'
            shutil.copytree(bundle, snapshot, symlinks=True)
            require(verify(snapshot, key) == incoming, 'bundle changed during copy')
            old_schema, new_schema = schema(current), schema(snapshot / 'payload')
            for directory, expected in ((current, old_schema), (snapshot / 'payload', new_schema)):
                compiled = json.loads(subprocess.check_output([str(directory / 'bin/surveyscan-server'), 'schema-catalog'], timeout=10))
                require(compiled.get('format') == 'surveyscan-schema-v1' and compiled.get('migrations') == expected,
                        'signed schema metadata does not match compiled binary')
            require(new_schema[:len(old_schema)] == old_schema, 'schema catalog must extend the exact current prefix')
            checkpoint_record = None
            if old_schema != new_schema:
                from checkpoint import verify as verify_checkpoint
                require(checkpoint is not None, 'schema-changing update requires a verified common checkpoint')
                checkpoint_record = verify_checkpoint(checkpoint)
                require(checkpoint_record.get('writers_quiesced_by_operator') is True, 'stopped-writer checkpoint required')
            require(incoming['wire']['major'] == old['wire']['major'], 'wire major upgrade requires a separate migration procedure')
            # Updating service definitions/users is a separate installer operation; never silently mix them.
            def units(manifest):
                return {name: entry for name, entry in manifest['files'].items()
                        if name.startswith('systemd/') and name.endswith(('.service', '.conf'))}
            require(units(old) == units(incoming), 'unit/sysusers changes require explicit installation acceptance')
            candidate = Path(temp) / 'release'
            shutil.copytree(snapshot / 'payload', candidate)
            for name in ('manifest.json', 'manifest.sig'):
                shutil.copyfile(snapshot / name, candidate / ('release-' + name))
                (candidate / ('release-' + name)).chmod(0o644)
            if not exists:
                os.rename(candidate, target)
                sync(target.parent)
        record = {'format': 1, 'id': str(uuid.uuid4()), 'from': previous, 'to': incoming['version'],
                  'from_digest': digest(current / 'release-manifest.json'), 'to_digest': digest(target / 'release-manifest.json'),
                  'schema_changed': old_schema != new_schema}
        if checkpoint_record is not None:
            record['checkpoint'] = str(checkpoint.resolve())
            record['checkpoint_digest'] = digest(checkpoint / 'checkpoint.json')
        state(base, record, 'prepared')
        return record


def validate_record(base, key):
    record = read_json(base / 'update.json')
    require(record.get('format') == 1, 'unsupported update journal')
    old, _ = installed(base, record['from'], key)
    new, _ = installed(base, record['to'], key)
    require(digest(old / 'release-manifest.json') == record['from_digest'] and digest(new / 'release-manifest.json') == record['to_digest'],
            'journal references changed release metadata')
    require(active(base) in (record['from'], record['to']), 'unexpected active version')
    return record, old, new


def launch(base, record, name, controller, phase):
    select(base, name)
    state(base, record, 'starting' if phase == 'complete' else 'rolling_back')
    fence(base, False)
    controller.start()
    require(controller.healthy(), 'updated service did not become ready')
    state(base, record, phase)
    return {'phase': phase, 'active': name, 'schema_changed': record['schema_changed']}


def apply(root, key, controller, recover=False):
    with locked(root) as base:
        record, old, new = validate_record(base, key)
        if record['schema_changed'] and not recover:
            from checkpoint import verify as verify_checkpoint
            backup = Path(record['checkpoint'])
            verify_checkpoint(backup)
            require(digest(backup / 'checkpoint.json') == record['checkpoint_digest'], 'checkpoint changed since preparation')
        if not recover:
            require(record['phase'] == 'prepared' and active(base) == record['from'], 'prepared update required')
        else:
            require(record['phase'] not in ('complete', 'rolled_back')
                    and (record['phase'] != 'prepared' or (base / 'update.fence').exists()), 'no interrupted update to recover')
        interrupted = record['phase']
        fence(base, True)
        state(base, record, 'stopping')
        try:
            controller.stop()
            state(base, record, 'stopped')
            if recover:
                # On crash during/after migration, inspect actual DB; never infer rollback from exit status.
                if interrupted not in ('prepared', 'stopping', 'stopped', 'rolling_back') and controller.check_schema(new / 'bin/surveyscan-server'):
                    return launch(base, record, record['to'], controller, 'complete')
                require(controller.check_schema(old / 'bin/surveyscan-server'), 'neither recovery path matches DB')
                return launch(base, record, record['from'], controller, 'rolled_back')
            require(controller.check_schema(old / 'bin/surveyscan-server'), 'database does not match active release')
            state(base, record, 'migrating')
            controller.migrate(new / 'bin/surveyscan-server')
            require(controller.check_schema(new / 'bin/surveyscan-server'), 'database does not match candidate release')
            state(base, record, 'migrated')
            return launch(base, record, record['to'], controller, 'complete')
        except Exception:
            fence(base, True)
            state(base, record, 'recovery_required')
            try:
                controller.stop()
                if controller.check_schema(old / 'bin/surveyscan-server'):
                    return launch(base, record, record['from'], controller, 'rolled_back')
            except Exception:
                pass
            # Even failed rollback/start must leave the persistent gate in place.
            fence(base, True)
            try:
                controller.stop()
            except Exception:
                pass
            state(base, record, 'recovery_required')
            return {'phase': 'recovery_required', 'active': active(base), 'schema_changed': record['schema_changed']}


class SystemdController:
    def __init__(self, root, health_url, ca=None, dev_http=False):
        require(root.resolve() == Path('/'), 'systemd controller supports only the explicitly selected live root')
        url = urllib.parse.urlsplit(health_url)
        require(not url.username and not url.password and not url.query and not url.fragment and url.path == '/health/ready', 'explicit ready URL required')
        require(url.scheme == 'https' or dev_http and url.scheme == 'http' and url.hostname in ('127.0.0.1', '::1'), 'HTTPS or explicit literal loopback development HTTP required')
        self.url = health_url
        self.tls = ssl.create_default_context(cafile=str(ca) if ca else None)

    def run(self, args):
        return subprocess.run(args, capture_output=True, timeout=180).returncode

    def stop(self):
        require(self.run(['systemctl', 'stop', 'surveyscan-server.service', 'surveyscan-migrate.service']) == 0, 'stop failed')

    def start(self):
        require(self.run(['systemctl', 'start', 'surveyscan-server.service']) == 0, 'start failed')

    def task(self, binary, command):
        return self.run(['systemd-run', '--quiet', '--wait', '--collect', '--unit=surveyscan-update-' + uuid.uuid4().hex[:12],
                         '--property=User=surveyscan-server', '--property=Group=surveyscan-server',
                         '--property=LoadCredential=pg_password:/etc/surveyscan-server/pg_password',
                         '--property=EnvironmentFile=/etc/surveyscan-server/server.env',
                         '--property=UMask=0077', '--property=NoNewPrivileges=yes', '--property=ProtectSystem=strict',
                         '--property=ProtectHome=yes', '--setenv=SURVEYSCAN_V2_DATABASE_PASSWORD_FILE=%d/pg_password',
                         str(binary), command])

    def migrate(self, binary):
        require(self.task(binary, 'migrate') == 0, 'migration failed')

    def check_schema(self, binary):
        return self.task(binary, 'schema-check') == 0

    def healthy(self):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=self.tls))
        for _ in range(30):
            try:
                if self.run(['systemctl', 'is-active', '--quiet', 'surveyscan-server.service']) == 0:
                    with opener.open(self.url, timeout=2) as response:
                        if response.status == 200:
                            return True
            except OSError:
                pass
            time.sleep(1)
        return False


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['prepare', 'apply', 'recover', 'status'])
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--public-key', type=Path, required=True)
    p.add_argument('--bundle', type=Path)
    p.add_argument('--checkpoint', type=Path)
    p.add_argument('--health-url')
    p.add_argument('--ca-file', type=Path)
    p.add_argument('--dev-loopback-http', action='store_true')
    a = p.parse_args()
    if a.command == 'prepare':
        require(a.bundle is not None, 'bundle required')
        result = prepare(a.root, a.bundle, a.public_key, a.checkpoint)
    elif a.command == 'status':
        with locked(a.root) as base:
            _, manifest = installed(base, active(base), a.public_key)
            result = {'active': manifest['version'], 'fenced': (base / 'update.fence').exists(),
                      'journal': read_json(base / 'update.json') if (base / 'update.json').exists() else None}
    else:
        require(a.health_url is not None, 'health URL required')
        result = apply(a.root, a.public_key, SystemdController(a.root, a.health_url, a.ca_file, a.dev_loopback_http), a.command == 'recover')
    print(json.dumps(result))
    return 0 if result.get('phase') not in ('rolled_back', 'recovery_required') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('update refused or incomplete; inspect protected update journal and service logs')
