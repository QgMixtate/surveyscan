#!/usr/bin/env python3
"""Package an operator-quiesced PG/Bao/files checkpoint; extract only to a new private root.

Does not stop services or restore a running DB/Bao. Custody/recovery keys stay separate.
Input must come from one frozen application checkpoint, never independently timed live copies.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

from release import digest, read_json, require

MAX_BYTES = 2 * 1024 * 1024 * 1024


def files(root):
    require(root.is_dir() and not root.is_symlink(), 'regular directory required')
    result = {}
    size = 0
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'symlink/special state entry refused')
        name = path.relative_to(root).as_posix()
        require(all(32 <= ord(c) < 127 for c in name) and '\\' not in name, 'unsupported state filename')
        if stat.S_ISREG(mode):
            size += path.stat().st_size
            require(size <= MAX_BYTES and len(result) < 20000, 'checkpoint exceeds bound')
            result[name] = {'bytes': path.stat().st_size, 'sha256': digest(path)}
    return result


def privatize(root):
    root.chmod(0o700)
    for path in root.rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)


def pack(output, postgres, raft, states, quiesced):
    require(quiesced, 'all selected application writers must be stopped/fenced before capture')
    require(not output.exists() and not output.is_symlink(), 'new checkpoint directory required')
    require(states and all(re.fullmatch('[a-z][a-z0-9-]{0,47}', label) for label in states), 'named state roots required')
    require(raft.is_file() and not raft.is_symlink(), 'regular Raft snapshot required')
    pg = read_json(postgres / 'backup.json')
    require(pg.get('format') == 'surveyscan-pg-backup-v1', 'PG component backup required')
    for source in (postgres, *states.values()):
        files(source)  # Validate source before copying; never follow symlinks into private custody.
        require(not output.absolute().is_relative_to(source.resolve()), 'output must be outside selected state roots')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.checkpoint-', dir=output.parent) as temp:
        root = Path(temp) / 'checkpoint'
        payload = root / 'payload'
        payload.mkdir(parents=True)
        shutil.copytree(postgres, payload / 'postgres', symlinks=True)
        shutil.copyfile(raft, payload / 'bao.snapshot')
        for label, source in states.items():
            shutil.copytree(source, payload / 'state' / label, symlinks=True)
        copied = files(payload)
        archive = payload / 'postgres/postgres.dump'
        require(digest(archive) == pg.get('sha256') and archive.stat().st_size == pg.get('bytes'), 'PG archive mismatch')
        require(digest(payload / 'bao.snapshot') == digest(raft), 'snapshot changed during copy')
        for label, source in states.items():
            require(files(payload / 'state' / label) == files(source), 'state changed while copying')
        privatize(root)
        manifest = {'format': 'surveyscan-offline-checkpoint-v1', 'checkpoint_id': str(uuid.uuid4()),
                    'completed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'writers_quiesced_by_operator': True, 'states': sorted(states), 'files': copied,
                    'scope': 'selected PG/Bao/application files; operator is responsible for complete coverage and separate custody',
                    'production_dr_validated': False}
        (root / 'checkpoint.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        (root / 'checkpoint.json').chmod(0o600)
        os.rename(root, output)
    return manifest


def verify(root):
    require(root.is_dir() and not root.is_symlink() and root.stat().st_mode & 0o077 == 0, 'private checkpoint directory required')
    require({p.name for p in root.iterdir()} == {'checkpoint.json', 'payload'}, 'unexpected checkpoint entries')
    manifest = read_json(root / 'checkpoint.json')
    require(manifest.get('format') == 'surveyscan-offline-checkpoint-v1', 'unsupported checkpoint')
    require(files(root / 'payload') == manifest.get('files'), 'checkpoint digest/size/set mismatch')
    for path in (root, *root.rglob('*')):
        require(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0, 'checkpoint must stay owner-only')
    return manifest


def extract(source, target):
    require(not target.exists() and not target.is_symlink(), 'new private restore directory required')
    manifest = verify(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.restore-checkpoint-', dir=target.parent) as temp:
        copy = Path(temp) / 'checkpoint'
        shutil.copytree(source, copy, symlinks=True)
        require(verify(copy) == manifest, 'checkpoint changed during extraction')
        os.rename(copy, target)
    return {'extracted': True, 'checkpoint_id': manifest['checkpoint_id'], 'services_started': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='command', required=True)
    build = commands.add_parser('pack')
    build.add_argument('--output', required=True, type=Path)
    build.add_argument('--postgres', required=True, type=Path)
    build.add_argument('--bao-snapshot', required=True, type=Path)
    build.add_argument('--state', action='append', default=[], metavar='LABEL=DIR')
    build.add_argument('--writers-quiesced', action='store_true')
    for command in ('verify', 'extract'):
        sub = commands.add_parser(command)
        sub.add_argument('--checkpoint', required=True, type=Path)
        if command == 'extract':
            sub.add_argument('--target', required=True, type=Path)
    args = p.parse_args()
    if args.command == 'pack':
        states = {}
        for item in args.state:
            label, path = item.split('=', 1)
            require(label not in states, 'duplicate state label')
            states[label] = Path(path)
        result = pack(args.output, args.postgres, args.bao_snapshot, states, args.writers_quiesced)
    elif args.command == 'verify':
        result = verify(args.checkpoint)
    else:
        result = extract(args.checkpoint, args.target)
    print(json.dumps({k: v for k, v in result.items() if k not in ('files', 'states')}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit('checkpoint operation refused; inspect protected source, quiescence and destination')
