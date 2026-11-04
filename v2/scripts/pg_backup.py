#!/usr/bin/env python3
"""PostgreSQL17 component backup/restore. Not a complete PG+Bao+filesystem backup.

Connection/authentication use standard libpq environment and protected pgpass.
Restore requires an explicitly named, already-created empty database. Never DROP/--clean.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from release import digest, read_json, require


class Client:
    def __init__(self, commands=None, env=None):
        self.commands = commands or {name: [name] for name in ('psql', 'pg_dump', 'pg_restore')}
        self.env = env

    def run(self, tool, args, stdin=None, stdout=None):
        result = subprocess.run(self.commands[tool] + args, stdin=stdin,
                                stdout=stdout if stdout is not None else subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=300, env=self.env)
        require(result.returncode == 0, 'PostgreSQL client operation failed; backup/restore incomplete')
        return result.stdout or b''

    def sql(self, database, query):
        return self.run('psql', ['-X', '--no-password', '--dbname=' + database,
                                '--set=ON_ERROR_STOP=1', '-Atc', query]).decode().strip()

    def check(self, database):
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}', database) is not None,
                'explicit simple database name required')
        require(database not in ('postgres', 'template0', 'template1'), 'system database refused')
        for tool in ('pg_dump', 'pg_restore'):
            require(re.search(rb'\(PostgreSQL\) 17\.', self.run(tool, ['--version'])),
                    'PostgreSQL17 clients required')
        require(170000 <= int(self.sql(database, 'SHOW server_version_num')) < 180000,
                'PostgreSQL17 target required')


def private_file(path):
    info = path.lstat()
    require(path.is_file() and not path.is_symlink() and info.st_uid == os.getuid()
            and info.st_mode & 0o077 == 0, 'owner-only regular backup file required')


def backup(client, database, output):
    require(not output.exists() and not output.is_symlink(), 'new backup directory required')
    client.check(database)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.pg-backup-', dir=output.parent) as temp:
        directory = Path(temp) / 'backup'
        directory.mkdir(mode=0o700)
        archive = directory / 'postgres.dump'
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            client.run('pg_dump', ['--no-password', '--format=custom', '--no-owner', '--no-acl',
                                   '--dbname=' + database], stdout=stream)
            stream.flush()
            os.fsync(stream.fileno())
        with archive.open('rb') as stream:
            client.run('pg_restore', ['--list'], stdin=stream)
        manifest = {'format': 'surveyscan-pg-backup-v1', 'database': database, 'postgres_major': 17,
                    'completed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'sha256': digest(archive), 'bytes': archive.stat().st_size,
                    'complete_system_backup': False,
                    'scope': 'PostgreSQL only; Bao, filesystem state and custody are separate'}
        fd = os.open(directory / 'backup.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(manifest, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(directory, output)
    return {'backed_up': True, 'postgres_major': 17, 'complete_system_backup': False}


def restore(client, directory, database):
    require(directory.is_dir() and not directory.is_symlink() and directory.stat().st_mode & 0o077 == 0,
            'private backup directory required')
    require({p.name for p in directory.iterdir()} == {'postgres.dump', 'backup.json'}, 'unexpected backup entries')
    private_file(directory / 'backup.json')
    private_file(directory / 'postgres.dump')
    manifest = read_json(directory / 'backup.json')
    require(manifest.get('format') == 'surveyscan-pg-backup-v1' and manifest.get('postgres_major') == 17,
            'unsupported backup format')
    require(database != manifest.get('database'), 'restore requires a different empty database')
    # Protected local copy avoids consuming archive bytes changed after verification.
    with tempfile.TemporaryDirectory(prefix='surveyscan-pg-restore-') as temp:
        archive = Path(temp) / 'postgres.dump'
        shutil.copyfile(directory / 'postgres.dump', archive)
        archive.chmod(0o600)
        require(archive.stat().st_size == manifest.get('bytes') and digest(archive) == manifest.get('sha256'),
                'backup checksum or size mismatch')
        with archive.open('rb') as stream:
            client.run('pg_restore', ['--list'], stdin=stream)
        client.check(database)
        # Non-default schemas and any user relation/function/type make the target nonempty.
        empty = client.sql(database, """SELECT
            (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname !~ '^pg_') +
            (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('information_schema') AND n.nspname !~ '^pg_') +
            (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname != 'information_schema' AND n.nspname !~ '^pg_') +
            (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname != 'information_schema' AND n.nspname !~ '^pg_')""")
        require(empty == '0', 'restore target must be empty; no objects are removed')
        with archive.open('rb') as stream:
            client.run('pg_restore', ['--no-password', '--exit-on-error', '--single-transaction',
                                      '--no-owner', '--no-acl', '--dbname=' + database], stdin=stream)
    return {'restored': True, 'postgres_major': 17, 'complete_system_restore': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['backup', 'restore'])
    parser.add_argument('--database', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    result = backup(Client(), args.database, args.directory) if args.command == 'backup' else restore(Client(), args.directory, args.database)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('PostgreSQL component operation refused or failed; no complete-system backup claim')
