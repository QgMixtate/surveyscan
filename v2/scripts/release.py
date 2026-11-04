#!/usr/bin/env python3
"""Offline signed directory bundles and verified staging. Never manage live services.

Trust anchor is an operator-provided Ed25519 public key, never a key from the bundle.
Signing is explicit and separate from build; OpenSSL 3 and Python 3 are target prerequisites.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
BINARIES = {'surveyscan-server': 'server', 'surveyscan-agent': 'agent',
            'surveyscan-collector': 'collector', 'surveyscanctl': 'cli'}
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9][a-zA-Z0-9.-]*)?')
MAX_FILES = 10000
MAX_BYTES = 512 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    path.chmod(0o644)


def read_json(path, limit=2 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
            'bounded regular JSON file required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def inventory(root):
    require(root.is_dir() and not root.is_symlink(), 'regular directory required')
    result = {}
    total = 0
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                'symlinks and special files are forbidden')
        name = path.relative_to(root).as_posix()
        require(all(32 < ord(c) < 127 for c in name) and '\\' not in name,
                'only printable ASCII artifact paths without whitespace are supported')
        if path.is_dir():
            require(stat.S_IMODE(info.st_mode) == 0o755, 'artifact directory must have mode 0755')
            continue
        require(stat.S_IMODE(info.st_mode) in (0o644, 0o755), 'invalid artifact mode')
        total += info.st_size
        require(total <= MAX_BYTES and len(result) < MAX_FILES, 'bundle exceeds limits')
        result[name] = {'sha256': digest(path), 'bytes': info.st_size,
                        'mode': stat.S_IMODE(info.st_mode)}
    return result


def openssl(*args):
    # Do not forward OpenSSL diagnostics: private key/provider paths are operator data.
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, timeout=30)
    require(result.returncode == 0, 'OpenSSL signature operation failed')
    return result.stdout


def sign(bundle, key):
    info = key.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and not stat.S_IMODE(info.st_mode) & 0o077, 'owner-only private signing key required')
    require_ed25519(openssl('pkey', '-in', key, '-pubout', '-outform', 'DER'))
    signature = openssl('pkeyutl', '-sign', '-rawin', '-inkey', key,
                        '-in', bundle / 'manifest.json')
    require(len(signature) == 64, 'Ed25519 signing key required')
    with (bundle / 'manifest.sig').open('xb') as stream:
        stream.write(signature)
    (bundle / 'manifest.sig').chmod(0o644)


def require_ed25519(der):
    require(len(der) == 44 and der[:12] == bytes.fromhex('302a300506032b6570032100'),
            'Ed25519 key required')


def verify(bundle, public_key):
    require(bundle.is_dir() and not bundle.is_symlink(), 'bundle directory required')
    require({p.name for p in bundle.iterdir()} == {'manifest.json', 'manifest.sig', 'payload'},
            'unexpected or missing bundle entries')
    signature = bundle / 'manifest.sig'
    require(signature.is_file() and not signature.is_symlink() and signature.stat().st_size == 64,
            'Ed25519 detached signature required')
    manifest = read_json(bundle / 'manifest.json')
    require_ed25519(openssl('pkey', '-pubin', '-in', public_key, '-outform', 'DER'))
    openssl('pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', public_key,
            '-in', bundle / 'manifest.json', '-sigfile', signature)
    require(manifest.get('format') == 'surveyscan-release-v1', 'unsupported manifest')
    require(VERSION.fullmatch(manifest.get('version', '')) is not None, 'invalid release version')
    require(manifest.get('platform') == 'linux/amd64', 'unsupported platform')
    expected = manifest.get('files')
    require(isinstance(expected, dict), 'file inventory required')
    for name in expected:
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
                'unsafe manifest path')
    actual = inventory(bundle / 'payload')
    require(actual == expected, 'artifact set, digest, size or mode mismatch')
    for name in BINARIES:
        require(actual.get('bin/' + name, {}).get('mode') == 0o755, 'missing executable component')
    require({'web/index.html', 'web/version.json', 'sbom.spdx.json', 'CHECKSUMS.sha256'} <= actual.keys(),
            'missing Web UI or release metadata')
    sums = ''.join(f'{data["sha256"]}  {name}\n' for name, data in actual.items()
                   if name != 'CHECKSUMS.sha256')
    require((bundle / 'payload/CHECKSUMS.sha256').read_text() == sums, 'checksum index mismatch')
    # Verification never invokes any executable delivered in the bundle.
    return manifest


def sbom(payload, versions, go):
    packages = []
    relationships = []
    for name in BINARIES:
        identifier = 'SPDXRef-' + name
        packages.append({'SPDXID': identifier, 'name': name, 'versionInfo': versions[name]['version'],
                         'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False,
                         'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION',
                         'copyrightText': 'NOASSERTION',
                         'checksums': [{'algorithm': 'SHA256', 'checksumValue': digest(payload / 'bin' / name)}]})
        relationships.append({'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES',
                              'relatedSpdxElement': identifier})
    modules = {}
    for name in BINARIES:
        output = subprocess.check_output([str(go), 'version', '-m', str(payload / 'bin' / name)], text=True)
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0] == 'dep':
                module, version = fields[1:3]
                module_id = 'SPDXRef-go-' + hashlib.sha256((module + '@' + version).encode()).hexdigest()[:24]
                modules[module_id] = {'SPDXID': module_id, 'name': module, 'versionInfo': version,
                    'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False,
                    'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION',
                    'copyrightText': 'NOASSERTION', 'comment': 'Go build metadata: ' + ' '.join(fields[3:])}
                relationships.append({'spdxElementId': 'SPDXRef-' + name, 'relationshipType': 'DEPENDS_ON',
                                      'relatedSpdxElement': module_id})
    packages.extend(modules.values())
    lock = read_json(ROOT / 'web/package-lock.json')
    for path, data in lock['packages'].items():
        if not path:
            continue
        identifier = 'SPDXRef-npm-' + hashlib.sha256(path.encode()).hexdigest()[:24]
        packages.append({'SPDXID': identifier, 'name': path.rsplit('node_modules/', 1)[-1],
                         'versionInfo': data['version'], 'downloadLocation': 'NOASSERTION',
                         'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION',
                         'licenseDeclared': data.get('license', 'NOASSERTION'), 'copyrightText': 'NOASSERTION',
                         'comment': 'npm lock entry; inclusion in emitted JS not attested; integrity=' + data.get('integrity', 'unknown')})
        relationships.append({'spdxElementId': identifier, 'relationshipType': 'BUILD_DEPENDENCY_OF',
                              'relatedSpdxElement': 'SPDXRef-web'})
    packages.append({'SPDXID': 'SPDXRef-web', 'name': '@surveyscan/web',
                     'versionInfo': versions['web']['version'], 'downloadLocation': 'NOASSERTION',
                     'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION',
                     'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION'})
    relationships.append({'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES',
                          'relatedSpdxElement': 'SPDXRef-web'})
    namespace = hashlib.sha256(json.dumps(versions, sort_keys=True).encode()).hexdigest()
    epoch = subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=ROOT, text=True).strip()
    created = datetime.fromtimestamp(int(epoch), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
            'name': 'surveyscan-v2', 'documentNamespace': 'https://surveyscan.invalid/spdx/' + namespace,
            'creationInfo': {'creators': ['Tool: surveyscan-release-v1'],
                             'created': created,
                             'comment': 'Dependency inventory, not vulnerability or license compliance attestation. External PG/Bao/systemd/edge are prerequisites, not bundled.'},
            'packages': packages, 'relationships': relationships}


def build(output, version, distribution, web, go):
    require(VERSION.fullmatch(version) is not None, 'semantic version required')
    require(not output.exists() and not output.is_symlink(), 'new output directory required')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.release-', dir=output.parent) as temp:
        bundle = Path(temp) / 'bundle'
        payload = bundle / 'payload'
        (payload / 'bin').mkdir(parents=True)
        versions = {}
        for name, component in BINARIES.items():
            source = distribution / name
            require(source.is_file() and not source.is_symlink(), 'regular locally built binary required')
            with source.open('rb') as stream:
                header = stream.read(20)
            require(header[:6] == b'\x7fELF\x02\x01' and header[18:20] == b'\x3e\x00',
                    'Linux amd64 ELF binary required')
            shutil.copyfile(source, payload / 'bin' / name)
            (payload / 'bin' / name).chmod(0o755)
            versions[name] = json.loads(subprocess.check_output([str(payload / 'bin' / name), 'version'], timeout=10))
            require(versions[name]['component'] == component and versions[name]['version'] == version,
                    'build all four binaries with requested VERSION first')
        versions['web'] = read_json(web / 'version.json')
        require(versions['web']['version'] == version, 'build Web UI with requested SURVEYSCAN_VERSION first')
        revisions = {v['revision'] for v in versions.values()}
        require(len(revisions) == 1 and re.fullmatch('[0-9a-f]{40}', revisions.pop()), 'component revision mismatch')
        require(all(v.get('source_dirty') in ('true', 'false') for v in versions.values()), 'source provenance required')
        source_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        require(all(v['revision'] == source_revision for v in versions.values()), 'rebuild components after changing source revision')
        for field, name in [('openapi_sha256', 'openapi.json'), ('c09_sha256', 'c09.openapi.json'),
                            ('c12_sha256', 'c12.openapi.json')]:
            require(versions['web'].get(field) == digest(distribution / 'contracts' / name),
                    'Web/API contract mismatch; rebuild Web UI and binaries')
        for source, name in [(distribution / 'contracts', 'contracts'), (web, 'web'),
                             (ROOT / 'deploy/systemd', 'systemd')]:
            require(source.is_dir() and not source.is_symlink() and not any(p.is_symlink() for p in source.rglob('*')),
                    'regular artifact directories required')
            shutil.copytree(source, payload / name)
        for path in payload.rglob('*'):
            path.chmod(0o755 if path.is_dir() or path.parent.name == 'bin' else 0o644)
        payload.chmod(0o755)
        write_json(payload / 'sbom.spdx.json', sbom(payload, versions, go))
        files = inventory(payload)
        sums = payload / 'CHECKSUMS.sha256'
        sums.write_text(''.join(f'{data["sha256"]}  {name}\n' for name, data in files.items()))
        sums.chmod(0o644)
        write_json(bundle / 'manifest.json', {'format': 'surveyscan-release-v1', 'version': version,
            'platform': 'linux/amd64', 'components': versions, 'files': inventory(payload),
            'source_revision': source_revision,
            'source_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT)),
            'wire': {'major': 1, 'baseline_minor': 0, 'profile_minor': 1},
            'requires': ['systemd>=252', 'PostgreSQL17', 'OpenBao2.7.2', 'operator TLS/PKI and custody', 'static Web edge'],
            'scope': 'C13 candidate; systemd boot and upgrade/restore acceptance pending'})
        bundle.chmod(0o755)
        os.rename(bundle, output)
    return {'built': True, 'version': version, 'signed': False}


def install(bundle, public_key, target):
    # Empty staging only. No mutation of a live /opt or current symlink; service orchestration comes later.
    require(target.absolute() != Path('/') and not target.is_symlink(), 'empty staging root required')
    require(not target.exists() or target.is_dir() and not any(target.iterdir()), 'empty staging root required')
    manifest = verify(bundle, public_key)
    target = target.absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.checked-stage-', dir=target.parent) as temp:
        work = Path(temp)
        snapshot = work / 'snapshot'
        shutil.copytree(bundle, snapshot, symlinks=True)
        # Verify the copied bytes too, before publishing anything into the target.
        copied = verify(snapshot, public_key)
        require(digest(snapshot / 'manifest.json') == digest(bundle / 'manifest.json') and copied == manifest,
                'bundle changed during staging')
        root = work / 'root'
        release = root / 'opt/surveyscan/releases' / manifest['version']
        release.parent.mkdir(parents=True)
        shutil.copytree(snapshot / 'payload', release)
        os.symlink('releases/' + manifest['version'], root / 'opt/surveyscan/current')
        units = root / 'usr/lib/systemd/system'
        units.mkdir(parents=True)
        for unit in (release / 'systemd').glob('*.service'):
            shutil.copyfile(unit, units / unit.name)
        sysusers = root / 'usr/lib/sysusers.d'
        sysusers.mkdir(parents=True)
        shutil.copyfile(release / 'systemd/surveyscan.conf', sysusers / 'surveyscan.conf')
        for component in ('server', 'collector', 'agent', 'bao'):
            (root / ('etc/surveyscan-' + component)).mkdir(parents=True)
            state = root / ('var/lib/surveyscan-' + component)
            state.mkdir(parents=True, mode=0o700)
        for directory in (root, *[p for p in root.rglob('*') if p.is_dir() and not p.is_symlink()]):
            directory.chmod(0o755)
        for component in ('server', 'collector', 'agent', 'bao'):
            (root / ('var/lib/surveyscan-' + component)).chmod(0o700)
        for public in (*units.glob('*.service'), sysusers / 'surveyscan.conf'):
            public.chmod(0o644)
        shutil.copyfile(snapshot / 'manifest.json', root / 'release-manifest.json')
        shutil.copyfile(snapshot / 'manifest.sig', root / 'release-manifest.sig')
        write_json(root / 'staging-receipt.json', {'format': 1, 'version': manifest['version'],
            'manifest_sha256': digest(snapshot / 'manifest.json'), 'host_services_modified': False,
            'scope': 'verified filesystem staging; not live installation or schema upgrade'})
        # Publish only to a new/empty target, preserving existing installation/state by refusal.
        os.rename(root, target)
    return {'staged': True, 'version': manifest['version'], 'signature_verified': True,
            'services_started': False, 'live_update_supported': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('build')
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--version', required=True)
    p.add_argument('--dist', type=Path, default=ROOT / '.dist')
    p.add_argument('--web', type=Path, default=ROOT / 'web/dist')
    p.add_argument('--go', type=Path, default=Path(os.environ.get('GO', 'go')))
    for command in ('sign', 'verify', 'stage'):
        p = commands.add_parser(command)
        p.add_argument('--bundle', required=True, type=Path)
        p.add_argument('--key' if command == 'sign' else '--public-key', required=True, type=Path)
        if command == 'stage':
            p.add_argument('--root', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'build':
        result = build(args.output, args.version, args.dist, args.web, args.go)
    elif args.command == 'sign':
        sign(args.bundle, args.key)
        result = {'signed': True}
    elif args.command == 'verify':
        manifest = verify(args.bundle, args.public_key)
        result = {'verified': True, 'version': manifest['version'], 'files': len(manifest['files'])}
    else:
        result = install(args.bundle, args.public_key, args.root)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('release operation refused; check artifacts, trusted key and arguments')
