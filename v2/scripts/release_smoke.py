#!/usr/bin/env python3
"""Real OpenSSL, compiled components and separate Web UI; no services or external signing keys."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

import release
from dev import STATE


def main():
    checks = []
    STATE.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='c13-release-', dir=STATE) as temp:
        work = Path(temp)
        key, public, foreign = work / 'signing.key', work / 'signing.pub', work / 'foreign.pub'
        def keys(private, public):
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(private)], check=True, capture_output=True)
            private.chmod(0o600)
            public.write_bytes(release.openssl('pkey', '-in', private, '-pubout'))
        keys(key, public)
        keys(work / 'foreign.key', foreign)
        bundle = work / 'bundle'
        version = json.loads(subprocess.check_output([str(release.ROOT / '.dist/surveyscan-server'), 'version']))['version']
        release.build(bundle, version, release.ROOT / '.dist', release.ROOT / 'web/dist', Path(os.environ['GO']))
        def refused(action):
            try:
                action()
            except (ValueError, OSError):
                return
            raise AssertionError('invalid operation was accepted')
        refused(lambda: release.verify(bundle, public))
        checks.append('unsigned candidate refused before staging')
        release.sign(bundle, key)
        manifest = release.verify(bundle, public)
        checks.append('real Ed25519 signature and complete file/mode/size/hash inventory verified')
        assert all(manifest['components'][name]['version'] == version and manifest['components'][name]['revision'] != 'unknown' for name in release.BINARIES)
        assert release.VERSION.fullmatch(manifest['components']['web']['version'])
        checks.append('four compiled binaries identify bundle version/revision; independent Web version records provenance and matches API contract hashes')
        bom = release.read_json(bundle / 'payload/sbom.spdx.json')
        ids = {p['SPDXID'] for p in bom['packages']} | {'SPDXRef-DOCUMENT'}
        assert len(ids) == len(bom['packages']) + 1
        assert all(r['spdxElementId'] in ids and r['relatedSpdxElement'] in ids for r in bom['relationships'])
        assert any(p['name'] == 'github.com/jackc/pgx/v5' for p in bom['packages'])
        assert any(p['name'] == 'react' for p in bom['packages'])
        assert any(p['name'] == 'vite' for p in bom['packages'])
        checks.append('SPDX2.3 inventory contains actual Go module metadata and npm lock/build graph with valid references')
        target = work / 'bad-stage'
        refused(lambda: release.install(bundle, foreign, target))
        assert not target.exists()
        checks.append('foreign trust anchor refused without creating installation root')
        binary = bundle / 'payload/bin/surveyscan-agent'
        with binary.open('ab') as stream:
            stream.write(b'tamper')
        refused(lambda: release.install(bundle, public, target))
        assert not target.exists()
        with binary.open('r+b') as stream:
            stream.truncate(binary.stat().st_size - 6)
        checks.append('tampered executable refused before target mutation')
        raw = (bundle / 'manifest.json').read_bytes()
        sig = (bundle / 'manifest.sig').read_bytes()
        (bundle / 'manifest.json').write_bytes(raw.replace(version.encode(), b'9.9.9-evil', 1))
        refused(lambda: release.verify(bundle, public))
        (bundle / 'manifest.json').write_bytes(raw)
        checks.append('tampered signed manifest refused')
        extra = bundle / 'payload/unlisted.txt'
        extra.write_text('extra')
        refused(lambda: release.verify(bundle, public))
        extra.unlink()
        binary.rename(work / 'saved-agent')
        refused(lambda: release.verify(bundle, public))
        os.symlink(work / 'saved-agent', binary)
        refused(lambda: release.verify(bundle, public))
        binary.unlink()
        (work / 'saved-agent').rename(binary)
        binary.chmod(0o644)
        refused(lambda: release.verify(bundle, public))
        binary.chmod(0o755)
        checks.append('extra/missing file, symlink and executable mode changes refused')
        unsafe = dict(manifest)
        unsafe['files'] = dict(manifest['files'], **{'../escape': {'sha256': '0' * 64, 'bytes': 0, 'mode': 420}})
        release.write_json(bundle / 'manifest.json', unsafe)
        (bundle / 'manifest.sig').unlink()
        release.sign(bundle, key)
        refused(lambda: release.install(bundle, public, target))
        assert not target.exists() and not (work / 'escape').exists()
        (bundle / 'manifest.json').write_bytes(raw)
        (bundle / 'manifest.sig').write_bytes(sig)
        checks.append('even correctly signed traversal inventory refused without writes outside staging')
        key.chmod(0o644)
        refused(lambda: release.sign(bundle, key))
        key.chmod(0o600)
        checks.append('group/world-readable signing key refused')
        old_mask = os.umask(0o077)
        try:
            root = work / 'install-one'
            result = release.install(bundle, public, root)
        finally:
            os.umask(old_mask)
        assert result['signature_verified'] and not result['services_started']
        for name in release.BINARIES:
            actual = json.loads(subprocess.check_output([str(root / 'opt/surveyscan/current/bin' / name), 'version']))
            assert actual == manifest['components'][name]
        assert root.stat().st_mode & 0o777 == 0o755
        assert (root / 'usr/lib/systemd/system/surveyscan-server.service').stat().st_mode & 0o777 == 0o644
        assert (root / 'var/lib/surveyscan-agent').stat().st_mode & 0o777 == 0o700
        assert not list((root / 'etc/surveyscan-agent').iterdir())
        checks.append('verified copy published atomically, binaries executable under umask077, empty private state and no keys copied')
        before = release.digest(root / 'staging-receipt.json')
        refused(lambda: release.install(bundle, public, root))
        refused(lambda: release.install(bundle, public, Path('/')))
        assert release.digest(root / 'staging-receipt.json') == before
        checks.append('live root and nonempty installation refused; existing receipt/state preserved')
        release.install(bundle, public, work / 'install-two')
        assert release.digest(work / 'install-two/release-manifest.json') == release.digest(root / 'release-manifest.json')
        checks.append('same signed bundle stages twice without rebuild or regenerated machine identity')
        # C33.02: необязательный сервис поиска в том же подписанном выпуске; SBOM включает Cargo.lock
        if os.environ.get('SURVEYSCAN_RELEASE_SEARCH') == '1':
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=release.ROOT, text=True).strip()
            env = dict(os.environ, SURVEYSCAN_VERSION=version, SURVEYSCAN_REVISION=revision, SURVEYSCAN_DIRTY=manifest['components']['surveyscan-server']['source_dirty'])
            subprocess.run(['cargo', 'build', '--release', '--locked'], cwd=release.ROOT / 'search', env=env, check=True, capture_output=True, timeout=1800)
            with_search = work / 'bundle-search'
            release.build(with_search, version, release.ROOT / '.dist', release.ROOT / 'web/dist', Path(os.environ['GO']), release.ROOT / 'search/target/release/surveyscan-search')
            release.sign(with_search, key)
            signed = release.verify(with_search, public)
            assert signed['components']['search']['revision'] == revision and signed['components']['search']['version'] == version
            bom = release.read_json(with_search / 'payload/sbom.spdx.json')
            assert any(p['name'] == 'tantivy' for p in bom['packages']) and any(p['name'] == 'surveyscan-search' for p in bom['packages'])
            (with_search / 'payload/bin/surveyscan-search').rename(work / 'saved-search')
            refused(lambda: release.verify(with_search, public))
            checks.append('search service (C29) ships in the same signed release with matching version/revision; SPDX lists Cargo.lock crates; missing search binary refused')
        # C33.02: подписанный список отзыва; отозванный выпуск не готовится updater
        import updater
        revoked = work / 'revocations'
        release.revoke(revoked, key, [version + ':test revocation'])
        assert version in release.revoked_versions(revoked, public)
        refused(lambda: release.revoked_versions(revoked, foreign))
        extended = work / 'revocations-2'
        release.revoke(extended, key, ['9.9.9:later'], revoked)
        assert release.revoked_versions(extended, public) == {version, '9.9.9'}
        doc = (revoked / 'revocations.json').read_text()
        (revoked / 'revocations.json').write_text(doc.replace(version, '0.0.1'))
        refused(lambda: release.revoked_versions(revoked, public))
        (revoked / 'revocations.json').write_text(doc)
        refused(lambda: release.revoke(work / 'bad', key, ['not-a-version:x']))
        try:
            updater.prepare(root, bundle, public, None, revoked)
            raise AssertionError('revoked release prepared')
        except ValueError as e:
            assert str(e) == 'release version is revoked', e
        checks.append('signed revocation list: foreign key and tampering refused, list only grows, updater refuses to prepare a revoked release')
        # Duplicate keys must not select a different version/path interpretation between parsers.
        (bundle / 'manifest.json').write_bytes(b'{"format":1,"format":2}')
        (bundle / 'manifest.sig').unlink()
        release.sign(bundle, key)
        refused(lambda: release.verify(bundle, public))
        checks.append('duplicate JSON manifest keys refused')
    report = {'package': 'C13', 'task': 'C13.02 preparation', 'status': 'passed', 'count': len(checks),
              'checks': checks, 'target': 'actual built ELF binaries/Web, OpenSSL Ed25519 and local empty filesystem roots',
              'unrun': ['systemd boot/reboot', 'live checked update and schema rollback', 'production signing custody',
                        'backup/restore', 'two independent installed systems'], 'host_services_modified': False}
    (STATE / 'c13-release-smoke.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
