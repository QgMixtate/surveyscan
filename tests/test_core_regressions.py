"""Регрессии импорта и сетевого профиля config; внешние вызовы подменены."""
import shutil

from surveyscan.api import runner
from surveyscan.cli import ROOT
from surveyscan.db import apply_role_guess, connect, find_or_create_asset
from surveyscan.pgcompat import drop_db


def test_import_role_defaults_preserve_explicit_roles(tmp_path):
    sv = tmp_path / 'survey.sqlite'
    con = connect(sv)
    try:
        host = find_or_create_asset(con, hostname='host')
        device = find_or_create_asset(con, hostname='switch', kind='netdev')
        special = find_or_create_asset(con, hostname='plc', role='ics')
        for aid in (host, device, special):
            apply_role_guess(con, aid)
        roles = {r['hostname']: r['role'] for r in con.execute('SELECT hostname,role FROM asset')}
        assert roles == {'host': 'it', 'switch': 'netdev', 'plc': 'ics'}
    finally:
        con.close()
        drop_db(sv)


def test_network_config_evaluates_collected_facts(monkeypatch):
    from surveyscan import collect
    monkeypatch.setattr(runner, 'nmap_scan', lambda targets, out, **kw:
                        shutil.copyfile(ROOT / 'samples/hosts/nmap-10.10.1.0.xml', out))

    def fake_collect(con, *args, **kwargs):
        from surveyscan.ingest import ingest_file
        ingest_file(con, ROOT / 'samples/hosts/astra-app01.surv')
        return {'collected': [], 'failed': [], 'l2_links': []}

    monkeypatch.setattr(collect, 'collect', fake_collect)
    result, html, dashboard = runner.run_pipeline(
        'config regression', None, {'kind': 'config', 'targets': 'example.invalid'},
        creds=[{'type': 'ssh', 'username': 'audit', 'secret': 'fake'}])
    assert result['source'] == 'network'
    assert result['config']['base']['pass'] + result['config']['base']['fail'] > 0
