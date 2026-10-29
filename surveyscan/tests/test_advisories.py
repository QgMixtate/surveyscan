"""Тесты фидов вендоров: загрузчики, разрешение релиза, вердикт по бэкпортам."""
import sqlite3
from pathlib import Path

import pytest

from surveyscan.advisories import (import_feeds, load_debian_json, load_ubuntu_oval,
                                    resolve_distro_release)
from surveyscan.cli import ROOT

ADV = ROOT / "samples" / "advisories"


@pytest.mark.parametrize("os_id,ver,expected", [
    ("astra", "1.7.4", ("astra", "1.7")),
    ("astra", "1.8", ("astra", "1.8")),
    ("ubuntu", "22.04", ("ubuntu", "jammy")),
    ("ubuntu", "24.04", ("ubuntu", "noble")),
    ("debian", "11", ("debian", "bullseye")),
    ("redos", "7.3.4", ("redos", "7.3")),
    ("windows", "10", (None, None)),
])
def test_resolve_release(os_id, ver, expected):
    assert resolve_distro_release(os_id, ver) == expected


def test_ubuntu_oval_parser(tmp_path):
    con = sqlite3.connect(tmp_path / "a.sqlite")
    con.executescript("CREATE TABLE advisory(distro,release,package,cve,fixed_version,status,advisory_id,url);"
                      "CREATE TABLE adv_release(distro,release);")
    n = load_ubuntu_oval(ADV / "com.ubuntu.jammy.pkg.oval.xml", con)
    assert n == 2
    row = con.execute("SELECT fixed_version,status FROM advisory WHERE package='openssh-server' AND cve='CVE-2099-0001'").fetchone()
    assert row == ("1:8.9p1-3ubuntu0.10", "fixed")


def test_debian_json_parser(tmp_path):
    con = sqlite3.connect(tmp_path / "a.sqlite")
    con.executescript("CREATE TABLE advisory(distro,release,package,cve,fixed_version,status,advisory_id,url);"
                      "CREATE TABLE adv_release(distro,release);")
    load_debian_json(ADV / "debian_tracker_sample.json", con)
    # resolved+fixed_version -> fixed; open -> vulnerable; _comment пропущен
    assert con.execute("SELECT status FROM advisory WHERE package='openssh' AND release='bullseye'").fetchone()[0] == "fixed"
    assert con.execute("SELECT status FROM advisory WHERE package='sudo' AND release='bullseye'").fetchone()[0] == "vulnerable"


def test_import_all_feeds(tmp_path):
    counts = import_feeds(tmp_path / "adv.sqlite",
                          ubuntu_oval=[ADV / "com.ubuntu.jammy.pkg.oval.xml"],
                          debian_json=[ADV / "debian_tracker_sample.json"],
                          normalized=[ADV / "astra_normalized.jsonl"])
    assert sum(counts.values()) == 8
    from surveyscan.pgcompat import open_db
    con = open_db(tmp_path / "adv.sqlite", schema="adv")
    rels = {tuple(r) for r in con.execute("SELECT distro, release FROM adv.adv_release").fetchall()}
    assert ("astra", "1.7") in rels and ("ubuntu", "jammy") in rels
