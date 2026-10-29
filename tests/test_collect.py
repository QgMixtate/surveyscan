"""Тесты аутентифицированного сбора (collect.py).

Сетевые вызовы (SSH/SNMP) подменяются, проверяется логика: выбор протокола по
портам/ОС, фильтрация SNMP-ошибок, оркестрация с обогащением активов через ingest.
"""
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from surveyscan import collect
from surveyscan.db import connect
from surveyscan.ingest import ingest_file
from surveyscan.pgcompat import drop_db

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples" / "hosts"


def test_protocols_by_ports_and_os():
    assert collect._protocols({"ports": {22}, "os": "", "kind": "", "ips": []}) == ["ssh"]
    assert collect._protocols({"ports": {3389, 445}, "os": "", "kind": "", "ips": []}) == ["winrm"]
    assert "ssh" in collect._protocols({"ports": set(), "os": "Astra Linux 1.7", "kind": "", "ips": []})
    assert "winrm" in collect._protocols({"ports": set(), "os": "Microsoft Windows 10", "kind": "", "ips": []})
    # шлюз .1 и сетевое устройство -> snmp
    assert "snmp" in collect._protocols({"ports": set(), "os": "", "kind": "Сетевое устройство", "ips": ["10.0.0.5"]})
    assert "snmp" in collect._protocols({"ports": set(), "os": "", "kind": "", "ips": ["10.0.0.1"]})


def test_snmpwalk_filters_error_lines(monkeypatch):
    monkeypatch.setattr(collect.shutil, "which", lambda _x: "/usr/bin/snmpwalk")
    out = 'switch-core\n"No Such Object available on this agent at this OID"\nUpstreamSw'
    monkeypatch.setattr(collect.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout=out, stderr=""))
    vals = collect._snmpwalk("10.0.0.1", "public", "1.0.8802.1.1.2.1.4.1.1.9")
    assert vals == ["switch-core", "UpstreamSw"]      # строки-ошибки SNMP отфильтрованы


def test_snmpwalk_raises_on_failure(monkeypatch):
    monkeypatch.setattr(collect.shutil, "which", lambda _x: "/usr/bin/snmpwalk")
    monkeypatch.setattr(collect.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="Timeout"))
    with pytest.raises(RuntimeError):
        collect._snmpwalk("10.0.0.9", "wrong", "1.3.6.1.2.1.1.5.0")


def test_collect_ssh_enriches_asset(monkeypatch):
    sv = Path(tempfile.mkdtemp()) / "s.sqlite"
    drop_db(sv)
    con = connect(sv)
    try:
        ingest_file(con, SAMPLES / "nmap-10.10.1.0.xml")      # активы из сетевого скана (ещё без ПО)
        con.commit()
        before = con.execute("SELECT count(*) FROM software").fetchone()[0]

        surv_text = (SAMPLES / "astra-app01.surv").read_text(encoding="utf-8")
        # подменяем реальный SSH на возврат готового вывода коллектора
        monkeypatch.setattr(collect, "_ssh_collect", lambda host, cred, script, timeout=60: surv_text)

        creds = [{"type": "ssh", "username": "audit", "secret": "x"}]
        summary = collect.collect(con, creds, ROOT, log=None)
        con.commit()

        assert summary["collected"], "ожидался хотя бы один собранный актив по SSH"
        assert summary["collected"][0]["proto"] == "ssh"
        assert summary["collected"][0]["cred"] == "audit"
        after = con.execute("SELECT count(*) FROM software").fetchone()[0]
        assert after > before, "аутентифицированный сбор должен добавить пакеты/ПО"
    finally:
        con.close()
        drop_db(sv)


def test_collect_snmp_produces_l2_links(monkeypatch):
    sv = Path(tempfile.mkdtemp()) / "s.sqlite"
    drop_db(sv)
    con = connect(sv)
    try:
        ingest_file(con, SAMPLES / "nmap-10.10.1.0.xml")
        from surveyscan.db import find_or_create_asset
        find_or_create_asset(con, hostname="gw1", ips=["10.10.1.1"], kind="netdev")   # шлюз-устройство
        con.commit()
        # вернём SNMP-соседа (LLDP)
        monkeypatch.setattr(collect, "_snmp_collect",
                            lambda host, community, timeout=10: {"sysname": "gw1", "sysdescr": "RouterOS",
                                                                 "lldp_neighbors": ["core-dist-1"]})
        creds = [{"type": "snmp", "secret": "public"}]
        summary = collect.collect(con, creds, ROOT, log=None)
        assert any(l["b"] == "core-dist-1" for l in summary["l2_links"]), "ожидалась L2-связь из LLDP"
    finally:
        con.close()
        drop_db(sv)
