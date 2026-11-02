"""Регрессии инвентаризации без подключения к обследуемым хостам."""
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from surveyscan import ingest, report
from surveyscan.db import SCHEMA
from surveyscan.reporttpl import load_template

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("line", [
    '0 0 10.0.0.2:22 10.0.0.3:50123 users:(("sshd",pid=7,fd=3))',
    'ESTAB 0 0 10.0.0.2:22 10.0.0.3:50123 users:(("sshd",pid=7,fd=3))',
    'tcp ESTAB 0 0 10.0.0.2:22 10.0.0.3:50123 users:(("sshd",pid=7,fd=3))',
    'tcp 0 0 10.0.0.2:22 10.0.0.3:50123 ESTABLISHED 7/sshd',
])
def test_connections_ss_and_netstat(line):
    assert ingest._parse_ss_conn(line) == [{
        "local_address": "10.0.0.2", "local_port": 22,
        "remote_address": "10.0.0.3", "remote_port": 50123, "process": "sshd",
    }]


def test_connections_ipv6_without_process_and_netstat_state_filter():
    rows = ingest._parse_ss_conn('0 0 [2001:db8::2]:443 [2001:db8::3]:50000')
    assert rows[0]["remote_address"] == "2001:db8::3"
    assert rows[0]["process"] is None
    assert ingest._parse_ss_conn('tcp 0 0 10.0.0.2:22 0.0.0.0:* LISTEN 7/sshd') == []
    assert ingest._parse_ss_conn('Recv-Q Send-Q Local Peer\nmalformed') == []


@pytest.mark.parametrize("line,proto,addr,port,process", [
    ('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=7,fd=3))', "tcp", "0.0.0.0", 22, "sshd"),
    ('tcp6 0 0 :::22 :::* LISTEN 7/sshd', "tcp", "::", 22, "sshd"),
    ('udp 0 0 127.0.0.1:53 0.0.0.0:* -', "udp", "127.0.0.1", 53, None),
])
def test_listening_ss_and_netstat(line, proto, addr, port, process):
    assert ingest._parse_ss(line) == [{"proto": proto, "address": addr, "port": port, "process": process}]


def test_routes_fallback_and_incomplete_tokens():
    rows = ingest._parse_linux_routes('''Kernel IP routing table
Destination Gateway Genmask Flags Metric Ref Use Iface
0.0.0.0 10.0.0.1 0.0.0.0 UG 100 0 0 eth0
10.0.0.0 0.0.0.0 255.255.255.0 U 100 0 0 eth0
''')
    assert rows[0] == {"destination": "0.0.0.0/0", "gateway": "10.0.0.1", "interface": "eth0", "metric": "100"}
    assert rows[1]["destination"] == "10.0.0.0/24"
    assert rows[1]["gateway"] is None
    rows = ingest._parse_linux_routes('default via 10.0.0.1 dev eth0 metric 20\nblackhole 192.0.2.0/24\ndefault via\nbroken')
    assert len(rows) == 3
    assert rows[0]["metric"] == "20"
    assert rows[1]["destination"] == "192.0.2.0/24"
    assert rows[2]["gateway"] is None


@pytest.mark.parametrize("addr", [
    'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n    inet 10.0.0.2 netmask 255.255.255.0\n    ether 00:11:22:33:44:55',
    'eth0 Link encap:Ethernet HWaddr 00:11:22:33:44:55\n    inet addr:10.0.0.2 Bcast:10.0.0.255 Mask:255.255.255.0',
    'eth0: flags=4163<UP> mtu 1500\n    inet 10.0.0.2 netmask 0xffffff00\n    ether 00:11:22:33:44:55',
])
def test_interfaces_ifconfig(addr):
    assert ingest._parse_linux_interfaces("", addr) == [{
        "name": "eth0", "mac": "00:11:22:33:44:55", "addresses": [{"ip": "10.0.0.2", "prefix": 24}],
    }]


def test_interfaces_ip_alias_ipv6():
    rows = ingest._parse_linux_interfaces(
        '2: eth0@if3: <UP> mtu 1500 link/ether 00:11:22:33:44:55',
        '2: eth0@if3 inet 10.0.0.2/24 scope global eth0\n2: eth0@if3 inet6 2001:db8::2/64 scope global')
    assert len(rows) == 1 and rows[0]["name"] == "eth0"
    assert rows[0]["addresses"][1] == {"ip": "2001:db8::2", "prefix": 64}
    assert ingest._parse_linux_interfaces('3: tun0: <UP> mtu 1500 link/none', '') == [
        {"name": "tun0", "mac": None, "addresses": []}]


def test_linux_collector_status_without_host_collection():
    shell = shutil.which("sh")
    if not shell and Path("C:/Program Files/Git/bin/sh.exe").exists():
        shell = "C:/Program Files/Git/bin/sh.exe"
    if not shell:
        pytest.skip("sh не установлен")
    source = (ROOT / "collectors" / "linux_collect.sh").read_text(encoding="utf-8")
    helpers = source.split("sec meta", 1)[0]
    script = helpers + '''
empty_result() { :; }
denied_result() { return 1; }
inventory_run empty empty_result
inventory_run denied denied_result
inventory_run missing surveyscan_nonexistent_command
printf '%b' "$INVENTORY_STATUS"
'''
    result = subprocess.run([shell], input=script, text=True, capture_output=True, check=True, timeout=10)
    assert ingest._kv(result.stdout) == {"empty": "ok", "denied": "unavailable", "missing": "unavailable"}


@pytest.fixture
def inventory_db(monkeypatch):
    # Проверяем реальный SQL ingest/report; только PostgreSQL-проверка наличия БДУ подменена.
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    con.execute("INSERT INTO survey(name) VALUES ('inventory-test')")
    monkeypatch.setattr("surveyscan.pgcompat.schema_exists", lambda *args: False)
    yield con
    con.close()


def dashboard(con, tmp_path):
    return report.dashboard_json(report.collect(con, tmp_path, load_template(None)))


def test_linux_ingest_to_dashboard(inventory_db, tmp_path):
    path = tmp_path / "linux.surv"
    path.write_text('''@@@SURVEY:meta@@@
uid=0
@@@SURVEY:hostname@@@
test-linux
@@@SURVEY:ip_addr@@@
2: eth0 inet 10.0.0.2/24 scope global eth0
@@@SURVEY:connections@@@
0 0 10.0.0.2:22 10.0.0.3:50123
@@@SURVEY:resolv_conf@@@
  nameserver 10.0.0.53
@@@SURVEY:collection_status@@@
ip_addr=ok
ip_link=unavailable
connections=ok
dns=ok
routes=unavailable
@@@SURVEY:end@@@
ok
''', encoding="utf-8")
    ingest.ingest_file(inventory_db, path)
    inv = dashboard(inventory_db, tmp_path)["assets"][0]["inventory"]
    assert inv["connections"][0]["remote_port"] == 50123
    assert inv["dns"] == ["10.0.0.53"]
    assert inv["collection_status"]["nics"] == "partial"
    assert inv["collection_status"]["routes"] == "unavailable"


def test_linux_ifconfig_ips_reach_asset(inventory_db, tmp_path):
    path = tmp_path / "fallback.surv"
    path.write_text('''@@@SURVEY:hostname@@@
fallback
@@@SURVEY:ip_addr@@@
eth0: flags=4163<UP> mtu 1500
    inet 10.0.0.2 netmask 255.255.255.0
    ether 00:11:22:33:44:55
''', encoding="utf-8")
    ingest.ingest_file(inventory_db, path)
    a = dashboard(inventory_db, tmp_path)["assets"][0]
    assert a["ips"] == "10.0.0.2"
    assert a["inventory"]["is_root"] is None
    assert not a["partial"]


def test_windows_ingest_preserves_new_inventory_and_status(inventory_db, tmp_path):
    facts = {
        "nics": [{"name": "Ethernet", "ip": ["10.0.0.2", "2001:db8::2"], "mask": ["255.255.255.0", "64"]}],
        "groups": [{"name": "Operators", "members": None}],
        "disks": [{"id": "C:", "free_gb": 0}], "shares": [], "usb_devices": [],
        "services": [{"name": "test", "path": "C:\\test\u0000.exe"}],
        "connections": [{"local_port": 22, "remote_port": 50123}],
        "routes": [{"destination": "0.0.0.0/0", "metric": 0}],
        "collection_status": {"groups": "partial", "shares": "ok", "usb_devices": "unavailable", "services": "ok"},
    }
    data = {"meta": {"collector": "windows_collect.ps1", "is_admin": False},
            "host": {"hostname": "test-windows", "ips": ["10.0.0.2"]}, "facts": facts,
            "software": [{"name": "app\u0000", "version": "1.0"}], "hotfixes": [{"id": "KB123"}]}
    path = tmp_path / "windows.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    ingest.ingest_file(inventory_db, path)
    a = dashboard(inventory_db, tmp_path)["assets"][0]
    inv = a["inventory"]
    assert inv["is_admin"] is False
    assert inv["software"][0]["name"] == "app"
    assert inv["services"][0]["path"] == "C:\\test.exe"
    assert inv["groups"][0]["members"] is None
    assert inv["disks"][0]["free_gb"] == 0
    assert inv["nics"][0]["mask"] == ["255.255.255.0", "64"]
    assert inv["hotfixes"] == ["123"]
    assert inv["collection_status"] == facts["collection_status"]


def test_legacy_absence_is_unknown_and_root_is_unknown():
    facts = ingest.linux_facts({})
    assert facts["is_root"] is None
    inv = report._build_inventory({"os_family": "windows", "kind": "host"}, {}, [], [])
    assert inv["collection_status"] == {}
    assert inv["part_of_domain"] is None


def test_windows_collector_mocked():
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell не установлен")
    result = subprocess.run([shell, "-NoProfile", "-File", str(ROOT / "tests" / "windows_inventory_mock.ps1")],
                            capture_output=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
