"""Сквозной прогон на синтетических данных из samples/ и проверка ключевых результатов."""
import json
import sqlite3
from pathlib import Path

import pytest

from surveyscan.bdu import iter_records
from surveyscan.cli import ROOT, main
from surveyscan.configcheck import evaluate, load_checks, load_catalog
from surveyscan.ingest import linux_facts, parse_sections
from surveyscan.msrc import host_products


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    out = tmp_path_factory.mktemp("demo")
    main(["demo", "--out", str(out)])
    from surveyscan.pgcompat import open_db
    con = open_db(out / "survey.sqlite", schema="public")
    return out, con


def findings(con, host):
    return {r["bdu_id"] or r["cve"] or r["product"]: r for r in con.execute(
        "SELECT f.* FROM vuln_finding f JOIN asset a ON a.id = f.asset_id WHERE COALESCE(a.hostname, a.ips) LIKE ?",
        (f"%{host}%",))}


def result(con, host, check, profile="base"):
    row = con.execute("SELECT c.result, c.actual FROM check_result c JOIN asset a ON a.id = c.asset_id "
                      "WHERE a.hostname = ? AND c.check_id = ? AND c.profile = ?", (host, check, profile)).fetchone()
    return tuple(row) if row else None


def test_bdu_parser_reads_both_name_tags():
    recs = {r["id"]: r for r in iter_records(ROOT / "samples" / "bdu" / "vulxml_sample.xml")}
    assert recs["BDU:2099-00002"]["name"].startswith("Уязвимость утилиты sudo")      # тег <n>
    assert recs["BDU:2099-00001"]["cvss2_score"] == 9.3                              # «9,3»
    assert recs["BDU:2099-00001"]["severity_level"] == "critical"
    assert recs["BDU:2099-00013"]["cves"] == []                                      # только БДУ


def test_assets_merged_by_ip(demo):
    _, con = demo
    names = sorted(r[0] or "" for r in con.execute("SELECT hostname FROM asset"))
    assert names == ["", "WS-BUH-07", "astra-app01", "core-sw1", "redos-db01"]


def test_direct_bdu_matches_on_astra(demo):
    _, con = demo
    f = findings(con, "astra-app01")
    # OpenSSH закрыт бэкпортом по фиду вендора -> снят (и из инвентаря, и из сетевого сервиса)
    assert "BDU:2099-00001" not in f
    assert not con.execute("SELECT 1 FROM vuln_finding v JOIN asset a ON a.id=v.asset_id "
                           "WHERE a.hostname='astra-app01' AND v.product LIKE 'openssh%'").fetchall()
    # sudo: фид вендора подтверждает и даёт целевую версию обновления
    assert f["BDU:2099-00002"]["confidence"] == "подтверждено (фид вендора)"
    assert json.loads(f["BDU:2099-00002"]["details"])["исправлено_в_версии"] == "1.9.5p2-3+deb11u1+astra2"
    # postgresql только в инвентаре, в фиде записи нет -> требует проверки, а не «уязвимо»
    assert f["BDU:2099-00004"]["confidence"] == "требует проверки"
    # ядро обрабатывается отдельно (не deb/rpm) -> остаётся «вероятно»
    assert f["BDU:2099-00003"]["confidence"] == "вероятно"
    # nginx найден и в пакетах, и сетевым сканированием — одна находка, два источника;
    # сетевой сервис независимо подтверждает -> находка не снимается
    assert "сетевой сервис" in f["BDU:2099-00007"]["source"] and "инвентарь" in f["BDU:2099-00007"]["source"]


def test_bdu_only_vulnerability_without_cve(demo):
    _, con = demo
    f = findings(con, "redos-db01")
    assert set(f) == {"BDU:2099-00013"}                     # Postgres Pro; обновлённые openssh/sudo не попали


def test_windows_msrc_by_build(demo):
    _, con = demo
    f = findings(con, "WS-BUH-07")
    assert "BDU:2099-00006" in f                            # CVE-2099-1001 -> БДУ
    assert "CVE-2099-1002" in f and json.loads(f["CVE-2099-1002"]["details"])["нет_в_БДУ"]
    assert "CVE-2099-1003" not in f                         # сборка хоста новее исправления
    assert "CVE-2099-1004" not in f                         # только для Windows Server
    assert {"BDU:2099-00005", "BDU:2099-00012", "BDU:2099-00011"} <= set(f)
    assert len(f["BDU:2099-00011"]["source"].split(",")) == 3   # Tomcat: OpenVAS + ПО + сервис


def test_unparsed_versions_go_to_manual_review(demo):
    _, con = demo
    rows = con.execute("SELECT DISTINCT bdu_id FROM manual_review").fetchall()
    assert {r[0] for r in rows} == {"BDU:2099-00009", "BDU:2099-00010"}
    assert not con.execute("SELECT 1 FROM vuln_finding WHERE bdu_id IN ('BDU:2099-00009','BDU:2099-00010')").fetchall()


def test_config_results(demo):
    _, con = demo
    assert result(con, "astra-app01", "LNX-SSH-01")[0] == "fail"
    assert result(con, "astra-app01", "LNX-ACC-01") == ("fail", '["root", "backup"]')
    assert result(con, "astra-app01", "AST-01")[0] == "pass"            # «ВКЛЮЧЕН» без учёта регистра
    assert result(con, "astra-app01", "AST-02")[0] == "fail"
    assert result(con, "astra-app01", "LNX-PWD-02") == ("fail", "не выполнено условие LNX-PWD-01")
    assert result(con, "redos-db01", "AST-01") is None                   # проверки Astra не применяются к РЕД ОС
    assert con.execute("SELECT COUNT(*) FROM check_result c JOIN asset a ON a.id = c.asset_id "
                       "WHERE a.hostname = 'redos-db01' AND profile = 'base' AND result = 'fail'").fetchone()[0] == 0
    assert result(con, "WS-BUH-07", "WIN-NET-03") == ("fail", "3")      # значение по умолчанию при null
    assert result(con, "WS-BUH-07", "WIN-AV-01")[0] == "pass"
    assert result(con, "core-sw1", "IOS-05") == ("fail", "transport input telnet ssh")


def test_customer_profile_overrides(demo):
    _, con = demo
    assert result(con, "redos-db01", "LNX-PWD-02", "customer-example")[0] == "fail"   # 10 < 12
    assert result(con, "redos-db01", "LNX-PWD-02", "base")[0] == "pass"
    assert result(con, "astra-app01", "LNX-FS-01", "customer-example") is None      # исключена
    title = con.execute("SELECT title FROM check_result WHERE check_id='WIN-PWD-01' AND profile='customer-example'").fetchone()[0]
    assert "12" in title


def test_report_rendered(demo):
    out, _ = demo
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "BDU:2099-00011" in html and "Профиль «customer-example»" in html
    assert "Требуют ручной проверки" in html
    assert (out / "csv" / "vulnerabilities.csv").read_bytes().startswith(b"\xef\xbb\xbf")


def test_all_checks_reference_known_documents():
    checks = load_checks(ROOT / "checks")
    cat = load_catalog(ROOT / "catalog")
    for cid, refs in cat["mapping"].items():
        assert cid in checks, f"в каталоге привязка к несуществующей проверке {cid}"
        for r in refs:
            assert r["doc"] in cat["documents"], r
    for cid, c in checks.items():
        for req in c.get("requires", []):
            assert req in checks, f"{cid} зависит от несуществующей {req}"


@pytest.mark.parametrize("op,actual,value,ok", [
    ("eq", "1", 1, True), ("eq", "Yes", "yes", True), ("ge", "10", 8, True), ("ge", "abc", 8, False),
    ("range", "0", [1, 900], False), ("in", 3, [2, 3], True), ("mode_le", "640", "640", True),
    ("mode_le", "644", "640", False), ("mode_le", "0", "640", True), ("subset_of", ["root"], ["root"], True),
    ("not_contains", [22, 80], [21, 23], True), ("not_contains", [21, 22], [21, 23], False),
    ("regex", "ВКЛЮЧЕН", "^(enabled|включен)", True), ("empty", [], None, True), ("eq", True, True, True),
])
def test_operators(op, actual, value, ok):
    assert evaluate(op, actual, value) is ok


def test_linux_facts_without_root():
    sec = parse_sections("@@@SURVEY:meta@@@\nuid=1000\n@@@SURVEY:shadow_empty@@@\n#noaccess\n"
                         "@@@SURVEY:sshd_config@@@\n# только комментарии\n")
    f = linux_facts(sec)
    assert f["is_root"] is False and f["empty_password_users"] is None   # нет доступа != нет пустых паролей
    assert f["sshd"] == {}                                               # файл есть, действуют умолчания


def test_windows_products():
    assert host_products({"build": "19045", "architecture": "64-разрядная", "product_type": 1}) == \
        ["Windows 10 Version 22H2 for x64-based Systems"]
    assert host_products({"build": "20348", "product_type": 3, "installation_type": "Server Core"}) == \
        ["Windows Server 2022 (Server Core installation)"]
    assert host_products({"build": "12345", "product_type": 1}) == []


def test_secrets_masked_in_report(demo):
    from surveyscan.configcheck import mask_secrets
    assert mask_secrets("enable password cisco123") == "enable password ******"
    assert mask_secrets("enable secret 9 $9$abc") == "enable secret 9 ******"
    assert mask_secrets("snmp-server community S3cr3t RW") == "snmp-server community ****** RW"
    assert mask_secrets("snmp-server community public RO") == "snmp-server community public RO"
    assert mask_secrets("snmp-agent community read cipher %^%#xx") == "snmp-agent community read cipher ******"
    assert "$1a$xyz" not in mask_secrets("local-user admin password irreversible-cipher $1a$xyz")
    assert mask_secrets("service password-encryption") == "service password-encryption"
    out, con = demo
    assert result(con, "core-sw1", "IOS-03") == ("fail", "enable password ******")
    assert "cisco123" not in (out / "report.html").read_text(encoding="utf-8")
