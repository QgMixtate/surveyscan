"""Шаблоны отчётов: выбор секций и фильтры (кастомные отчёты)."""
import sqlite3

import pytest

from surveyscan.cli import ROOT, main
from surveyscan.report import collect
from surveyscan.reporttpl import load_template, sev_allowed


@pytest.fixture(scope="module")
def con(tmp_path_factory):
    out = tmp_path_factory.mktemp("rt")
    main(["demo", "--out", str(out)])
    from surveyscan.pgcompat import open_db
    return open_db(out / "survey.sqlite", schema="public")


def test_default_is_full():
    tpl = load_template(None, ROOT / "reports")
    assert tpl["id"] == "full"
    assert all(tpl["has"][s] for s in ("summary", "vuln_details", "config", "sources"))


def test_builtin_executive_sections():
    tpl = load_template("executive", ROOT / "reports")
    assert tpl["has"]["summary"] and tpl["has"]["remediation"] and tpl["has"]["config"]
    assert not tpl["has"]["vuln_details"] and not tpl["has"]["inventory"]
    assert tpl["filters"]["min_severity"] == "high"


def test_min_severity_filters_vulns(con):
    full = collect(con, ROOT / "catalog", load_template("full", ROOT / "reports"))
    execu = collect(con, ROOT / "catalog", load_template("executive", ROOT / "reports"))
    assert full["sev_counts"].get("medium")                      # в полном есть средние
    assert "medium" not in execu["sev_counts"]                   # executive отсекает ниже high
    assert all(v["severity"] in ("critical", "high") for v in execu["vulns"])
    assert len(execu["vulns"]) < len(full["vulns"])


def test_host_filter(con):
    tpl = load_template(None, ROOT / "reports")
    tpl["filters"]["hosts"] = ["astra-app01"]
    data = collect(con, ROOT / "catalog", tpl)
    assert [a["name"] for a in data["assets"]] == ["astra-app01"]
    assert all(v["assets"] == ["astra-app01"] for v in data["vulns"])


def test_config_template_hides_vulns():
    tpl = load_template("config", ROOT / "reports")
    assert tpl["has"]["config"] and not tpl["has"]["vuln_table"] and not tpl["has"]["remediation"]


def test_unknown_section_rejected(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("sections: [summary, nonsense]\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        load_template(str(p))


def test_sev_allowed():
    assert sev_allowed("critical", "high") and sev_allowed("high", "high")
    assert not sev_allowed("medium", "high") and not sev_allowed("low", "high")
    assert sev_allowed("low", None)                              # без порога — всё проходит
