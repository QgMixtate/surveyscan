"""Формирование отчёта об обследовании (HTML) и выгрузка находок (CSV).

Отчёт собирается по шаблону (surveyscan.reporttpl): шаблон выбирает секции и
фильтрует находки. collect() всегда считает все агрегаты; шаблон решает, что
показать, а фильтры сужают множество находок до отрисовки.
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import math
import sqlite3
from collections import defaultdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .bdu import bdu_version_label
from .configcheck import load_catalog, mask_secrets
from .reporttpl import load_template, sev_allowed

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
SEV_SEQ = ["critical", "high", "medium", "low", "unknown"]
SEV_RU = {"critical": "Критический", "high": "Высокий", "medium": "Средний", "low": "Низкий", "unknown": "Не определён"}
SEV_HEX = {"critical": "#8e1b1b", "high": "#b4441c", "medium": "#c07d10", "low": "#2e6b3f", "unknown": "#8a94a6"}
KIND_RU = {"host": "Хост", "netdev": "Сетевое устройство", "image": "Образ / ФС"}

_DONUT_R = 52.0
_DONUT_C = 2 * math.pi * _DONUT_R


def _asset_label(a) -> str:
    ips = json.loads(a["ips"] or "[]")
    return a["hostname"] or (ips[0] if ips else f"актив {a['id']}")


def _build_inventory(a, facts: dict, software: list[dict], hotfixes: list[str]) -> dict:
    """Полная инвентаризация актива для карточки в UI — из facts коллектора (SSH/WinRM/SNMP)."""
    fam = a["os_family"] or ""
    inv: dict = {"software": software, "collection_status": dict(facts.get("collection_status") or {})}
    if fam == "linux":
        statuses = inv["collection_status"]
        if "ip_addr" in statuses or "ip_link" in statuses:
            states = [statuses.get(k, "unknown") for k in ("ip_addr", "ip_link")]
            statuses["nics"] = "ok" if all(s == "ok" for s in states) else "unavailable"
    # Команда может успеть вернуть часть строк до ошибки. Их сохраняем с пометкой.
    for key, status in list(inv["collection_status"].items()):
        if status == "unavailable" and facts.get(key):
            inv["collection_status"][key] = "partial"
    if fam == "windows":
        osd = facts.get("os") or {}
        hotfixes_sorted = sorted(hotfixes, key=lambda k: (-int(k) if k.isdigit() else 0, k))
        inv.update({
            "hotfixes": hotfixes_sorted,
            "domain": osd.get("domain"), "part_of_domain": osd.get("part_of_domain"),
            "last_boot": osd.get("last_boot"), "architecture": osd.get("architecture"),
            "installation_type": osd.get("installation_type"),
            "is_admin": facts.get("is_admin"),
            "users": facts.get("users") or [],
            "admins": facts.get("admins") or [],
            "groups": facts.get("groups") or [],
            "services": facts.get("services") or [],
            "firewall": facts.get("firewall") or {},
            "antivirus": facts.get("antivirus") or [],
            "defender": facts.get("defender"),
            "listening": facts.get("listening") or [],
            "connections": facts.get("connections") or [],
            "nics": facts.get("nics") or [],
            "routes": facts.get("routes") or [],
            "disks": facts.get("disks") or [],
            "shares": facts.get("shares") or [],
            "usb_devices": facts.get("usb_devices") or [],
        })
    elif fam == "linux":
        inv.update({
            "login_users": facts.get("login_users") or [],
            "uid0_users": facts.get("uid0_users") or [],
            "sudo_nopasswd": facts.get("sudo_nopasswd"),
            "empty_password_users": facts.get("empty_password_users"),
            "sshd": facts.get("sshd"),
            "mounts": facts.get("mounts") or {},
            "listening": facts.get("listening") or [],
            "connections": facts.get("connections") or [],
            "nics": facts.get("nics") or [],
            "routes": facts.get("routes") or [],
            "dns": facts.get("dns") or [],
            "services_active": facts.get("services_active") or {},
            "services_enabled": facts.get("services_enabled") or [],
            "audit_rules": len(facts.get("audit_rules") or []),
            "is_root": facts.get("is_root"),
        })
    elif fam == "netdev" or a["kind"] == "netdev":
        inv["config"] = mask_secrets(facts.get("config") or "")
        inv["interfaces"] = facts.get("interfaces") or []
        inv["neighbors"] = facts.get("neighbors") or []
    return inv


def make_donut(pairs: list[tuple[str, str, int]]) -> dict | None:
    """pairs: [(label, hex-color, count)] -> данные для SVG-кольца."""
    total = sum(c for _, _, c in pairs)
    if not total:
        return None
    segs, off = [], 0.0
    for label, color, count in pairs:
        if not count:
            continue
        frac = count / total
        segs.append({"label": label, "color": color, "count": count,
                     "pct": round(100 * frac, 1),
                     "dash": round(frac * _DONUT_C, 2),
                     "gap": round((1 - frac) * _DONUT_C, 2),
                     "offset": round(-off * _DONUT_C, 2)})
        off += frac
    return {"total": total, "r": _DONUT_R, "c": round(_DONUT_C, 2), "segments": segs}


def collect(con: sqlite3.Connection, catalog_dir: Path, tpl: dict) -> dict:
    f = tpl["filters"]
    host_filter = set(f["hosts"]) if f.get("hosts") else None
    conf_filter = set(f["confidence"]) if f.get("confidence") else None
    prof_filter = set(f["profiles"]) if f.get("profiles") else None
    min_sev = f.get("min_severity")

    assets_all = con.execute("SELECT * FROM asset ORDER BY kind, hostname").fetchall()
    label = {a["id"]: _asset_label(a) for a in assets_all}
    assets = [a for a in assets_all if host_filter is None or label[a["id"]] in host_filter]
    allowed_ids = {a["id"] for a in assets}

    sw_count = dict(con.execute("SELECT asset_id, COUNT(*) FROM software GROUP BY asset_id").fetchall())
    sw_list = defaultdict(list)
    for s in con.execute("SELECT asset_id, name, version, vendor, ecosystem FROM software ORDER BY name"):
        sw_list[s["asset_id"]].append({"name": s["name"], "version": s["version"] or "",
                                       "vendor": s["vendor"], "ecosystem": s["ecosystem"]})
    hotfix_list = defaultdict(list)
    for h in con.execute("SELECT asset_id, kb FROM hotfix ORDER BY kb"):
        hotfix_list[h["asset_id"]].append(h["kb"])
    svc = defaultdict(list)
    for s in con.execute("SELECT * FROM service ORDER BY port"):
        if s["asset_id"] in allowed_ids:
            svc[s["asset_id"]].append(f"{s['port']}/{s['proto']} {s['product'] or s['name'] or ''} {s['version'] or ''}".strip())
    asset_rows, asset_by_name = [], {}
    for a in assets:
        facts = json.loads(a["facts"] or "{}")
        sec_tools = []
        if a["os_family"] == "windows":
            sec_tools = [x.get("name") for x in facts.get("antivirus") or [] if x.get("name")]
        elif a["os_family"] == "linux":
            act = facts.get("services_active") or {}
            sec_tools = [n for n, v in act.items() if v == "active" and n in ("kesl", "klnagent", "drweb-configd")]
        netdev_ifaces = facts.get("interfaces") or []
        netdev_vlans = sorted({v for i in netdev_ifaces
                               for v in ([i["vlan"]] if i.get("vlan") else []) + (i.get("allowed_vlans") or [])})
        row = {
            "id": a["id"], "name": label[a["id"]], "kind": KIND_RU.get(a["kind"], a["kind"]),
            "os_family": a["os_family"] or "", "ips": ", ".join(json.loads(a["ips"] or "[]")),
            "os": a["os_pretty"] or " ".join(x for x in (a["os_id"], a["os_version"]) if x) or "—",
            "build": a["os_build"] or a["kernel"] or "", "software": sw_count.get(a["id"], 0),
            "services": svc.get(a["id"], []), "source": a["source"] or "", "sec_tools": sec_tools,
            "role": a["role"] or "", "collected_at": a["collected_at"] or "",
            "partial": a["os_family"] == "linux" and facts.get("is_root") is False,
            "inventory": _build_inventory(a, facts, sw_list.get(a["id"], []), hotfix_list.get(a["id"], [])),
            # для построения схемы сети из конфигов (surveyscan.topology): VLAN/interfaces на
            # узле устройства + потенциальные L2-соседи из description интерфейсов.
            "interfaces": netdev_ifaces, "vlans": netdev_vlans, "neighbors": facts.get("neighbors") or [],
        }
        asset_rows.append(row)
        asset_by_name[row["name"]] = row

    # ---------------------------------------------------------------- уязвимости
    from .pgcompat import schema_exists
    has_bdu = schema_exists(con, "bdu")
    bdu_label = bdu_version_label(con) if has_bdu else "БДУ не подключена"

    groups: dict[tuple, dict] = {}
    for v in con.execute("SELECT * FROM vuln_finding").fetchall():
        if v["asset_id"] not in allowed_ids:
            continue
        if conf_filter is not None and v["confidence"] not in conf_filter:
            continue
        key = (v["bdu_id"] or v["cve"] or v["title"], v["product"])
        g = groups.get(key)
        if g is None:
            sol = desc = fix = expl = c3v = c2v = None
            c3s = c2s = None
            if v["bdu_id"] and has_bdu:
                b = con.execute("SELECT description, solution, fix_status, exploit_status, "
                                "cvss3_score, cvss3_vector, cvss2_score, cvss2_vector "
                                "FROM bdu.bdu_vuln WHERE id = ?", (v["bdu_id"],)).fetchone()
                if b:
                    desc, sol, fix, expl = b["description"], b["solution"], b["fix_status"], b["exploit_status"]
                    c3s, c3v, c2s, c2v = b["cvss3_score"], b["cvss3_vector"], b["cvss2_score"], b["cvss2_vector"]
            det = json.loads(v["details"] or "{}")
            score = c3s if c3s is not None else c2s
            vector = c3v if c3s is not None else c2v
            g = groups[key] = {
                "bdu_id": v["bdu_id"], "cve": det.get("CVE") or ([v["cve"]] if v["cve"] else []),
                "title": v["title"], "product": v["product"], "versions": set(), "severity": v["severity_level"],
                "assets": [], "confidence": v["confidence"], "sources": set(),
                "description": desc, "solution": sol, "fix_status": fix, "exploit_status": expl,
                "cvss_score": score, "cvss_vector": vector, "cvss3_score": c3s, "cvss2_score": c2s,
                "range": det.get("диапазон_БДУ"), "not_in_bdu": det.get("нет_в_БДУ", False),
                "all_products": det.get("все_затронутые_ПО", []),
                "vendor_fix": det.get("исправлено_в_версии"), "bulletin": det.get("бюллетень"),
                "note": det.get("примечание"),
            }
        g["assets"].append(label.get(v["asset_id"], "?"))
        if v["version"]:
            g["versions"].add(v["version"])
        g["sources"].update(x.strip() for x in (v["source"] or "").split(","))

    vulns = [g for g in groups.values() if sev_allowed(g["severity"], min_sev)]
    vulns.sort(key=lambda g: (SEV_ORDER.get(g["severity"], 9), -len(set(g["assets"])), g["bdu_id"] or ""))
    for g in vulns:
        g["assets"] = sorted(set(g["assets"]))
        g["versions"] = sorted(g["versions"])
        g["sources"] = sorted(g["sources"])
        g["anchor"] = (g["bdu_id"] or (g["cve"][0] if g["cve"] else g["title"]) or "v").replace(":", "-").replace(" ", "-")

    sev_counts = defaultdict(int)
    for g in vulns:
        sev_counts[g["severity"]] += 1
    hosts_with_crit = len({a for g in vulns if g["severity"] in ("critical", "high") for a in g["assets"]})
    vuln_donut = make_donut([(SEV_RU[s], SEV_HEX[s], sev_counts.get(s, 0)) for s in SEV_SEQ])

    # ------- матрица по хостам: сколько уязвимостей каждой опасности на хосте
    host_mx = {r["name"]: {s: 0 for s in SEV_SEQ} for r in asset_rows}
    for g in vulns:
        for name in g["assets"]:
            if name in host_mx:
                host_mx[name][g["severity"]] += 1
    by_host = []
    for r in asset_rows:
        row = {"name": r["name"], **host_mx[r["name"]], "total": sum(host_mx[r["name"]].values())}
        by_host.append(row)
    by_host.sort(key=lambda x: (-x["critical"], -x["high"], -x["total"], x["name"]))

    # ------- матрица по продуктам
    prod_mx: dict[str, dict] = {}
    for g in vulns:
        p = g["product"] or "—"
        d = prod_mx.setdefault(p, {s: 0 for s in SEV_SEQ})
        d[g["severity"]] += 1
    by_product = sorted(
        ({"product": p, **d, "total": sum(d.values())} for p, d in prod_mx.items()),
        key=lambda x: (-x["critical"], -x["high"], -x["total"], x["product"]))

    # ------- план устранения: приоритизированные действия
    rem: dict[str, dict] = {}
    for g in vulns:
        p = g["product"] or "—"
        a = rem.get(p)
        if a is None:
            a = rem[p] = {"product": p, "severity": g["severity"], "hosts": set(), "n_vulns": 0,
                          "targets": set(), "bulletin": None, "bdu": [], "actions": set(), "feed": False}
        if SEV_ORDER.get(g["severity"], 9) < SEV_ORDER.get(a["severity"], 9):
            a["severity"] = g["severity"]
        a["hosts"].update(g["assets"])
        a["n_vulns"] += 1
        if g["bdu_id"]:
            a["bdu"].append(g["bdu_id"])
        if g["vendor_fix"]:
            a["targets"].add(g["vendor_fix"])
            a["feed"] = True
            a["bulletin"] = a["bulletin"] or g["bulletin"]
        if "подтверждено (фид вендора)" in g["confidence"]:
            a["feed"] = True
    remediation = []
    for a in rem.values():
        if a["targets"]:
            act = f"Обновить {a['product']} до версии " + ", ".join(sorted(a["targets"]))
        else:
            act = f"Проверить и обновить {a['product']} (см. рекомендации БДУ в карточках)"
        remediation.append({**a, "hosts": sorted(a["hosts"]), "n_hosts": len(a["hosts"]),
                            "bdu": sorted(set(a["bdu"]))[:6], "targets": sorted(a["targets"]),
                            "actions": sorted(a["actions"]), "action": act})
    remediation.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), -x["n_hosts"], -x["n_vulns"], x["product"]))

    # ------- детальные карточки уязвимостей (для секции vuln_details)
    vuln_cards = []
    for g in vulns:
        refs = []
        if g["bdu_id"]:
            refs.append(("БДУ ФСТЭК", g["bdu_id"], f"https://bdu.fstec.ru/vul/{g['bdu_id'].replace('BDU:', '')}"))
        for c in g["cve"]:
            refs.append(("CVE", c, f"https://nvd.nist.gov/vuln/detail/{c}"))
        if g["bulletin"]:
            refs.append(("Бюллетень вендора", "ссылка", g["bulletin"]))
        vuln_cards.append({**g, "refs_list": refs})

    # ---------------------------------------------------------------- конфигурации
    catalog = load_catalog(catalog_dir)
    profiles = []
    for (pid,) in con.execute("SELECT DISTINCT profile FROM check_result ORDER BY profile"):
        if prof_filter is not None and pid not in prof_filter:
            continue
        rows = [r for r in con.execute("SELECT * FROM check_result WHERE profile = ?", (pid,)).fetchall()
                if r["asset_id"] in allowed_ids]
        if not rows:
            continue
        doc_keys = []
        for r in rows:
            for ref in json.loads(r["refs"] or "[]"):
                if ref["doc"] not in doc_keys:
                    doc_keys.append(ref["doc"])
        order = list(catalog["documents"].keys())
        doc_keys.sort(key=lambda d: order.index(d) if d in order else 99)
        by_check: dict[str, dict] = {}
        per_asset = defaultdict(lambda: {"pass": 0, "fail": 0, "na": 0, "error": 0})
        for r in rows:
            per_asset[r["asset_id"]][r["result"]] += 1
            c = by_check.setdefault(r["check_id"], {
                "id": r["check_id"], "title": r["title"], "severity": r["severity"], "remediation": r["remediation"],
                "expected": r["expected"], "fails": [], "passes": 0, "na": 0, "refs": defaultdict(list)})
            for ref in json.loads(r["refs"] or "[]"):
                if ref.get("item") and ref["item"] not in c["refs"][ref["doc"]]:
                    c["refs"][ref["doc"]].append(ref["item"])
            if r["result"] in ("fail", "error"):
                c["fails"].append({"asset": label.get(r["asset_id"], "?"), "actual": r["actual"], "error": r["result"] == "error"})
            elif r["result"] == "pass":
                c["passes"] += 1
            else:
                c["na"] += 1
        failed = sorted([c for c in by_check.values() if c["fails"]],
                        key=lambda c: (SEV_ORDER.get(c["severity"], 9), -len(c["fails"]), c["id"]))
        assets_cmp = []
        for aid, st in per_asset.items():
            total = st["pass"] + st["fail"]
            assets_cmp.append({"name": label.get(aid, "?"), "pass": st["pass"], "fail": st["fail"], "na": st["na"],
                               "pct": round(100 * st["pass"] / total) if total else None})
        assets_cmp.sort(key=lambda x: (x["pct"] if x["pct"] is not None else 101))
        tot_p = sum(x["pass"] for x in assets_cmp)
        tot_f = sum(x["fail"] for x in assets_cmp)
        fail_by_sev = defaultdict(int)
        for c in failed:
            fail_by_sev[c["severity"]] += 1
        profiles.append({
            "id": pid, "checks": len(by_check), "failed": failed, "assets": assets_cmp,
            "pct": round(100 * tot_p / (tot_p + tot_f)) if tot_p + tot_f else None,
            "docs": [{"key": d, **catalog["documents"].get(d, {"short": d, "title": d})} for d in doc_keys],
            "passed_checks": sorted(c["id"] for c in by_check.values() if not c["fails"] and c["passes"]),
            "donut": make_donut([("Соответствует", "#2e6b3f", tot_p), ("Не соответствует", "#8e1b1b", tot_f)]),
            "fail_by_sev": dict(fail_by_sev),
        })

    # ------- разбивка по хостам (секция by_host): уязвимости + конфиг на каждом хосте
    host_sections = []
    for r in asset_rows:
        hv = [g for g in vulns if r["name"] in g["assets"]]
        n_v = sum(host_mx[r["name"]].values())
        hcfg = [{"profile": p["id"], **x} for p in profiles for x in p["assets"] if x["name"] == r["name"]]
        if not hv and n_v == 0 and not any(c["fail"] for c in hcfg):
            continue
        host_sections.append({
            "asset": r, "sev": {s: host_mx[r["name"]][s] for s in SEV_SEQ},
            "n_vulns": n_v,
            "vulns": sorted(hv, key=lambda g: (SEV_ORDER.get(g["severity"], 9), g["bdu_id"] or "")),
            "config": hcfg,
        })

    # ---------------------------------------------------------------- приложения
    manual = con.execute(
        "SELECT product, COUNT(DISTINCT bdu_id) AS n, COUNT(DISTINCT asset_id) AS hosts, "
        "GROUP_CONCAT(DISTINCT version_raw) AS samples FROM manual_review "
        "WHERE asset_id IN (%s) GROUP BY product ORDER BY n DESC" %
        (",".join("?" * len(allowed_ids)) or "NULL"), tuple(allowed_ids)).fetchall() if allowed_ids else []
    manual = [{"product": m["product"], "n": m["n"], "hosts": m["hosts"],
               "samples": "; ".join((m["samples"] or "").split(",")[:3])} for m in manual]
    artifacts = [{"asset": label.get(r["asset_id"], "—") if r["asset_id"] else "—", "kind": r["kind"],
                  "file": Path(r["path"]).name, "sha256": r["sha256"][:16], "loaded": r["loaded_at"]}
                 for r in con.execute("SELECT * FROM raw_artifact ORDER BY loaded_at")
                 if r["asset_id"] is None or r["asset_id"] in allowed_ids]
    survey = con.execute("SELECT * FROM survey LIMIT 1").fetchone()
    kinds = defaultdict(int)
    for a in asset_rows:
        kinds[a["kind"]] += 1
    cfg_tot_p = sum(x["pass"] for p in profiles for x in p["assets"])
    cfg_tot_f = sum(x["fail"] for p in profiles for x in p["assets"])
    return {
        "tpl": tpl, "survey": dict(survey), "generated": dt.datetime.now().strftime("%d.%m.%Y %H:%M"),
        "bdu_label": bdu_label, "assets": asset_rows, "asset_kinds": dict(kinds),
        "vulns": vulns, "vuln_cards": vuln_cards, "sev_counts": dict(sev_counts),
        "hosts_with_crit": hosts_with_crit, "vuln_donut": vuln_donut,
        "by_host": by_host, "by_product": by_product, "remediation": remediation,
        "host_sections": host_sections,
        "profiles": profiles, "manual": manual, "manual_total": sum(m["n"] for m in manual),
        "artifacts": artifacts, "SEV_RU": SEV_RU, "SEV_HEX": SEV_HEX, "SEV_SEQ": SEV_SEQ,
        "cfg_compliance": round(100 * cfg_tot_p / (cfg_tot_p + cfg_tot_f)) if cfg_tot_p + cfg_tot_f else None,
    }


def render_html_with_data(con, catalog_dir: Path, out: Path,
                          template: str | None = None, reports_dir: Path | None = None):
    """Отрисовать HTML-отчёт и вернуть (путь, структурные данные collect)."""
    tpl = load_template(template, reports_dir)
    env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                      autoescape=select_autoescape(["html", "j2"]), trim_blocks=True, lstrip_blocks=True)
    data = collect(con, catalog_dir, tpl)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(env.get_template("report.html.j2").render(**data), encoding="utf-8")
    return out, data


def render_html(con, catalog_dir: Path, out: Path,
                template: str | None = None, reports_dir: Path | None = None) -> Path:
    return render_html_with_data(con, catalog_dir, out, template, reports_dir)[0]


def dashboard_json(data: dict) -> dict:
    """Структурные данные для нативного дашборда/вкладок UI (JSON-safe срез collect)."""
    sev = data["sev_counts"]
    totals = {
        "assets": len(data["assets"]),
        "vulns": len(data["vulns"]),
        "critical": sev.get("critical", 0),
        "high": sev.get("high", 0),
        "crit_high": sev.get("critical", 0) + sev.get("high", 0),
        "hosts_with_crit": data["hosts_with_crit"],
        "manual": data["manual_total"],
        "cfg_compliance": data["cfg_compliance"],
    }
    # топ активов по риску (взвешенная сумма находок)
    w = {"critical": 10, "high": 5, "medium": 2, "low": 1, "unknown": 1}
    os_by_name = {a["name"]: a for a in data["assets"]}
    top = []
    for r in data["by_host"]:
        score = sum(r[s] * w[s] for s in SEV_SEQ)
        a = os_by_name.get(r["name"], {})
        top.append({"name": r["name"], "os": a.get("os", "—"), "ips": a.get("ips", ""),
                    "critical": r["critical"], "high": r["high"], "total": r["total"], "score": score})
    top.sort(key=lambda x: -x["score"])
    return {
        "survey": data["survey"], "generated": data["generated"], "bdu_label": data["bdu_label"],
        "asset_kinds": data["asset_kinds"], "totals": totals,
        "sev_counts": sev, "vuln_donut": data["vuln_donut"],
        "top_assets": top[:6], "assets": data["assets"],
        "vulns": data["vuln_cards"], "by_product": data["by_product"],
        "remediation": data["remediation"], "profiles": data["profiles"], "manual": data["manual"],
    }


def export_csv(con: sqlite3.Connection, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = []
    q = {
        "vulnerabilities.csv": "SELECT a.hostname, a.ips, f.bdu_id, f.cve, f.title, f.product, f.version, "
                               "f.severity_level, f.confidence, f.source, f.status FROM vuln_finding f "
                               "JOIN asset a ON a.id = f.asset_id ORDER BY a.hostname",
        "config_checks.csv": "SELECT a.hostname, c.profile, c.check_id, c.title, c.result, c.expected, c.actual, "
                             "c.severity, c.refs FROM check_result c JOIN asset a ON a.id = c.asset_id "
                             "ORDER BY a.hostname, c.check_id",
        "inventory_software.csv": "SELECT a.hostname, s.name, s.version, s.vendor, s.ecosystem FROM software s "
                                  "JOIN asset a ON a.id = s.asset_id ORDER BY a.hostname, s.name",
    }
    for name, sql in q.items():
        cur = con.execute(sql)
        p = out_dir / name
        with open(p, "w", newline="", encoding="utf-8-sig") as fh:   # BOM — чтобы Excel открыл кириллицу
            w = csv.writer(fh, delimiter=";")
            w.writerow([d[0] for d in cur.description])
            w.writerows(cur.fetchall())
        files.append(p)
    return files
