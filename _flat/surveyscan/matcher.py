"""Сопоставление инвентаря и результатов сканеров с БДУ ФСТЭК.

Путь A (через CVE): находки OpenVAS / Trivy / бюллетени Microsoft -> CVE -> BDU.
Путь Б (прямой): ПО и сервисы инвентаря -> названия в БДУ -> диапазоны версий.
Одна уязвимость на одном активе для одного ПО попадает в отчёт один раз; источники склеиваются.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Optional

from .advisories import resolve_distro_release
from .msrc import host_products
from .normalize import Catalog
from .versions import Constraint, dpkg_cmp, numeric_tuple_cmp, rpm_cmp, version_in

CONF_RANK = {"подтверждено (фид вендора)": 4, "подтверждено сканером": 3, "высокая": 3,
             "вероятно": 2, "требует проверки": 1}
SCANNER_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
               "log": "low", "important": "high", "moderate": "medium"}


class _Acc:
    """Накопитель находок со сведением дублей."""

    def __init__(self):
        self.items: dict[tuple, dict] = {}

    def add(self, asset_id, *, bdu_id=None, cve=None, product=None, version=None, software_id=None,
            service_id=None, source, confidence, severity=None, title=None, details=None):
        key = (asset_id, bdu_id) if bdu_id else (asset_id, cve or title, (product or "").lower())
        cur = self.items.get(key)
        if cur is None:
            self.items[key] = dict(asset_id=asset_id, bdu_id=bdu_id, cve=cve, product=product, version=version,
                                   software_id=software_id, service_id=service_id, sources={source},
                                   confidence=confidence, severity=severity, title=title, details=details or {},
                                   products={product} if product and not re.fullmatch(r"\d+/(tcp|udp)", product) else set())
            return
        cur["sources"].add(source)
        if product and not re.fullmatch(r"\d+/(tcp|udp)", product):
            cur["products"].add(product)
        # предпочитаем имя ПО из инвентаря имени порта из сканера
        if product and (not cur["product"] or "/tcp" in cur["product"] or "/udp" in cur["product"]):
            cur["product"], cur["version"] = product, version or cur["version"]
        if CONF_RANK.get(confidence, 0) > CONF_RANK.get(cur["confidence"], 0):
            cur["confidence"] = confidence
        cur["cve"] = cur["cve"] or cve
        cur["details"].update(details or {})


def _bdu_by_cve(con, cve: str) -> list[sqlite3.Row]:
    return con.execute("SELECT v.* FROM bdu.bdu_cve c JOIN bdu.bdu_vuln v ON v.id = c.bdu_id WHERE c.cve = ?",
                       (cve.upper(),)).fetchall()


def _bdu_cves(con, bdu_id: str) -> list[str]:
    return [r[0] for r in con.execute("SELECT cve FROM bdu.bdu_cve WHERE bdu_id = ? ORDER BY cve", (bdu_id,))]


def _ver_cmp(a: str, b: str, eco: str) -> int:
    return rpm_cmp(a, b) if eco == "rpm" else dpkg_cmp(a, b)


def adv_decision(con, distro, release, package, cves, installed, eco, covered) -> tuple[str, Optional[str], Optional[str]]:
    """Сверка с фидом вендора. Возвращает (вердикт, исправленная_версия, ссылка).

    вердикт: 'fixed' (бэкпорт применён — не уязвим), 'vulnerable' (подтверждено вендором),
             'unknown' (релиз в фиде есть, записи нет), 'no_feed' (фид не подключён)."""
    if not distro or not release or (distro, release) not in covered:
        return ("no_feed", None, None)
    if not cves:
        return ("unknown", None, None)
    q = ("SELECT cve, fixed_version, status, url FROM adv.advisory "
         "WHERE distro=? AND release=? AND package=? AND cve IN (%s)" % ",".join("?" * len(cves)))
    rows = con.execute(q, (distro, release, package, *[c.upper() for c in cves])).fetchall()
    if not rows:
        return ("unknown", None, None)
    fixed_hit = None
    for r in rows:
        if r["status"] == "vulnerable":
            return ("vulnerable", None, r["url"])            # вендор подтвердил, фикса нет
        if r["fixed_version"]:
            try:
                cmp = _ver_cmp(installed, r["fixed_version"], eco)
            except Exception:
                continue
            if cmp < 0:
                return ("vulnerable", r["fixed_version"], r["url"])   # установлено старее исправленного
            fixed_hit = (r["fixed_version"], r["url"])        # установлено >= исправленного (бэкпорт)
    if fixed_hit:
        return ("fixed", fixed_hit[0], fixed_hit[1])
    return ("unknown", None, None)


def analyze(con: sqlite3.Connection, catalog: Catalog, msrc_db: Optional[Path] = None,
            adv_db: Optional[Path] = None) -> dict:
    con.execute("DELETE FROM vuln_finding")
    con.execute("DELETE FROM manual_review")
    acc = _Acc()
    stats = defaultdict(int)

    # ------------------------------------------------------------------ фиды вендоров
    from .pgcompat import schema_exists
    adv_covered: set = set()
    if adv_db and schema_exists(con, "adv"):
        adv_covered = {(r[0], r[1]) for r in con.execute("SELECT distro, release FROM adv.adv_release")}

    # ------------------------------------------------------------------ путь A: сканеры
    for f in con.execute("SELECT * FROM scanner_finding").fetchall():
        cves = json.loads(f["cves"] or "[]")
        product = f["title"].split(":")[0] if f["source"] == "trivy" else f["port"]
        if not cves:
            acc.add(f["asset_id"], title=f["title"], product=product, source=f["source"],
                    confidence="подтверждено сканером",
                    severity=SCANNER_SEV.get((f["severity"] or "").lower(), "unknown"))
            stats["scanner_no_cve"] += 1
            continue
        for cve in cves:
            rows = _bdu_by_cve(con, cve)
            if rows:
                for b in rows:
                    acc.add(f["asset_id"], bdu_id=b["id"], cve=cve, product=product, source=f["source"],
                            confidence="подтверждено сканером", severity=b["severity_level"], title=b["name"])
                stats["scanner_bdu"] += 1
            else:
                acc.add(f["asset_id"], cve=cve, product=product, source=f["source"],
                        confidence="подтверждено сканером",
                        severity=SCANNER_SEV.get((f["severity"] or "").lower(), "unknown"),
                        title=f["title"], details={"нет_в_БДУ": True})
                stats["scanner_cve_not_in_bdu"] += 1

    # ------------------------------------------------------------------ путь Б: прямой по БДУ
    soft_cache: dict[str, list[sqlite3.Row]] = {}
    backport_fixed: set = set()   # (asset_id, bdu_id): закрыто бэкпортом по фиду вендора

    def soft_for(names: list[str]) -> list[sqlite3.Row]:
        out = []
        for n in names:
            if n not in soft_cache:
                soft_cache[n] = con.execute(
                    "SELECT s.*, v.severity_level, v.name AS vuln_name FROM bdu.bdu_soft s "
                    "JOIN bdu.bdu_vuln v ON v.id = s.bdu_id WHERE s.name_norm = ?", (n,)).fetchall()
            out.extend(soft_cache[n])
        return out

    def match_item(asset_id, product, version, upstream, names, confidence, source, software_id=None,
                   service_id=None, pkg=None, eco=None, adv=None):
        if not upstream:
            return
        for s in soft_for(names):
            if not s["version_json"]:
                con.execute("INSERT INTO manual_review VALUES (?,?,?,?,?)",
                            (asset_id, product, version, s["bdu_id"], s["version_raw"]))
                stats["manual_review"] += 1
                continue
            constraints = [Constraint(**c) for c in json.loads(s["version_json"])]
            if not version_in(upstream, constraints):
                continue
            conf = confidence
            details = {"диапазон_БДУ": s["version_raw"], "сравнивалась_версия": upstream}
            # сверка с фидом вендора: снимает бэкпорт-ложняки и уточняет рекомендацию
            if adv and pkg and eco in ("deb", "rpm"):
                verdict, fixed, url = adv_decision(con, adv["distro"], adv["release"], pkg,
                                                   _bdu_cves(con, s["bdu_id"]), version, eco, adv_covered)
                if verdict == "fixed":
                    stats["suppressed_backport"] += 1
                    backport_fixed.add((asset_id, s["bdu_id"]))
                    continue                                  # исправление бэкпортнуто — не уязвим
                if verdict == "vulnerable":
                    conf = "подтверждено (фид вендора)"
                    if fixed:
                        details["исправлено_в_версии"] = fixed
                    if url:
                        details["бюллетень"] = url
                elif verdict == "unknown":
                    conf = "требует проверки"
                    details["примечание"] = "нет в фиде вендора — сверить вручную"
                else:  # no_feed
                    details["примечание"] = "фид вендора не подключён — возможен бэкпорт"
            acc.add(asset_id, bdu_id=s["bdu_id"], product=product, version=version, software_id=software_id,
                    service_id=service_id, source=source, confidence=conf,
                    severity=s["severity_level"], title=s["vuln_name"], details=details)
            stats["direct_match"] += 1

    # distro/release актива -> для сверки с фидом вендора (кэш по активу)
    asset_rel: dict[int, tuple] = {}
    for a in con.execute("SELECT id, os_id, os_version FROM asset"):
        asset_rel[a["id"]] = resolve_distro_release(a["os_id"], a["os_version"])

    for sw in con.execute("SELECT * FROM software").fetchall():
        eco = sw["ecosystem"]
        adv = None
        if eco == "win":
            _, names = catalog.for_windows(sw["name"])
            conf = "высокая"
        else:
            _, names = catalog.for_package(sw["name"])
            conf = "вероятно" if eco in ("deb", "rpm", "kernel") else "высокая"
            if eco in ("deb", "rpm") and adv_covered:
                distro, release = asset_rel.get(sw["asset_id"], (None, None))
                adv = {"distro": distro, "release": release}
        match_item(sw["asset_id"], sw["name"], sw["version"], sw["upstream"], names, conf, "БДУ (инвентарь)",
                   software_id=sw["id"], pkg=sw["name"], eco=eco, adv=adv)

    for sv in con.execute("SELECT * FROM service WHERE product IS NOT NULL AND version IS NOT NULL").fetchall():
        _, names = catalog.for_service(sv["product"])
        up = sv["version"].split()[0]
        match_item(sv["asset_id"], f"{sv['product']} ({sv['proto']}/{sv['port']})", sv["version"], up, names,
                   "вероятно", "БДУ (сетевой сервис)", service_id=sv["id"])

    # ------------------------------------------------------------------ Windows: бюллетени Microsoft
    if msrc_db and schema_exists(con, "ms"):
        if True:
            for a in con.execute("SELECT * FROM asset WHERE os_family = 'windows'").fetchall():
                facts = json.loads(a["facts"] or "{}")
                os_info = facts.get("os") or {}
                products = host_products(os_info)
                if not products:
                    stats["windows_unknown_build"] += 1
                    continue
                kbs = {r[0] for r in con.execute("SELECT kb FROM hotfix WHERE asset_id = ?", (a["id"],))}
                host_build = a["os_build"] or ""
                by_cve = defaultdict(list)
                q = f"SELECT * FROM ms.msrc_fix WHERE product IN ({','.join('?' * len(products))})"
                for r in con.execute(q, products).fetchall():
                    by_cve[r["cve"]].append(r)
                for cve, rems in by_cve.items():
                    fixed, kb_list, fixed_builds = False, [], []
                    for r in rems:
                        if r["fixed_build"] and host_build:
                            same_line = r["fixed_build"].split(".")[:3] == host_build.split(".")[:3]
                            if same_line:
                                fixed_builds.append(r["fixed_build"])
                                if numeric_tuple_cmp(host_build, r["fixed_build"]) >= 0:
                                    fixed = True
                        if r["kb"]:
                            kb_list.append(r["kb"])
                            if r["kb"] in kbs:
                                fixed = True
                    if fixed:
                        continue
                    conf = "высокая" if fixed_builds else "вероятно"
                    details = {"сборка_хоста": host_build, "исправлено_в_сборке": sorted(set(fixed_builds)),
                               "KB": sorted(set(kb_list))}
                    bdu_rows = _bdu_by_cve(con, cve)
                    product = os_info.get("caption") or "Windows"
                    if bdu_rows:
                        for b in bdu_rows:
                            acc.add(a["id"], bdu_id=b["id"], cve=cve, product=product, version=host_build,
                                    source="MSRC", confidence=conf, severity=b["severity_level"], title=b["name"],
                                    details=details)
                    else:
                        sev = (rems[0]["severity"] or "").lower()
                        acc.add(a["id"], cve=cve, product=product, version=host_build, source="MSRC",
                                confidence=conf, severity=SCANNER_SEV.get(sev, "unknown"), title=rems[0]["title"],
                                details={**details, "нет_в_БДУ": True})
                    stats["windows_os_vulns"] += 1
        con.commit()

    # авторитетный пакетный вердикт (бэкпорт) перекрывает слабые сигналы по той же (актив, BDU):
    # сетевой сервис и прямое сопоставление по БДУ знают только upstream и о бэкпорте не судят
    _bdu_only = {"БДУ (инвентарь)", "БДУ (сетевой сервис)"}
    for key in backport_fixed:
        it = acc.items.get(key)
        if it and it["sources"] <= _bdu_only:
            acc.items.pop(key, None)
            stats["suppressed_backport_service"] += 1

    # ------------------------------------------------------------------ запись
    for it in acc.items.values():
        if it["bdu_id"]:
            it["details"]["CVE"] = _bdu_cves(con, it["bdu_id"])
        if len(it["products"]) > 1:
            it["details"]["все_затронутые_ПО"] = sorted(it["products"])
        con.execute(
            "INSERT INTO vuln_finding(asset_id,software_id,service_id,bdu_id,cve,product,version,source,"
            "confidence,severity_level,title,details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (it["asset_id"], it["software_id"], it["service_id"], it["bdu_id"], it["cve"], it["product"],
             it["version"], ", ".join(sorted(it["sources"])), it["confidence"], it["severity"] or "unknown",
             it["title"], json.dumps(it["details"], ensure_ascii=False)))
    con.commit()
    stats["findings"] = len(acc.items)
    return dict(stats)
