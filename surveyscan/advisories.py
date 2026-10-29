"""Фиды безопасности вендоров дистрибутивов: CVE -> исправленная версия ПАКЕТА в конкретном релизе.

Решает проблему бэкпортов: вендор закрывает уязвимость, не меняя upstream-версию
(openssh 8.9p1 остаётся 8.9p1, фикс уезжает в ревизию -3ubuntu0.10). Поэтому вердикт и
рекомендацию нужно строить по версии ПАКЕТА против версии из фида вендора, а не по upstream из БДУ.

Нормализованная таблица advisory(distro, release, package, cve, fixed_version, status, advisory_id, url).
status: 'fixed' (есть fixed_version), 'vulnerable' (вендор подтвердил, фикса нет), 'not_affected'.

Загрузчики:
  load_ubuntu_oval(path)  — Ubuntu OVAL (com.ubuntu.<release>.pkg.oval.xml[.bz2])
  load_debian_json(path)  — Debian security-tracker (data/json)
  load_normalized(path)   — простой JSONL для Astra/РЕД ОС, пока нет их машиночитаемых фидов
"""
from __future__ import annotations

import bz2
import json
import re
import sqlite3
from pathlib import Path
from typing import Iterator, Optional

from lxml import etree

SCHEMA = """
CREATE TABLE IF NOT EXISTS adv_meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS advisory (
  distro TEXT, release TEXT, package TEXT, cve TEXT,
  fixed_version TEXT, status TEXT, advisory_id TEXT, url TEXT
);
CREATE INDEX IF NOT EXISTS ix_adv ON advisory(distro, release, package);
CREATE INDEX IF NOT EXISTS ix_adv_cve ON advisory(distro, release, package, cve);
CREATE TABLE IF NOT EXISTS adv_release (distro TEXT, release TEXT, PRIMARY KEY (distro, release));
"""

# Сопоставление ОС актива -> (distro, release) фида вендора.
# Astra/РЕД ОС/Альт — приближение по базовому дистрибутиву; уточняется при подключении их фидов.
_UBUNTU = {"24.04": "noble", "22.04": "jammy", "20.04": "focal", "18.04": "bionic",
           "24.10": "oracular", "23.10": "mantic"}
_DEBIAN = {"13": "trixie", "12": "bookworm", "11": "bullseye", "10": "buster"}
def resolve_distro_release(os_id: str, os_version: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """ОС актива -> (distro, release) фида вендора. Astra/РЕД ОС используют собственные бюллетени."""
    os_id = (os_id or "").lower()
    v = (os_version or "").strip()
    if os_id == "ubuntu":
        return ("ubuntu", _UBUNTU.get(v.split()[0] if v else "", ""))  # '' release -> нет фида
    if os_id in ("debian",):
        return ("debian", _DEBIAN.get(v.split(".")[0], ""))
    if os_id.startswith("astra"):
        return ("astra", v[:3])            # 1.7 / 1.8 — ключ бюллетеней Astra
    if os_id in ("redos",):
        return ("redos", v.rsplit(".", 1)[0] if v else "")   # напр. 7.3
    if os_id in ("altlinux", "alt"):
        # ветки Альт: p10 / p11 — определяется точнее по данным репозитория
        return ("alt", "p10")
    return (None, None)


# --------------------------------------------------------------------------- запись
def _open(path: Path):
    return bz2.open(path, "rb") if str(path).endswith(".bz2") else open(path, "rb")


class Writer:
    def __init__(self, con: sqlite3.Connection):
        self.con = con
        self.batch: list[tuple] = []
        self.n = 0

    def add(self, distro, release, package, cve, fixed_version, status, advisory_id=None, url=None):
        self.batch.append((distro, release, package, cve, fixed_version, status, advisory_id, url))
        self.n += 1
        if len(self.batch) >= 2000:
            self.flush()

    def flush(self):
        self.con.executemany("INSERT INTO advisory VALUES (?,?,?,?,?,?,?,?)", self.batch)
        self.batch.clear()


# --------------------------------------------------------------------------- Ubuntu OVAL
_LN = re.compile(r"\{.*\}")


def _ln(tag) -> str:
    return _LN.sub("", tag) if isinstance(tag, str) else ""


def load_ubuntu_oval(path: Path, con: sqlite3.Connection) -> int:
    """Разбор Ubuntu OVAL: definition(CVE) -> criterion test_ref -> dpkginfo test -> (пакет, fixed EVR)."""
    with _open(path) as fh:
        tree = etree.parse(fh)
    root = tree.getroot()
    # release из заголовка (<generator><oval:product_version> или из имени файла)
    release = ""
    m = re.search(r"com\.ubuntu\.([a-z]+)\.", path.name)
    if m:
        release = m.group(1)

    objects, states, tests = {}, {}, {}
    for el in root.iter():
        ln = _ln(el.tag)
        if ln == "dpkginfo_object":
            name = next((c.text for c in el if _ln(c.tag) == "name" and c.text), None)
            if name:
                objects[el.get("id")] = name.strip()
        elif ln == "dpkginfo_state":
            evr = next((c for c in el if _ln(c.tag) == "evr"), None)
            if evr is not None and evr.text:
                states[el.get("id")] = (evr.get("operation") or "", evr.text.strip())
        elif ln == "dpkginfo_test":
            obj = state = None
            for c in el:
                lc = _ln(c.tag)
                if lc == "object":
                    obj = c.get("object_ref")
                elif lc == "state":
                    state = c.get("state_ref")
            tests[el.get("id")] = (obj, state)

    w = Writer(con)
    releases = set()
    for d in root.iter():
        if _ln(d.tag) != "definition" or d.get("class") != "vulnerability":
            continue
        cves, adv_url, rel = [], None, release
        for meta in d.iter():
            lm = _ln(meta.tag)
            if lm == "reference" and (meta.get("source") or "").upper() == "CVE":
                cves.append(meta.get("ref_id"))
                adv_url = adv_url or meta.get("ref_url")
            elif lm == "platform" and meta.text and "Ubuntu" in meta.text:
                rm = re.search(r"Ubuntu\s+([\d.]+)", meta.text)
                if rm:
                    rel = _UBUNTU.get(rm.group(1), rel)
        if not cves:
            continue
        # все test_ref внутри definition -> (пакет, fixed version) где операция «less than»
        for crit in d.iter():
            if _ln(crit.tag) != "criterion":
                continue
            tref = crit.get("test_ref")
            obj, state = tests.get(tref, (None, None))
            pkg = objects.get(obj)
            op_evr = states.get(state)
            if not pkg or not op_evr:
                continue
            op, evr = op_evr
            if "less than" in op:
                for cve in cves:
                    w.add("ubuntu", rel, pkg, cve, evr, "fixed", d.get("id"), adv_url)
                releases.add(rel)
    w.flush()
    for r in releases:
        con.execute("INSERT OR IGNORE INTO adv_release VALUES ('ubuntu', ?)", (r,))
    con.commit()
    return w.n


# --------------------------------------------------------------------------- Debian security-tracker JSON
def load_debian_json(path: Path, con: sqlite3.Connection) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    w = Writer(con)
    releases = set()
    for pkg, cves in data.items():
        if not isinstance(cves, dict):
            continue                       # служебные ключи (_comment и т.п.)
        for cve, info in cves.items():
            if not isinstance(info, dict):
                continue
            for rel, r in (info.get("releases") or {}).items():
                fixed = r.get("fixed_version")
                status = r.get("status", "")
                if fixed and fixed != "0":
                    w.add("debian", rel, pkg, cve, fixed, "fixed",
                          r.get("nodsa") or None, f"https://security-tracker.debian.org/tracker/{cve}")
                elif status == "open":
                    w.add("debian", rel, pkg, cve, None, "vulnerable", None,
                          f"https://security-tracker.debian.org/tracker/{cve}")
                else:
                    continue
                releases.add(rel)
    w.flush()
    for r in releases:
        con.execute("INSERT OR IGNORE INTO adv_release VALUES ('debian', ?)", (r,))
    con.commit()
    return w.n


# --------------------------------------------------------------------------- Нормализованный JSONL
def load_normalized(path: Path, con: sqlite3.Connection) -> int:
    w = Writer(con)
    releases = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        r = json.loads(line)
        w.add(r["distro"], r.get("release", ""), r["package"], r["cve"].upper(),
              r.get("fixed_version"), r.get("status", "fixed" if r.get("fixed_version") else "vulnerable"),
              r.get("advisory_id"), r.get("url"))
        releases.add((r["distro"], r.get("release", "")))
    w.flush()
    for distro, rel in releases:
        con.execute("INSERT OR IGNORE INTO adv_release VALUES (?, ?)", (distro, rel))
    con.commit()
    return w.n


def init_db(db_path: Path):
    from .pgcompat import open_db
    con = open_db(Path(db_path), schema="adv", recreate=True)
    con.executescript(SCHEMA)
    con.commit()
    return con


def import_feeds(db_path: Path, ubuntu_oval=(), debian_json=(), normalized=()) -> dict:
    con = init_db(db_path)
    counts = {}
    for p in ubuntu_oval:
        counts[f"ubuntu:{Path(p).name}"] = load_ubuntu_oval(Path(p), con)
    for p in debian_json:
        counts[f"debian:{Path(p).name}"] = load_debian_json(Path(p), con)
    for p in normalized:
        counts[f"normalized:{Path(p).name}"] = load_normalized(Path(p), con)
    con.execute("INSERT OR REPLACE INTO adv_meta VALUES ('imported_at', datetime('now'))")
    con.commit()
    con.close()
    return counts
