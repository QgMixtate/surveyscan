"""Импорт выгрузки БДУ ФСТЭК (vulxml.zip / vulxml.xml) в SQLite.

Файл ~560 МБ, поэтому разбор потоковый (iterparse) с очисткой обработанных узлов.
Структура записи <vul>: identifier, name (в части выгрузок — n), description,
vulnerable_software/soft(vendor, name, version, platform, types/type),
cvss/vector@score, cvss3/vector@score, severity, solution, vul_status,
exploit_status, fix_status, identifiers/identifier[@type='CVE'], даты.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import sqlite3
import zipfile
from pathlib import Path
from typing import Iterator, Optional

from lxml import etree

from .normalize import norm_name
from .versions import parse_bdu_versions

SCHEMA = """
CREATE TABLE IF NOT EXISTS bdu_meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS bdu_vuln (
  id TEXT PRIMARY KEY, name TEXT, description TEXT,
  severity_level TEXT, severity_text TEXT,
  cvss2_score REAL, cvss2_vector TEXT, cvss3_score REAL, cvss3_vector TEXT,
  solution TEXT, vul_status TEXT, exploit_status TEXT, fix_status TEXT,
  identify_date TEXT, publication_date TEXT, last_upd_date TEXT
);
CREATE TABLE IF NOT EXISTS bdu_cve (cve TEXT, bdu_id TEXT);
CREATE TABLE IF NOT EXISTS bdu_soft (
  bdu_id TEXT, vendor TEXT, name TEXT, name_norm TEXT,
  version_raw TEXT, version_json TEXT, platform TEXT, types TEXT
);
"""
INDEXES = """
CREATE INDEX IF NOT EXISTS ix_bdu_cve ON bdu_cve(cve);
CREATE INDEX IF NOT EXISTS ix_bdu_cve_id ON bdu_cve(bdu_id);
CREATE INDEX IF NOT EXISTS ix_bdu_soft_name ON bdu_soft(name_norm);
CREATE INDEX IF NOT EXISTS ix_bdu_soft_id ON bdu_soft(bdu_id);
"""

SEVERITY_LEVELS = [("критич", "critical"), ("высок", "high"), ("средн", "medium"), ("низк", "low")]


def severity_level(text: Optional[str]) -> str:
    t = (text or "").strip().lower()
    for prefix, level in SEVERITY_LEVELS:
        if t.startswith(prefix):
            return level
    return "unknown"


def _t(el, *tags) -> Optional[str]:
    for tag in tags:
        x = el.find(tag)
        if x is not None and x.text and x.text.strip():
            return x.text.strip()
    return None


def _vector(el, tag):
    v = el.find(f"{tag}/vector")
    if v is None:
        return None, None
    score = v.get("score")
    try:
        score = float(score.replace(",", ".")) if score else None
    except ValueError:
        score = None
    return score, (v.text or "").strip() or None


def _open_xml(path: Path):
    if zipfile.is_zipfile(path):
        zf = zipfile.ZipFile(path)
        name = next(n for n in zf.namelist() if n.lower().endswith(".xml"))
        return zf.open(name)
    return open(path, "rb")


def iter_records(path: Path) -> Iterator[dict]:
    with _open_xml(path) as fh:
        for _, el in etree.iterparse(fh, events=("end",), tag="vul", huge_tree=True, recover=True):
            rec = {
                "id": _t(el, "identifier"),
                "name": _t(el, "name", "n"),
                "description": _t(el, "description"),
                "severity_text": _t(el, "severity"),
                "solution": _t(el, "solution"),
                "vul_status": _t(el, "vul_status"),
                "exploit_status": _t(el, "exploit_status"),
                "fix_status": _t(el, "fix_status"),
                "identify_date": _t(el, "identify_date"),
                "publication_date": _t(el, "publication_date"),
                "last_upd_date": _t(el, "last_upd_date"),
                "soft": [],
                "cves": [],
            }
            rec["cvss2_score"], rec["cvss2_vector"] = _vector(el, "cvss")
            rec["cvss3_score"], rec["cvss3_vector"] = _vector(el, "cvss3")
            rec["severity_level"] = severity_level(rec["severity_text"])
            for s in el.iterfind("vulnerable_software/soft"):
                types = [t.text.strip() for t in s.iterfind("types/type") if t.text]
                rec["soft"].append({
                    "vendor": _t(s, "vendor"),
                    "name": _t(s, "name", "n"),
                    "version": _t(s, "version"),
                    "platform": _t(s, "platform"),
                    "types": ", ".join(types) or None,
                })
            for ident in el.iterfind("identifiers/identifier"):
                if (ident.get("type") or "").upper() == "CVE" and ident.text:
                    rec["cves"].append(ident.text.strip().upper())
            # освобождаем память
            el.clear()
            while el.getprevious() is not None:
                del el.getparent()[0]
            if rec["id"]:
                yield rec


def import_bdu(src: Path, db_path: Path, progress=None) -> dict:
    from .pgcompat import open_db
    con = open_db(Path(db_path), schema="bdu", recreate=True)
    con.executescript(SCHEMA)
    con.commit()
    n_vul = n_soft = n_cve = n_unparsed = 0
    batch_v, batch_s, batch_c = [], [], []

    def flush():
        con.executemany("INSERT OR REPLACE INTO bdu_vuln VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch_v)
        con.executemany("INSERT INTO bdu_soft VALUES (?,?,?,?,?,?,?,?)", batch_s)
        con.executemany("INSERT INTO bdu_cve VALUES (?,?)", batch_c)
        batch_v.clear(); batch_s.clear(); batch_c.clear()

    for rec in iter_records(src):
        n_vul += 1
        batch_v.append((rec["id"], rec["name"], rec["description"], rec["severity_level"], rec["severity_text"],
                        rec["cvss2_score"], rec["cvss2_vector"], rec["cvss3_score"], rec["cvss3_vector"],
                        rec["solution"], rec["vul_status"], rec["exploit_status"], rec["fix_status"],
                        rec["identify_date"], rec["publication_date"], rec["last_upd_date"]))
        for s in rec["soft"]:
            parsed = parse_bdu_versions(s["version"])
            if parsed is None:
                n_unparsed += 1
            batch_s.append((rec["id"], s["vendor"], s["name"], norm_name(s["name"] or ""), s["version"],
                            json.dumps([c.to_dict() for c in parsed], ensure_ascii=False) if parsed else None,
                            s["platform"], s["types"]))
            n_soft += 1
        for cve in rec["cves"]:
            batch_c.append((cve, rec["id"]))
            n_cve += 1
        if len(batch_v) >= 2000:
            flush()
            if progress:
                progress(n_vul)
    flush()
    con.executescript(INDEXES)
    stamp = dt.datetime.fromtimestamp(src.stat().st_mtime).isoformat(timespec="seconds")
    meta = {
        "source_file": src.name,
        "source_mtime": stamp,
        "imported_at": dt.datetime.now().isoformat(timespec="seconds"),
        "records": str(n_vul), "soft_entries": str(n_soft), "cve_links": str(n_cve),
        "unparsed_versions": str(n_unparsed),
    }
    con.executemany("INSERT OR REPLACE INTO bdu_meta VALUES (?,?)", list(meta.items()))
    con.commit()
    con.close()
    return meta


def bdu_version_label(con: sqlite3.Connection, schema: str = "bdu") -> str:
    rows = dict(con.execute(f"SELECT key, value FROM {schema}.bdu_meta").fetchall())
    return f"{rows.get('source_file', '?')} от {rows.get('source_mtime', '?')} ({rows.get('records', '?')} записей)"
