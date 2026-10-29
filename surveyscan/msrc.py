"""Бюллетени Microsoft (MSRC CVRF v3) -> таблица «продукт, CVE, KB, исправленная сборка».

Онлайн: msrc-sync --months 2026-Sep 2026-Oct (нужен доступ к api.msrc.microsoft.com).
Офлайн: msrc-sync --file 2026-Oct.json (документ CVRF, скачанный заранее) — для закрытых контуров.
"""
from __future__ import annotations

import json
import re
import sqlite3
import urllib.request
from pathlib import Path
from typing import Iterable

API = "https://api.msrc.microsoft.com/cvrf/v3.0"

SCHEMA = """
CREATE TABLE IF NOT EXISTS msrc_fix (
  doc_id TEXT, product TEXT, cve TEXT, kb TEXT, fixed_build TEXT, severity TEXT, title TEXT
);
CREATE INDEX IF NOT EXISTS ix_msrc_product ON msrc_fix(product);
CREATE TABLE IF NOT EXISTS msrc_doc (doc_id TEXT PRIMARY KEY, loaded_at TEXT);
"""


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


def _products(tree: dict) -> dict[str, str]:
    out = {}

    def walk(node):
        if isinstance(node, dict):
            for fp in node.get("FullProductName") or []:
                out[str(fp.get("ProductID"))] = fp.get("Value")
            for b in node.get("Branch") or []:
                walk(b)
            for it in node.get("Items") or []:
                if isinstance(it, dict) and "ProductID" in it and "Value" in it:
                    out[str(it["ProductID"])] = it["Value"]
                walk(it)
        elif isinstance(node, list):
            for x in node:
                walk(x)

    walk(tree)
    return out


def parse_cvrf(doc: dict) -> list[tuple]:
    doc_id = (doc.get("DocumentTracking") or {}).get("Identification", {}).get("ID", {}).get("Value") \
        or doc.get("DocumentTitle", {}).get("Value", "?")
    products = _products(doc.get("ProductTree") or {})
    rows = []
    for v in doc.get("Vulnerability") or []:
        cve = v.get("CVE")
        title = (v.get("Title") or {}).get("Value")
        sev_by_pid = {}
        for t in v.get("Threats") or []:
            if t.get("Type") == 3:                       # Severity
                for pid in t.get("ProductID") or []:
                    sev_by_pid[str(pid)] = (t.get("Description") or {}).get("Value")
        for rem in v.get("Remediations") or []:
            if rem.get("Type") != 2:                     # Vendor Fix
                continue
            kb = re.sub(r"\D", "", str((rem.get("Description") or {}).get("Value") or ""))
            for pid in rem.get("ProductID") or []:
                name = products.get(str(pid))
                if name:
                    rows.append((doc_id, name, cve, kb or None, rem.get("FixedBuild"), sev_by_pid.get(str(pid)), title))
    return rows


def sync(db_path: Path, months: Iterable[str] = (), files: Iterable[Path] = ()) -> int:
    from .pgcompat import open_db
    con = open_db(Path(db_path), schema="ms", recreate=True)
    con.executescript(SCHEMA)
    con.commit()
    total = 0
    docs = []
    for f in files:
        docs.append(json.loads(Path(f).read_text(encoding="utf-8-sig")))
    if months:
        index = {d["ID"]: d["CvrfUrl"] for d in _get_json(f"{API}/updates").get("value", [])}
        for m in months:
            if m not in index:
                raise SystemExit(f"Нет бюллетеня {m}. Доступно, например: {', '.join(list(index)[-3:])}")
            docs.append(_get_json(index[m]))
    for doc in docs:
        rows = parse_cvrf(doc)
        if not rows:
            continue
        con.execute("DELETE FROM msrc_fix WHERE doc_id=?", (rows[0][0],))
        con.executemany("INSERT INTO msrc_fix VALUES (?,?,?,?,?,?,?)", rows)
        con.execute("INSERT OR REPLACE INTO msrc_doc VALUES (?, datetime('now'))", (rows[0][0],))
        total += len(rows)
    con.commit()
    con.close()
    return total


# --------------------------------------------------------------------------- сопоставление хоста
CLIENT = {10240: "Windows 10 for", 14393: "Windows 10 Version 1607 for", 17763: "Windows 10 Version 1809 for",
          19044: "Windows 10 Version 21H2 for", 19045: "Windows 10 Version 22H2 for", 22000: "Windows 11 for",
          22621: "Windows 11 Version 22H2 for", 22631: "Windows 11 Version 23H2 for",
          26100: "Windows 11 Version 24H2 for", 26200: "Windows 11 Version 25H2 for"}
SERVER = {9600: "Windows Server 2012 R2", 14393: "Windows Server 2016", 17763: "Windows Server 2019",
          20348: "Windows Server 2022", 25398: "Windows Server 2022, 23H2 Edition", 26100: "Windows Server 2025"}


def host_products(os_info: dict) -> list[str]:
    try:
        build = int(os_info.get("build") or 0)
    except ValueError:
        return []
    arch = (os_info.get("architecture") or "").lower()
    arch_s = "ARM64-based Systems" if "arm" in arch else ("x64-based Systems" if "64" in arch else "32-bit Systems")
    is_server = int(os_info.get("product_type") or 1) != 1 or "server" in (os_info.get("caption") or "").lower()
    if is_server:
        base = SERVER.get(build)
        if not base:
            return []
        core = (os_info.get("installation_type") or "").lower() == "server core"
        return [base + " (Server Core installation)"] if core else [base]
    prefix = CLIENT.get(build)
    return [f"{prefix} {arch_s}"] if prefix else []
