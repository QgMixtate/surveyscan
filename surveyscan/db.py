"""База обследования (SQLite в прототипе; в целевой системе — PostgreSQL с той же схемой)."""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS survey (
  id INTEGER PRIMARY KEY, name TEXT, customer TEXT, created_at TEXT, bdu_version TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS asset (
  id INTEGER PRIMARY KEY, kind TEXT, hostname TEXT, fqdn TEXT, ips TEXT,
  os_family TEXT, os_id TEXT, os_version TEXT, os_pretty TEXT, os_build TEXT, kernel TEXT,
  platform TEXT, role TEXT, exposure TEXT, source TEXT, collected_at TEXT, facts TEXT
);
CREATE TABLE IF NOT EXISTS software (
  id INTEGER PRIMARY KEY, asset_id INTEGER, name TEXT, version TEXT, upstream TEXT,
  ecosystem TEXT, vendor TEXT, arch TEXT
);
CREATE INDEX IF NOT EXISTS ix_software_asset ON software(asset_id);
CREATE TABLE IF NOT EXISTS service (
  id INTEGER PRIMARY KEY, asset_id INTEGER, proto TEXT, port INTEGER, name TEXT,
  product TEXT, version TEXT, extrainfo TEXT, cpe TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS hotfix (asset_id INTEGER, kb TEXT);
CREATE TABLE IF NOT EXISTS scanner_finding (
  id INTEGER PRIMARY KEY, asset_id INTEGER, source TEXT, port TEXT, title TEXT,
  cves TEXT, severity TEXT, score REAL, details TEXT
);
CREATE TABLE IF NOT EXISTS vuln_finding (
  id INTEGER PRIMARY KEY, asset_id INTEGER, software_id INTEGER, service_id INTEGER,
  bdu_id TEXT, cve TEXT, product TEXT, version TEXT, source TEXT, confidence TEXT,
  severity_level TEXT, title TEXT, details TEXT, status TEXT DEFAULT 'open', comment TEXT
);
CREATE TABLE IF NOT EXISTS manual_review (
  asset_id INTEGER, product TEXT, version TEXT, bdu_id TEXT, version_raw TEXT
);
CREATE TABLE IF NOT EXISTS check_result (
  id INTEGER PRIMARY KEY, asset_id INTEGER, profile TEXT, check_id TEXT, title TEXT,
  result TEXT, actual TEXT, expected TEXT, severity TEXT, remediation TEXT, refs TEXT
);
CREATE TABLE IF NOT EXISTS raw_artifact (
  id INTEGER PRIMARY KEY, asset_id INTEGER, kind TEXT, path TEXT, sha256 TEXT, loaded_at TEXT
);
"""


def connect(survey_db: Path, bdu_db: Optional[Path] = None):
    from .pgcompat import open_db, schema_exists
    con = open_db(Path(survey_db), schema="public")
    con.executescript(SCHEMA)
    con.commit()
    if con.execute("SELECT COUNT(*) FROM survey").fetchone()[0] == 0:
        con.execute("INSERT INTO survey(name, created_at) VALUES (?, ?)",
                    (Path(survey_db).stem, dt.datetime.now().isoformat(timespec="seconds")))
        con.commit()
    if bdu_db is not None and not schema_exists(con, "bdu"):
        raise SystemExit("База БДУ не найдена. Сначала выполните bdu-import.")
    return con


def find_or_create_asset(con: sqlite3.Connection, *, hostname: str = None, ips: list[str] = None,
                         kind: str = "host", **fields) -> int:
    ips = [ip for ip in (ips or []) if ip and not ip.startswith(("127.", "::1", "fe80"))]
    # совпадение по имени хоста или по любому IP
    for row in con.execute("SELECT id, hostname, ips FROM asset"):
        known_ips = set(json.loads(row["ips"] or "[]"))
        if (hostname and row["hostname"] and hostname.lower() == row["hostname"].lower()) or known_ips & set(ips):
            merged = sorted(known_ips | set(ips))
            sets = {"ips": json.dumps(merged)}
            # имя от коллектора (есть os_family) приоритетнее имени из DNS/сканера
            if hostname and (not row["hostname"] or fields.get("os_family")):
                sets["hostname"] = hostname
            for k, v in fields.items():
                if v is not None:
                    sets[k] = v
            con.execute(f"UPDATE asset SET {', '.join(f'{k}=?' for k in sets)} WHERE id=?",
                        (*sets.values(), row["id"]))
            return row["id"]
    cols = {"kind": kind, "hostname": hostname, "ips": json.dumps(sorted(set(ips)))}
    cols.update({k: v for k, v in fields.items() if v is not None})
    cur = con.execute(f"INSERT INTO asset ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) RETURNING id",
                      tuple(cols.values()))
    return cur.fetchone()[0]


def apply_role_guess(con, asset_id: int) -> None:
    """Базовая роль после импорта; уже заданную оператором роль не переопределяем.

    Специализированные роли АСУ ТП/СЗИ требуют подтверждения оператором.
    """
    con.execute(
        "UPDATE asset SET role=CASE WHEN kind='netdev' OR kind LIKE ? THEN 'netdev' ELSE 'it' END "
        "WHERE id=? AND (role IS NULL OR role='')", ('%сетев%', asset_id))
