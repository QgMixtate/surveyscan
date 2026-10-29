"""Хранилище задач в прикладной БД PostgreSQL.

Таблица task — журнал заданий бэкенда: что запущено, в каком статусе, результат.
Используется и API, и исполнителем. Каждая операция открывает своё соединение,
поэтому store безопасен при вызове из потоков исполнителя.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from ..pgcompat import open_db

# Прикладная БД выводится из каталога-метки (стабильное имя между запусками).
APP_PATH = Path(os.environ.get("SURVEYSCAN_APP_DIR", "/tmp/surveyscan_app")) / "app"

SCHEMA = """
CREATE TABLE IF NOT EXISTS task (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  name TEXT,
  customer TEXT,
  params TEXT,
  result TEXT,
  report_html TEXT,
  dashboard TEXT,
  progress TEXT,
  error TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS credential (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,              -- ssh | winrm | snmp
  username TEXT,
  domain TEXT,
  port INTEGER,
  secret_enc TEXT,                 -- пароль/ключ/community в зашифрованном виде (Fernet)
  created_at TIMESTAMPTZ DEFAULT now()
);
"""


def _conn():
    con = open_db(APP_PATH, schema="public")
    return con


def init() -> None:
    con = _conn()
    con.executescript(SCHEMA)
    con.execute("ALTER TABLE task ADD COLUMN IF NOT EXISTS dashboard TEXT")   # миграция старых БД
    con.execute("ALTER TABLE task ADD COLUMN IF NOT EXISTS progress TEXT")
    con.commit()
    con.close()


# ------------------------------------------------------------------ учётные записи (хранилище УЗ)
def create_credential(name: str, type: str, username: Optional[str], domain: Optional[str],
                      port: Optional[int], secret_enc: Optional[str]) -> int:
    con = _conn()
    cur = con.execute(
        "INSERT INTO credential (name, type, username, domain, port, secret_enc) "
        "VALUES (?,?,?,?,?,?) RETURNING id", (name, type, username, domain, port, secret_enc))
    cid = cur.fetchone()[0]
    con.commit()
    con.close()
    return cid


def list_credentials() -> list[dict]:
    """Список УЗ БЕЗ секретов — для UI/выбора."""
    con = _conn()
    rows = con.execute("SELECT id,name,type,username,domain,port,created_at FROM credential ORDER BY id").fetchall()
    con.close()
    return [{"id": r["id"], "name": r["name"], "type": r["type"], "username": r["username"],
             "domain": r["domain"], "port": r["port"],
             "created_at": r["created_at"].isoformat() if r["created_at"] else None} for r in rows]


def get_credentials_enc(ids: list[int]) -> list[dict]:
    """Выбранные УЗ ВМЕСТЕ с зашифрованным секретом — для исполнителя (расшифровка в app)."""
    if not ids:
        return []
    con = _conn()
    ph = ",".join("?" * len(ids))
    rows = con.execute(f"SELECT id,name,type,username,domain,port,secret_enc FROM credential "
                       f"WHERE id IN ({ph}) ORDER BY id", tuple(ids)).fetchall()
    con.close()
    return [{"id": r["id"], "name": r["name"], "type": r["type"], "username": r["username"],
             "domain": r["domain"], "port": r["port"], "secret_enc": r["secret_enc"]} for r in rows]


def delete_credential(cred_id: int) -> bool:
    con = _conn()
    row = con.execute("DELETE FROM credential WHERE id=? RETURNING id", (cred_id,)).fetchone()
    con.commit()
    con.close()
    return row is not None


def _row_to_dict(r, with_html: bool = False, with_dashboard: bool = False, with_progress: bool = False) -> dict:
    d = {
        "id": r["id"], "kind": r["kind"], "status": r["status"],
        "name": r["name"], "customer": r["customer"],
        "params": json.loads(r["params"]) if r["params"] else None,
        "result": json.loads(r["result"]) if r["result"] else None,
        "error": r["error"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        "started_at": r["started_at"].isoformat() if r["started_at"] else None,
        "finished_at": r["finished_at"].isoformat() if r["finished_at"] else None,
        "has_report": bool(r["report_html"]),
    }
    if with_html:
        d["report_html"] = r["report_html"]
    if with_dashboard:
        d["dashboard"] = json.loads(r["dashboard"]) if r["dashboard"] else None
    if with_progress:
        d["progress"] = json.loads(r["progress"]) if r["progress"] else []
    return d


def create_task(kind: str, name: Optional[str] = None, customer: Optional[str] = None,
                params: Optional[dict] = None) -> int:
    con = _conn()
    cur = con.execute(
        "INSERT INTO task (kind, status, name, customer, params) VALUES (?, 'queued', ?, ?, ?) RETURNING id",
        (kind, name, customer, json.dumps(params or {}, ensure_ascii=False)))
    tid = cur.fetchone()[0]
    con.commit()
    con.close()
    return tid


def mark_started(task_id: int) -> None:
    con = _conn()
    con.execute("UPDATE task SET status='running', started_at=now() WHERE id=?", (task_id,))
    con.commit()
    con.close()


def mark_done(task_id: int, result: dict, report_html: Optional[str],
              dashboard: Optional[dict] = None) -> None:
    con = _conn()
    con.execute("UPDATE task SET status='done', result=?, report_html=?, dashboard=?, finished_at=now() WHERE id=?",
                (json.dumps(result, ensure_ascii=False), report_html,
                 json.dumps(dashboard, ensure_ascii=False) if dashboard else None, task_id))
    con.commit()
    con.close()


def mark_error(task_id: int, error: str) -> None:
    con = _conn()
    con.execute("UPDATE task SET status='error', error=?, finished_at=now() WHERE id=?", (error, task_id))
    con.commit()
    con.close()


def mark_cancelled(task_id: int) -> None:
    con = _conn()
    con.execute("UPDATE task SET status='cancelled', finished_at=now() WHERE id=?", (task_id,))
    con.commit()
    con.close()


def append_progress(task_id: int, line: str, cap: int = 400) -> None:
    """Добавить строку в журнал прогресса задачи (для показа в UI без докер-логов)."""
    con = _conn()
    r = con.execute("SELECT progress FROM task WHERE id=?", (task_id,)).fetchone()
    if r is None:
        con.close()
        return
    lst = json.loads(r["progress"]) if r["progress"] else []
    import datetime as _dt
    lst.append({"t": _dt.datetime.now().strftime("%H:%M:%S"), "m": line})
    lst = lst[-cap:]
    con.execute("UPDATE task SET progress=? WHERE id=?", (json.dumps(lst, ensure_ascii=False), task_id))
    con.commit()
    con.close()


def task_status(task_id: int) -> Optional[str]:
    con = _conn()
    r = con.execute("SELECT status FROM task WHERE id=?", (task_id,)).fetchone()
    con.close()
    return r["status"] if r else None


def get_task(task_id: int, with_html: bool = False, with_dashboard: bool = False,
             with_progress: bool = False) -> Optional[dict]:
    con = _conn()
    r = con.execute("SELECT * FROM task WHERE id=?", (task_id,)).fetchone()
    con.close()
    return _row_to_dict(r, with_html, with_dashboard, with_progress) if r else None


def get_report_html(task_id: int) -> Optional[str]:
    con = _conn()
    r = con.execute("SELECT report_html FROM task WHERE id=?", (task_id,)).fetchone()
    con.close()
    return r["report_html"] if r else None


def list_tasks(limit: int = 50) -> list[dict]:
    con = _conn()
    rows = con.execute("SELECT * FROM task ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [_row_to_dict(r) for r in rows]
