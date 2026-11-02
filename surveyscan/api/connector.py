"""Протокол коннектора (этап 4).

Коннектор ставится в сети заказчика и всегда дозванивается до центра сам (pull-модель,
исходящий mTLS/HTTPS) — у заказчика не нужно открывать входящие правила. Для полностью
изолированного контура тот же обмен идёт файлами (офлайн-курьер): центр экспортирует
задание бандлом, коннектор собирает офлайн, результат импортируется тем же маршрутом.

Поток:
  центр создаёт connector_job (assigned) → коннектор GET /connector/jobs/next (забирает,
  collecting) → собирает сырьё коллекторами → POST .../result (центр анализирует базами
  знаний центра, создаёт обычную задачу-обследование, job → done).
"""
from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from . import runner, store
from ..pgcompat import open_db

SCHEMA = """
CREATE TABLE IF NOT EXISTS connector (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(), last_seen TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS connector_job (
  id INTEGER PRIMARY KEY,
  connector_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'assigned',
  name TEXT, customer TEXT, template TEXT, targets TEXT,
  task_id INTEGER,
  created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now()
);
"""


def _conn():
    return open_db(store.APP_PATH, schema="public")


def init() -> None:
    con = _conn()
    con.executescript(SCHEMA)
    con.commit()
    con.close()


# ------------------------------------------------------------------ коннекторы

def create_connector(name: str) -> dict:
    token = secrets.token_hex(24)
    con = _conn()
    cur = con.execute("INSERT INTO connector (name, token) VALUES (?, ?) RETURNING id", (name, token))
    cid = cur.fetchone()[0]
    con.commit(); con.close()
    return {"id": cid, "name": name, "token": token}


def connector_by_token(token: str) -> Optional[dict]:
    con = _conn()
    r = con.execute("SELECT id, name FROM connector WHERE token = ?", (token,)).fetchone()
    if r:
        con.execute("UPDATE connector SET last_seen = now() WHERE id = ?", (r["id"],))
        con.commit()
    con.close()
    return {"id": r["id"], "name": r["name"]} if r else None


def list_connectors() -> list[dict]:
    con = _conn()
    rows = con.execute("SELECT id, name, created_at, last_seen FROM connector ORDER BY id").fetchall()
    con.close()
    return [{"id": r["id"], "name": r["name"],
             "created_at": r["created_at"].isoformat() if r["created_at"] else None,
             "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None} for r in rows]


# ------------------------------------------------------------------ задания

def _job_dict(r) -> dict:
    return {"id": r["id"], "connector_id": r["connector_id"], "status": r["status"],
            "name": r["name"], "customer": r["customer"], "template": r["template"],
            "targets": json.loads(r["targets"]) if r["targets"] else None,
            "task_id": r["task_id"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None}


def create_job(connector_id: int, name=None, customer=None, template=None, targets=None) -> dict:
    con = _conn()
    cur = con.execute(
        "INSERT INTO connector_job (connector_id, status, name, customer, template, targets) "
        "VALUES (?, 'assigned', ?, ?, ?, ?) RETURNING id",
        (connector_id, name, customer, template, json.dumps(targets) if targets else None))
    jid = cur.fetchone()[0]
    con.commit()
    r = con.execute("SELECT * FROM connector_job WHERE id = ?", (jid,)).fetchone()
    con.close()
    return _job_dict(r)


def next_job(connector_id: int) -> Optional[dict]:
    con = _conn()
    r = con.execute("SELECT * FROM connector_job WHERE connector_id = ? AND status = 'assigned' "
                    "ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED", (connector_id,)).fetchone()
    if not r:
        con.close()
        return None
    con.execute("UPDATE connector_job SET status = 'collecting', updated_at = now() WHERE id = ?", (r["id"],))
    con.commit()
    con.close()
    d = _job_dict(r)
    d["status"] = "collecting"
    return d


def get_job(job_id: int) -> Optional[dict]:
    con = _conn()
    r = con.execute("SELECT * FROM connector_job WHERE id = ?", (job_id,)).fetchone()
    con.close()
    return _job_dict(r) if r else None


def submit_result(job_id: int, files: dict[str, str], connector_id: int) -> dict:
    """Приём сырья от коннектора: запись файлов, прогон ядра базами центра, создание задачи."""
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "задание не найдено")
    if job["connector_id"] != connector_id:
        raise HTTPException(403, "задание принадлежит другому коннектору")
    con = _conn()
    try:
        claimed = con.execute(
            "UPDATE connector_job SET status='analyzing', updated_at=now() "
            "WHERE id=? AND status IN ('assigned', 'collecting', 'error') RETURNING id", (job_id,)).fetchone()
        con.commit()
    finally:
        con.close()
    if not claimed:
        raise HTTPException(409, "результат уже принят или обрабатывается")
    raw = None
    tid = None
    try:
        raw = Path(tempfile.mkdtemp(prefix="surveyscan-conn-"))
        for fname, content in files.items():
            safe = Path(fname).name                  # без путей — только имя файла
            (raw / safe).write_text(content, encoding="utf-8")
        tid = store.create_task("connector", name=job["name"], customer=job["customer"],
                                params={"template": job["template"], "source": "connector",
                                        "connector_job": job_id})
        store.mark_started(tid)
        result, html, dash = runner.run_pipeline(job["name"], job["customer"],
                                                  {"template": job["template"]}, raw_dir=raw)
        result["source"] = "connector"
        store.mark_done(tid, result, html, dash)
        _set_job_done(job_id, tid)
    except (Exception, SystemExit):
        import traceback
        if tid is not None:
            store.mark_error(tid, traceback.format_exc(limit=6))
        _set_job_status(job_id, "error")
        raise HTTPException(500, "ошибка анализа на центре")
    finally:
        import shutil
        if raw is not None:
            shutil.rmtree(raw, ignore_errors=True)
    return {"job_id": job_id, "task_id": tid, "status": "done"}


def _set_job_done(job_id: int, task_id: int) -> None:
    con = _conn()
    con.execute("UPDATE connector_job SET status='done', task_id=?, updated_at=now() WHERE id=?",
                (task_id, job_id))
    con.commit(); con.close()


def _set_job_status(job_id: int, status: str) -> None:
    con = _conn()
    con.execute("UPDATE connector_job SET status=?, updated_at=now() WHERE id=?", (status, job_id))
    con.commit(); con.close()


# ------------------------------------------------------------------ маршруты

router = APIRouter()


class ConnectorCreate(BaseModel):
    name: str


class JobCreate(BaseModel):
    connector_id: int
    name: Optional[str] = None
    customer: Optional[str] = None
    template: Optional[Literal['full', 'executive', 'vuln', 'config', 'inventory']] = None
    targets: Optional[list] = None


class ResultSubmit(BaseModel):
    files: dict[str, str]                            # имя файла -> текстовое содержимое выгрузки


def _auth(authorization: Optional[str]) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "нужен токен коннектора (Authorization: Bearer …)")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(401, "нужен токен коннектора (Authorization: Bearer …)")
    c = connector_by_token(token)
    if not c:
        raise HTTPException(401, "неизвестный токен коннектора")
    return c


@router.post("/connectors", status_code=201)
def api_create_connector(body: ConnectorCreate) -> dict:
    return create_connector(body.name)              # операторское действие; в проде — админ-роль


@router.get("/connectors")
def api_list_connectors() -> list[dict]:
    return list_connectors()


@router.post("/connector/jobs", status_code=201)
def api_create_job(body: JobCreate) -> dict:
    return create_job(body.connector_id, body.name, body.customer, body.template, body.targets)


@router.get("/connector/jobs/next")
def api_next_job(authorization: Optional[str] = Header(default=None)):
    c = _auth(authorization)
    job = next_job(c["id"])
    if not job:
        from fastapi import Response
        return Response(status_code=204)             # заданий нет
    return job


@router.get("/connector/jobs/{job_id}")
def api_get_job(job_id: int) -> dict:
    j = get_job(job_id)
    if not j:
        raise HTTPException(404, "задание не найдено")
    return j


@router.get("/connector/jobs/{job_id}/bundle")
def api_job_bundle(job_id: int) -> dict:
    """Офлайн-курьер: выгрузка задания бандлом для переноса в изолированный контур."""
    j = get_job(job_id)
    if not j:
        raise HTTPException(404, "задание не найдено")
    return {"bundle": "surveyscan-job", "version": 1, "job": j}


@router.post("/connector/jobs/{job_id}/result")
def api_submit_result(job_id: int, body: ResultSubmit,
                      authorization: Optional[str] = Header(default=None)) -> dict:
    c = _auth(authorization)
    if not body.files:
        raise HTTPException(400, "пустой результат: нет файлов выгрузки")
    return submit_result(job_id, body.files, c["id"])
