"""FastAPI-бэкенд surveyscan (этап 2, вертикальный срез).

Поток: POST /tasks создаёт задание и ставит его в очередь → исполнитель прогоняет
пайплайн ядра → GET /tasks/{id} показывает статус и сводку → GET /tasks/{id}/report
отдаёт HTML-отчёт. Аутентификация/RBAC/мультиарендность — следующие этапы.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import connector, runner, secretbox, store

STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init()
    connector.init()
    yield


app = FastAPI(title="surveyscan API", version="0.3.0",
              description="Бэкенд обследования: задачи сканирования, отчёты и веб-интерфейс.",
              lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.include_router(connector.router, tags=["connector"])


KINDS = {"demo", "inventory", "vuln", "config"}   # профили сканирования, разведённые на бэкенде


CRED_TYPES = {"ssh", "winrm", "snmp"}


class Cred(BaseModel):
    type: str                          # ssh | winrm | snmp
    username: Optional[str] = None     # логин (ssh/winrm); для snmp не используется
    secret: Optional[str] = None       # пароль (ssh/winrm) или community (snmp)
    key: Optional[str] = None          # приватный ключ (ssh), альтернатива паролю
    domain: Optional[str] = None       # домен (winrm)
    port: Optional[int] = None         # нестандартный порт


class TaskCreate(BaseModel):
    kind: str = "demo"                 # demo | inventory | vuln | config
    name: Optional[str] = None
    customer: Optional[str] = None
    targets: Optional[str] = None      # подсети/хосты для реального скана (nmap), напр. "10.0.0.0/24, host1"
    snmp_community: Optional[str] = None  # ярлык: SNMP community -> добавляется как УЗ типа snmp
    cred_ids: Optional[list[int]] = None  # выбранные УЗ из хранилища (расшифровываются на сервере)
    creds: Optional[list[Cred]] = None    # разовые УЗ (для API/тестов); UI использует cred_ids
    template: Optional[str] = None     # шаблон отчёта: full|executive|vuln|config|inventory
    run: str = "async"                 # async (очередь) | sync (дождаться результата)


class CredentialCreate(BaseModel):
    name: str                          # человекочитаемое имя: «Linux-аудит», «Домен WIN»
    type: str                          # ssh | winrm | snmp
    username: Optional[str] = None
    secret: Optional[str] = None       # пароль / community / приватный ключ (ssh)
    domain: Optional[str] = None
    port: Optional[int] = None


@app.get("/credentials")
def list_credentials() -> list[dict]:
    return store.list_credentials()


@app.post("/credentials", status_code=201)
def create_credential(body: CredentialCreate) -> dict:
    if body.type not in CRED_TYPES:
        raise HTTPException(400, f"неизвестный тип УЗ: {body.type}")
    if not body.name.strip():
        raise HTTPException(400, "укажите имя УЗ")
    if body.type in ("ssh", "winrm") and not body.username:
        raise HTTPException(400, f"для УЗ {body.type} нужен логин")
    if not body.secret:
        raise HTTPException(400, "укажите секрет (пароль / community / ключ)")
    enc = secretbox.encrypt(body.secret)
    cid = store.create_credential(body.name.strip(), body.type, body.username,
                                  body.domain, body.port, enc)
    return {"id": cid, **{k: v for k, v in body.model_dump().items() if k != "secret"}}


@app.delete("/credentials/{cred_id}", status_code=204)
def delete_credential(cred_id: int) -> None:
    if not store.delete_credential(cred_id):
        raise HTTPException(404, "УЗ не найдена")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/tasks", status_code=201)
def create_task(body: TaskCreate) -> dict:
    if body.kind not in KINDS:
        raise HTTPException(400, f"неизвестный вид задачи: {body.kind}")
    if body.kind != "demo" and not (body.targets and body.targets.strip()):
        raise HTTPException(400, "укажите цели сканирования (подсети/хосты), напр. 10.0.0.0/24")
    try:
        runner.parse_targets(body.targets)        # ранняя валидация целей
    except ValueError as e:
        raise HTTPException(400, str(e))

    # набор УЗ: из хранилища (cred_ids, расшифровка) + ярлык snmp_community + разовые creds
    creds: list[dict] = []
    if body.cred_ids:
        found = {r["id"]: r for r in store.get_credentials_enc(body.cred_ids)}
        missing = [i for i in body.cred_ids if i not in found]
        if missing:
            raise HTTPException(400, f"УЗ не найдены: {missing}")
        for cid in body.cred_ids:
            r = found[cid]
            sec = secretbox.decrypt(r["secret_enc"]) if r["secret_enc"] else ""
            c = {"type": r["type"], "username": r["username"], "domain": r["domain"],
                 "port": r["port"], "name": r["name"]}
            if r["type"] == "ssh" and "PRIVATE KEY" in sec:    # хранимый приватный ключ
                c["key"] = sec
            else:
                c["secret"] = sec
            creds.append(c)
    if body.snmp_community and body.snmp_community.strip():
        creds.append({"type": "snmp", "secret": body.snmp_community.strip()})
    for c in body.creds or []:
        if c.type not in CRED_TYPES:
            raise HTTPException(400, f"неизвестный тип УЗ: {c.type}")
        if c.type in ("ssh", "winrm") and not c.username:
            raise HTTPException(400, f"для УЗ {c.type} нужен логин")
        if c.type in ("ssh", "winrm") and not (c.secret or c.key):
            raise HTTPException(400, f"для УЗ {c.type} нужен пароль или ключ")
        if c.type == "snmp" and not c.secret:
            raise HTTPException(400, "для УЗ snmp нужен community")
        creds.append(c.model_dump())

    # в params кладём обезличенную сводку по УЗ (без секретов) — для отображения/аудита
    safe = [{"type": c["type"], "name": c.get("name"), "username": c.get("username"),
             "domain": c.get("domain"), "port": c.get("port"),
             "has_secret": bool(c.get("secret") or c.get("key"))} for c in creds]
    tid = store.create_task(body.kind, name=body.name, customer=body.customer,
                            params={"template": body.template, "kind": body.kind, "targets": body.targets,
                                    "creds": safe})
    if creds:
        runner.put_secrets(tid, creds)            # секреты — только в память процесса

    if body.run == "sync":
        runner.run_sync(tid)
    else:
        runner.submit(tid)
    return store.get_task(tid)


@app.get("/tasks")
def list_tasks(limit: int = 50) -> list[dict]:
    return store.list_tasks(limit)


@app.get("/tasks/{task_id}")
def get_task(task_id: int) -> dict:
    t = store.get_task(task_id, with_dashboard=True, with_progress=True)
    if not t:
        raise HTTPException(404, "задача не найдена")
    return t


@app.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: int) -> dict:
    t = store.get_task(task_id)
    if not t:
        raise HTTPException(404, "задача не найдена")
    if t["status"] not in ("queued", "running"):
        raise HTTPException(409, f"задачу нельзя отменить в статусе «{t['status']}»")
    runner.cancel(task_id)
    return {"status": "cancelling", "id": task_id}


def _topology_of(task_id: int) -> dict:
    t = store.get_task(task_id, with_dashboard=True)
    if not t:
        raise HTTPException(404, "задача не найдена")
    topo = (t.get("dashboard") or {}).get("topology")
    if not topo:
        raise HTTPException(409, f"схема сети ещё не готова (статус: {t['status']})")
    return topo


@app.get("/tasks/{task_id}/topology")
def get_topology(task_id: int) -> dict:
    return _topology_of(task_id)


@app.get("/tasks/{task_id}/topology.svg")
def get_topology_svg(task_id: int) -> Response:
    from ..topology import to_svg
    return Response(content=to_svg(_topology_of(task_id)), media_type="image/svg+xml")


@app.get("/tasks/{task_id}/report", response_class=HTMLResponse)
def get_report(task_id: int) -> HTMLResponse:
    t = store.get_task(task_id)
    if not t:
        raise HTTPException(404, "задача не найдена")
    html = store.get_report_html(task_id)
    if not html:
        raise HTTPException(409, f"отчёт ещё не готов (статус: {t['status']})")
    return HTMLResponse(content=html)
