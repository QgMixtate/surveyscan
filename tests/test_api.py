"""Тесты бэкенда (этап 2): создать задачу → запустить скан → получить результат через API."""
import time

import pytest
from fastapi.testclient import TestClient

from surveyscan.api.app import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_create_sync_task_runs_pipeline(client):
    r = client.post("/tasks", json={"kind": "demo", "run": "sync",
                                     "name": "Тест-обследование", "customer": "ООО «Тест»"})
    assert r.status_code == 201
    t = r.json()
    assert t["status"] == "done"
    assert t["result"]["findings"] == 14            # та же сводка, что в CLI-демо
    assert t["result"]["template"] == "full"
    assert t["has_report"] is True


def test_report_endpoint_returns_html(client):
    tid = client.post("/tasks", json={"kind": "demo", "run": "sync"}).json()["id"]
    r = client.get(f"/tasks/{tid}/report")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "BDU:2099-00011" in r.text and "Детализация уязвимостей" in r.text


def test_template_param(client):
    t = client.post("/tasks", json={"kind": "demo", "run": "sync", "template": "vuln"}).json()
    assert t["result"]["template"] == "vuln"
    html = client.get(f"/tasks/{t['id']}/report").text
    assert "Соответствие конфигураций" not in html   # шаблon vuln без конфигураций


def test_async_task_eventually_done(client):
    tid = client.post("/tasks", json={"kind": "demo", "run": "async"}).json()["id"]
    for _ in range(60):
        t = client.get(f"/tasks/{tid}").json()
        if t["status"] in ("done", "error"):
            break
        time.sleep(1)
    assert t["status"] == "done", t.get("error")
    assert t["result"]["findings"] == 14


def test_list_tasks(client):
    rows = client.get("/tasks").json()
    assert len(rows) >= 3 and all("status" in r for r in rows)


def test_unknown_kind_rejected(client):
    assert client.post("/tasks", json={"kind": "nope"}).status_code == 400


def test_missing_task_404(client):
    assert client.get("/tasks/999999").status_code == 404


def test_spa_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "<title>surveyscan</title>" in r.text and "/static/app.js" in r.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/vendor/react.production.min.js").status_code == 200


def test_unknown_kind_still_rejected(client):
    assert client.post("/tasks", json={"kind": "pentest"}).status_code == 400


def test_real_scan_requires_targets(client):
    assert client.post("/tasks", json={"kind": "inventory", "run": "sync"}).status_code == 400
    assert client.post("/tasks", json={"kind": "vuln", "run": "sync"}).status_code == 400


def test_flag_injection_target_rejected(client):
    # ведущий '-' мог бы стать флагом nmap -> отклоняется на валидации
    assert client.post("/tasks", json={"kind": "inventory", "targets": "-oG/tmp/x"}).status_code == 400


def test_cancel_validation(client):
    # несуществующую нельзя
    assert client.post("/tasks/999999/cancel").status_code == 404
    # завершённую (demo sync -> done) нельзя
    t = client.post("/tasks", json={"kind": "demo", "run": "sync", "name": "готовая"}).json()
    assert client.post(f"/tasks/{t['id']}/cancel").status_code == 409


def test_task_has_progress_field(client):
    t = client.post("/tasks", json={"kind": "demo", "run": "sync"}).json()
    d = client.get(f"/tasks/{t['id']}").json()
    assert "progress" in d and isinstance(d["progress"], list)
