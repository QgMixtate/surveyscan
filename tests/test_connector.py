"""Тесты протокола коннектора (этап 4): регистрация, выдача задания, приём результата, офлайн-бандл."""
from fastapi.testclient import TestClient

from surveyscan.api.app import app
from surveyscan.cli import ROOT


def _raw_files() -> dict:
    return {p.name: p.read_text(encoding="utf-8")
            for p in (ROOT / "samples" / "hosts").glob("*") if p.is_file()}


def test_pull_flow_end_to_end():
    with TestClient(app) as c:
        conn = c.post("/connectors", json={"name": "Коннектор-тест"}).json()
        cid, token = conn["id"], conn["token"]
        h = {"Authorization": f"Bearer {token}"}

        job = c.post("/connector/jobs", json={"connector_id": cid, "name": "J1", "customer": "X"}).json()
        jid = job["id"]
        assert job["status"] == "assigned"

        # коннектор забирает задание (переходит в collecting), повторный запрос — пусто
        nj = c.get("/connector/jobs/next", headers=h)
        assert nj.status_code == 200 and nj.json()["id"] == jid
        assert c.get("/connector/jobs/next", headers=h).status_code == 204

        # выгрузка результата -> центр анализирует базами центра -> задача findings=14
        r = c.post(f"/connector/jobs/{jid}/result", json={"files": _raw_files()}, headers=h)
        assert r.status_code == 200
        tid = r.json()["task_id"]
        task = c.get(f"/tasks/{tid}").json()
        assert task["result"]["findings"] == 14 and task["result"]["source"] == "connector"
        assert c.get(f"/connector/jobs/{jid}").json()["status"] == "done"


def test_courier_bundle_then_import():
    with TestClient(app) as c:
        conn = c.post("/connectors", json={"name": "Коннектор-курьер"}).json()
        cid, token = conn["id"], conn["token"]
        h = {"Authorization": f"Bearer {token}"}
        jid = c.post("/connector/jobs", json={"connector_id": cid, "name": "J2"}).json()["id"]

        bundle = c.get(f"/connector/jobs/{jid}/bundle").json()
        assert bundle["bundle"] == "surveyscan-job" and bundle["job"]["id"] == jid

        # офлайн-результат импортируется тем же маршрутом result
        r = c.post(f"/connector/jobs/{jid}/result", json={"files": _raw_files()}, headers=h)
        assert r.status_code == 200
        assert c.get(f"/connector/jobs/{jid}").json()["status"] == "done"


def test_auth_required():
    with TestClient(app) as c:
        assert c.get("/connector/jobs/next").status_code == 401
        assert c.get("/connector/jobs/next", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_empty_result_rejected():
    with TestClient(app) as c:
        conn = c.post("/connectors", json={"name": "Коннектор-пустой"}).json()
        h = {"Authorization": f"Bearer {conn['token']}"}
        jid = c.post("/connector/jobs", json={"connector_id": conn["id"], "name": "J3"}).json()["id"]
        assert c.post(f"/connector/jobs/{jid}/result", json={"files": {}}, headers=h).status_code == 400


def test_results_are_owned_and_cannot_be_replayed(monkeypatch):
    from surveyscan.api import runner
    monkeypatch.setattr(runner, 'run_pipeline', lambda *a, **k: ({}, '<html>ok</html>', {}))
    with TestClient(app) as c:
        owner = c.post('/connectors', json={'name': 'owner'}).json()
        other = c.post('/connectors', json={'name': 'other'}).json()
        jid = c.post('/connector/jobs', json={'connector_id': owner['id']}).json()['id']
        url = f'/connector/jobs/{jid}/result'
        body = {'files': {'host.surv': 'sample'}}
        assert c.post(url, json=body, headers={'Authorization': f"Bearer {other['token']}"}).status_code == 403
        headers = {'Authorization': f"Bearer {owner['token']}"}
        assert c.post(url, json=body, headers=headers).status_code == 200
        assert c.post(url, json=body, headers=headers).status_code == 409


def test_concurrent_pollers_only_receive_job_once():
    from concurrent.futures import ThreadPoolExecutor
    from surveyscan.api import connector
    with TestClient(app) as c:
        owner = c.post('/connectors', json={'name': 'concurrent'}).json()
        jid = c.post('/connector/jobs', json={'connector_id': owner['id']}).json()['id']
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: connector.next_job(owner['id']), range(8)))
        assert [r['id'] for r in results if r] == [jid]
