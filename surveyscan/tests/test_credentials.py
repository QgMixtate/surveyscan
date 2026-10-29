"""Тесты хранилища учётных записей: шифрование секретов, CRUD через API, выбор по id."""
import pytest
from fastapi.testclient import TestClient

from surveyscan.api import secretbox, store
from surveyscan.api.app import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_secretbox_roundtrip():
    tok = secretbox.encrypt("S3cr3t!")
    assert tok != "S3cr3t!"                 # зашифровано, не плейнтекст
    assert secretbox.decrypt(tok) == "S3cr3t!"


def test_credential_crud_hides_secret(client):
    r = client.post("/credentials", json={"name": "Тест-УЗ", "type": "ssh",
                                           "username": "audit", "secret": "p@ss", "port": 22})
    assert r.status_code == 201
    cid = r.json()["id"]
    assert "secret" not in r.json()         # секрет не возвращается

    lst = client.get("/credentials").json()
    row = next(c for c in lst if c["id"] == cid)
    assert row["name"] == "Тест-УЗ" and row["username"] == "audit"
    assert "secret" not in row and "secret_enc" not in row   # в списке секретов нет

    # но хранится зашифрованно и расшифровывается в секрет
    enc = store.get_credentials_enc([cid])[0]["secret_enc"]
    assert enc and enc != "p@ss"
    assert secretbox.decrypt(enc) == "p@ss"

    assert client.delete(f"/credentials/{cid}").status_code == 204
    assert all(c["id"] != cid for c in client.get("/credentials").json())


def test_credential_validation(client):
    assert client.post("/credentials", json={"name": "x", "type": "bogus", "secret": "y"}).status_code == 400
    assert client.post("/credentials", json={"name": "x", "type": "ssh", "secret": "y"}).status_code == 400  # нет логина
    assert client.post("/credentials", json={"name": "x", "type": "ssh", "username": "u"}).status_code == 400  # нет секрета


def test_task_with_unknown_cred_ids_rejected(client):
    r = client.post("/tasks", json={"kind": "inventory", "targets": "10.0.0.1", "cred_ids": [999999]})
    assert r.status_code == 400
