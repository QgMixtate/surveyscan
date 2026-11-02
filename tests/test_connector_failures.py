"""Проверки владения заданиями и невалидного токена без PostgreSQL."""
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from surveyscan.api import connector


def test_connector_cannot_upload_another_connectors_job(monkeypatch):
    monkeypatch.setattr(connector, 'connector_by_token', Mock(return_value={'id': 1}))
    monkeypatch.setattr(connector, 'get_job', Mock(return_value={
        'id': 5, 'connector_id': 2, 'name': 'other', 'customer': None, 'template': None}))
    create = Mock(side_effect=AssertionError('must reject before creating a task'))
    monkeypatch.setattr(connector.store, 'create_task', create)
    with pytest.raises(HTTPException) as exc:
        connector.api_submit_result(5, connector.ResultSubmit(files={'host.surv': 'sample'}), 'Bearer own')
    assert exc.value.status_code == 403
    create.assert_not_called()


def test_empty_bearer_token_returns_401():
    with pytest.raises(HTTPException) as exc:
        connector._auth('Bearer   ')
    assert exc.value.status_code == 401
