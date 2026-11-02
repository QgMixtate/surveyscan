"""Ошибки исполнителя: без nmap и сетевых подключений."""
import subprocess
from unittest.mock import Mock

import pytest

from surveyscan.api import runner


def test_nmap_timeout_kills_and_reaps_process(monkeypatch):
    proc = Mock()
    proc.communicate.side_effect = [subprocess.TimeoutExpired(['nmap'], 1), ('', '')]
    monkeypatch.setattr(runner.subprocess, 'Popen', Mock(return_value=proc))
    with pytest.raises(subprocess.TimeoutExpired):
        runner._run_nmap(['nmap'], 1, 91001)
    proc.kill.assert_called_once()
    assert proc.communicate.call_count == 2
    assert 91001 not in runner._PROCS


def test_cancelled_queued_task_never_starts_pipeline(monkeypatch):
    tid = 91002
    pipeline = Mock(return_value=({}, '', {}))
    cancelled = Mock()
    for name in ('mark_started', 'mark_done', 'mark_error', 'append_progress'):
        monkeypatch.setattr(runner.store, name, Mock())
    monkeypatch.setattr(runner.store, 'mark_cancelled', cancelled)
    monkeypatch.setattr(runner.store, 'get_task', Mock(return_value={'params': {}}))
    monkeypatch.setattr(runner, 'run_pipeline', pipeline)
    runner.put_secrets(tid, [{'secret': 'test-secret'}])
    runner.cancel(tid)
    runner.run_sync(tid)
    pipeline.assert_not_called()
    cancelled.assert_called_once_with(tid)
    assert tid not in runner._VAULT and tid not in runner._CANCELLED


def test_start_failure_clears_secrets_and_records_error(monkeypatch):
    tid = 91003
    monkeypatch.setattr(runner.store, 'mark_started', Mock(side_effect=RuntimeError('store failed')))
    error = Mock()
    monkeypatch.setattr(runner.store, 'mark_error', error)
    monkeypatch.setattr(runner.store, 'append_progress', Mock())
    runner.put_secrets(tid, [{'secret': 'test-secret'}])
    try:
        runner.run_sync(tid)
        error.assert_called_once()
    finally:
        assert tid not in runner._VAULT


def test_cancelled_before_nmap_registration_does_not_spawn(monkeypatch):
    tid = 91004
    popen = Mock()
    monkeypatch.setattr(runner.subprocess, 'Popen', popen)
    runner.cancel(tid)
    try:
        with pytest.raises(runner._Cancelled):
            runner._run_nmap(['nmap'], 1, tid)
        popen.assert_not_called()
    finally:
        runner._CANCELLED.discard(tid)


def test_worker_error_and_progress_do_not_expose_secrets(monkeypatch):
    tid = 91005
    secret = 'runner-test-password'
    monkeypatch.setattr(runner.store, 'mark_started', Mock())
    monkeypatch.setattr(runner.store, 'get_task', Mock(return_value={'params': {}}))
    error, progress = Mock(), Mock()
    monkeypatch.setattr(runner.store, 'mark_error', error)
    monkeypatch.setattr(runner.store, 'append_progress', progress)

    def fail(*args, **kwargs):
        kwargs['log']('failed with ' + secret)
        raise RuntimeError('failed with ' + secret)

    monkeypatch.setattr(runner, 'run_pipeline', fail)
    runner.put_secrets(tid, [{'secret': secret}])
    runner.run_sync(tid)
    error.assert_called_once()
    assert secret not in str(error.call_args)
    assert secret not in str(progress.call_args_list)
