"""Исполнитель задач — backend очереди.

Сейчас backend — пул потоков (достаточно для вертикального среза и тестов). Интерфейс
submit(task_id) совместим с заменой на Celery+Redis: тело задачи (_run) переедет в
Celery-task без изменений. Каждая задача выполняет пайплайн ядра в своей рабочей БД
PostgreSQL (имя выводится из временного каталога задачи) и пишет результат в store.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import store
from ..collect import redact_secrets

_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:\-/]+$")   # IP / CIDR / hostname / ipv6 — без спецсимволов оболочки

# Секреты УЗ (пароли/ключи/community) живут ТОЛЬКО в памяти процесса, по id задачи,
# и никогда не пишутся в БД/лог/отчёт. При рестарте теряются (задача просто не сможет
# аутентифицироваться) — это осознанный компромисс в пользу безопасности.
_VAULT: dict[int, list[dict]] = {}
_VAULT_LOCK = threading.Lock()


def put_secrets(task_id: int, creds: list[dict]) -> None:
    with _VAULT_LOCK:
        _VAULT[task_id] = creds


def _pop_secrets(task_id: int) -> list[dict]:
    with _VAULT_LOCK:
        return _VAULT.pop(task_id, [])


# --- отмена задач: реестр активных процессов nmap и флагов отмены ---
_PROCS: dict[int, subprocess.Popen] = {}
_CANCELLED: set[int] = set()
_CANCEL_LOCK = threading.Lock()


def cancel(task_id: int) -> bool:
    """Запросить отмену задачи: поднять флаг и прибить активный процесс nmap, если он есть."""
    with _CANCEL_LOCK:
        _CANCELLED.add(task_id)
        proc = _PROCS.get(task_id)
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return True


def _is_cancelled(task_id) -> bool:
    with _CANCEL_LOCK:
        return task_id in _CANCELLED


def _log(task_id, msg: str) -> None:
    print(f"[task {task_id}] {msg}", flush=True)       # виден в `docker compose logs -f app`
    if task_id is not None:
        try:
            store.append_progress(task_id, msg)         # и в журнал задачи (для UI)
        except Exception:
            pass


def parse_targets(raw) -> list[str]:
    """Разбор строки целей (подсети/хосты) с валидацией — защита от инъекций в nmap."""
    if not raw:
        return []
    out = []
    for p in re.split(r"[\s,;]+", str(raw).strip()):
        if not p:
            continue
        # ведущий '-' запрещён, чтобы цель нельзя было подсунуть как флаг nmap
        if p.startswith("-") or len(p) > 100 or not _TARGET_RE.match(p):
            raise ValueError(f"недопустимая цель: {p!r}")
        out.append(p)
    return out


def _run_nmap(args: list[str], timeout: int, task_id) -> subprocess.CompletedProcess:
    """Запуск nmap через Popen с регистрацией процесса (чтобы задачу можно было отменить)."""
    # Проверка и регистрация под одним замком: отмена не должна потеряться при старте.
    with _CANCEL_LOCK:
        if task_id in _CANCELLED:
            raise _Cancelled()
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if task_id is not None:
            _PROCS[task_id] = proc
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
    finally:
        if task_id is not None:
            with _CANCEL_LOCK:
                _PROCS.pop(task_id, None)
    return subprocess.CompletedProcess(args, proc.returncode, out, err)


def nmap_scan(targets: list[str], out_xml: Path, timeout: int = 1800, task_id=None) -> None:
    """Реальное сетевое обнаружение: nmap по целям (сервисы + ОС), вывод в XML (его ест ingest)."""
    if not shutil.which("nmap"):
        raise RuntimeError("nmap не установлен на сервере — установите пакет nmap")
    base = ["nmap", "-sV", "-T4", "--open", "--stats-every", "15s", "-oX", str(out_xml)]
    # -O/--osscan-guess даёт ОС хостов, но требует root; при отказе повторяем без определения ОС
    r = _run_nmap(base[:1] + ["-O", "--osscan-guess"] + base[1:] + list(targets), timeout, task_id)
    if _is_cancelled(task_id):
        raise _Cancelled()
    if r.returncode != 0 and re.search(r"root|privileg|requires", (r.stderr or ""), re.I):
        r = _run_nmap(base + list(targets), timeout, task_id)
    if _is_cancelled(task_id):
        raise _Cancelled()
    if r.returncode != 0 or not out_xml.exists():
        raise RuntimeError(f"nmap завершился с ошибкой: {(r.stderr or r.stdout)[-600:]}")


class _Cancelled(Exception):
    """Внутренний сигнал: задача отменена пользователем."""

_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="surveyscan-worker")


def submit(task_id: int) -> None:
    _POOL.submit(_run, task_id)


def run_sync(task_id: int) -> None:
    """Синхронный запуск (для тестов и отладки)."""
    _run(task_id)


def _run(task_id: int) -> None:
    creds = _pop_secrets(task_id)        # секреты из памяти; вынимаем один раз
    try:
        if _is_cancelled(task_id):
            raise _Cancelled()
        store.mark_started(task_id)
        task = store.get_task(task_id)
        params = task.get("params") or {}
        result, html, dash = run_pipeline(task.get("name"), task.get("customer"), params,
                                          creds=creds, log=lambda m: _log(task_id, redact_secrets(m, creds)),
                                          task_id=task_id, cancel_check=lambda: _is_cancelled(task_id))
        if _is_cancelled(task_id):
            raise _Cancelled()
        store.mark_done(task_id, result, html, dash)
        _log(task_id, "готово")
    except _Cancelled:
        store.mark_cancelled(task_id)
        _log(task_id, "отменено пользователем")
    except (Exception, SystemExit):
        tb = redact_secrets(traceback.format_exc(limit=6), creds)
        store.mark_error(task_id, tb)
        _log(task_id, "ОШИБКА: " + (tb.strip().splitlines()[-1] if tb.strip() else "неизвестно"))
    finally:
        creds = None
        with _CANCEL_LOCK:
            _CANCELLED.discard(task_id)
            _PROCS.pop(task_id, None)


def run_pipeline(name, customer, params: dict, raw_dir=None, creds=None, log=None,
                 task_id=None, cancel_check=None) -> tuple[dict, str, dict]:
    """Прогон ядра. Возвращает (сводка, HTML-отчёт, данные для UI).

    Срез пайплайна: сбор баз → инвентаризация → анализ → конфигурации → отчёт.
    Базы знаний (БДУ, MSRC, фиды) берутся из комплекта центра. Сырьё инвентаризации:
    из raw_dir (выгрузки коллекторов, например от коннектора) либо, если не задано,
    из встроенных синтетических данных (демо).
    """
    from ..cli import ROOT
    from .. import bdu, msrc, advisories
    from ..db import connect
    from ..ingest import ingest_file
    from ..matcher import analyze
    from ..configcheck import run_checks
    from ..normalize import Catalog
    from ..report import render_html_with_data, dashboard_json
    from ..pgcompat import drop_db

    s = ROOT / "samples"
    # профиль сканирования задаёт, какие этапы включать
    kind = params.get("kind", "demo")
    do_vulns = kind in ("demo", "vuln")
    do_config = kind in ("demo", "config")
    template = params.get("template") or {"inventory": "inventory", "vuln": "vuln", "config": "config"}.get(kind)
    targets = parse_targets(params.get("targets"))    # реальные цели (подсети/хосты)
    real = bool(targets)                              # реальный скан vs демо-синтетика
    log = log or (lambda m: None)
    collect_summary = None
    workdir = Path(tempfile.mkdtemp(prefix="surveyscan-task-"))
    sv = workdir / "survey.sqlite"
    bd = workdir / "bdu.sqlite"
    ms = workdir / "msrc.sqlite"
    ad = workdir / "adv.sqlite"
    con = None

    def check_cancelled():
        if cancel_check and cancel_check():
            raise _Cancelled()

    try:
        check_cancelled()
        drop_db(sv)                                   # чистая рабочая БД задачи
        if real:                                      # реальное сетевое обнаружение целей
            nmap_xml = workdir / "nmap.xml"
            log(f"nmap: обнаружение целей {targets}…")
            nmap_scan(targets, nmap_xml, task_id=task_id)
            log("nmap: завершено")

        if do_vulns:                                  # базы знаний нужны только для поиска уязвимостей
            check_cancelled()
            bdu.import_bdu(s / "bdu" / "vulxml_sample.xml", bd)
            msrc.sync(ms, files=[s / "msrc_cvrf_sample.json"])
            advisories.import_feeds(
                ad,
                ubuntu_oval=[s / "advisories" / "com.ubuntu.jammy.pkg.oval.xml"],
                debian_json=[s / "advisories" / "debian_tracker_sample.json"],
                normalized=[s / "advisories" / "astra_normalized.jsonl"])
            con = connect(sv, bd)
        else:
            con = connect(sv)

        if real:
            ingest_file(con, nmap_xml)                # живые активы из сетевого скана
            con.commit()
            if creds:                                 # аутентифицированный сбор инвентаря по УЗ
                from ..collect import collect
                log(f"аутентифицированный сбор: {len(creds)} УЗ, подбор под активы…")
                collect_summary = collect(con, creds, ROOT, log=log, should_cancel=cancel_check)
                con.commit()
                if cancel_check and cancel_check():
                    raise _Cancelled()
        else:
            hosts = sorted(Path(raw_dir).glob("*")) if raw_dir else sorted((s / "hosts").glob("*"))
            for f in hosts:
                if f.is_file():
                    ingest_file(con, f)
        con.commit()

        check_cancelled()
        stats = {}
        if do_vulns:                                  # сопоставление с БДУ и фидами
            stats = analyze(con, Catalog(ROOT / "rules" / "products.yaml"), ms, ad)
            con.execute("UPDATE survey SET bdu_version=?, name=COALESCE(?, name), customer=COALESCE(?, customer)",
                        (bdu.bdu_version_label(con), name, customer))
        else:
            con.execute("UPDATE survey SET name=COALESCE(?, name), customer=COALESCE(?, customer)", (name, customer))
        con.commit()

        cfg = {}
        if do_config:                                # у nmap-only активов нет facts — run_checks их пропустит
            for prof in ("base", "customer-example"):
                cfg[prof] = run_checks(con, ROOT / "checks", ROOT / "catalog", ROOT / "profiles" / f"{prof}.yaml")

        check_cancelled()
        out_html = workdir / "report.html"
        _, data = render_html_with_data(con, ROOT / "catalog", out_html,
                                        template=template, reports_dir=ROOT / "reports")
        html = out_html.read_text(encoding="utf-8")
        dash = dashboard_json(data)
        from ..topology import build as build_topology, merge_l2
        dash["topology"] = build_topology(data["assets"])    # схема сети из активов
        if collect_summary and collect_summary.get("l2_links"):   # связи L2 из SNMP (LLDP)
            merge_l2(dash["topology"], collect_summary["l2_links"])
            dash["topology"]["stats"]["edges"] = len(dash["topology"]["elements"]["edges"])

        # сводка сбора без секретов (для UI/отчёта)
        collect_public = None
        if collect_summary is not None:
            collect_public = {"collected": collect_summary["collected"], "failed": collect_summary["failed"],
                              "l2_links": len(collect_summary["l2_links"])}
        result = {
            "vulnerabilities": stats,
            "config": cfg,
            "findings": stats.get("findings", 0),
            "template": template or "full",
            "kind": kind,
            "source": "network" if real else "demo",
            "targets": targets,
            "collect": collect_public,
        }
        return result, html, dash
    finally:
        try:
            if con is not None:
                con.close()
        finally:
            try:
                drop_db(sv)                           # не оставляем БД задачи в PostgreSQL
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
