"""Шаблоны отчётов — механизм кастомных отчётов.

Шаблон задаёт: какие секции включать и в каком порядке, фильтры по находкам
(минимальная опасность, достоверность, хосты, профили), брендинг (название,
логотип, подпись). Встроенные шаблоны лежат в reports/*.yaml; заказчик может
положить свой файл и передать его через `report --template`.
"""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

# Все известные секции отчёта в каноническом порядке. Шаблон выбирает подмножество.
ALL_SECTIONS = [
    "summary",            # сводка: дашборд с диаграммами + счётчики
    "remediation",        # план устранения (приоритизированные действия)
    "by_host_matrix",     # распределение уязвимостей по хостам
    "by_product_matrix",  # распределение уязвимостей по продуктам
    "inventory",          # инвентаризация активов
    "vuln_table",         # сводная таблица уязвимостей
    "vuln_details",       # детальные карточки уязвимостей
    "by_host",            # разбивка по каждому хосту (уязвимости + конфигурации)
    "config",             # соответствие конфигураций по профилям
    "manual",             # приложение: требуют ручной проверки
    "sources",            # приложение: исходные данные (артефакты)
]

SEV_THRESHOLD = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

# Значения по умолчанию — полный отчёт.
DEFAULTS = {
    "id": "custom",
    "title": "Отчёт об обследовании",
    "brand": {"product": "surveyscan", "logo_text": "surveyscan", "logo_path": None},
    "sections": list(ALL_SECTIONS),
    "disclaimer": True,
    "filters": {
        "min_severity": None,   # critical|high|medium|low — убрать находки ниже порога
        "confidence": None,     # список достоверностей, которые оставить; None = все
        "hosts": None,          # список имён хостов; None = все
        "profiles": None,       # список id профилей конфигураций; None = все
    },
}

# Встроенные шаблоны можно переопределять файлами в reports/, но эти всегда доступны по id.
BUILTIN = {
    "full": {"id": "full", "title": "Отчёт об обследовании"},
    "executive": {
        "id": "executive",
        "title": "Отчёт для руководства",
        "sections": ["summary", "remediation", "by_host_matrix", "config"],
        "disclaimer": True,
    },
    "vuln": {
        "id": "vuln",
        "title": "Отчёт по уязвимостям",
        "sections": ["summary", "by_host_matrix", "by_product_matrix",
                     "vuln_table", "vuln_details"],
    },
    "config": {
        "id": "config",
        "title": "Отчёт по соответствию конфигураций",
        "sections": ["summary", "config"],
    },
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_template(spec: str | None, reports_dir: Path | None = None) -> dict:
    """spec: None | id встроенного (full/executive/vuln/config) | путь к YAML-файлу."""
    over: dict = dict(BUILTIN["full"])   # по умолчанию — полный отчёт
    if spec:
        p = Path(spec)
        if p.exists():                                                   # явный путь к .yaml
            over = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        elif reports_dir and (reports_dir / f"{spec}.yaml").exists():    # файл в reports/ (приоритет)
            over = yaml.safe_load((reports_dir / f"{spec}.yaml").read_text(encoding="utf-8")) or {}
        elif spec in BUILTIN:                                            # встроенный, если файлов нет
            over = BUILTIN[spec]
        else:
            raise SystemExit(f"шаблон отчёта не найден: {spec} "
                             f"(встроенные: {', '.join(BUILTIN)}; либо путь к .yaml)")
    tpl = _merge(DEFAULTS, over)
    # нормализуем секции: только известные, в каноническом порядке
    want = set(tpl.get("sections") or ALL_SECTIONS)
    unknown = want - set(ALL_SECTIONS)
    if unknown:
        raise SystemExit(f"неизвестные секции в шаблоне: {', '.join(sorted(unknown))}")
    tpl["sections"] = [s for s in ALL_SECTIONS if s in want]
    tpl["has"] = {s: (s in want) for s in ALL_SECTIONS}
    ms = tpl["filters"].get("min_severity")
    if ms and ms not in SEV_THRESHOLD:
        raise SystemExit(f"min_severity должен быть одним из {list(SEV_THRESHOLD)}")
    return tpl


def sev_allowed(sev: str, min_severity: str | None) -> bool:
    if not min_severity:
        return True
    return SEV_THRESHOLD.get(sev, 9) <= SEV_THRESHOLD[min_severity]
