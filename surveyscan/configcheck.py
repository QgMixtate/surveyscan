"""Проверка конфигураций: проверки (checks/*.yaml) + каталог требований (catalog/*.yaml) + профиль (profiles/*.yaml).

Проверка описывает ЧТО сравнить с фактами, собранными коллектором; к каким пунктам каких
документов она относится — задаёт каталог; какие проверки и с какими порогами применять — профиль.
"""
from __future__ import annotations

import copy
import fnmatch
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import yaml

_MISSING = object()


# ----------------------------------------------------------------------------- загрузка
def load_checks(dirpath: Path) -> dict[str, dict]:
    checks = {}
    for f in sorted(dirpath.glob("*.yaml")):
        for c in (yaml.safe_load(f.read_text(encoding="utf-8")) or {}).get("checks", []):
            if c["id"] in checks:
                raise ValueError(f"Повтор ID проверки {c['id']} в {f}")
            c["_file"] = f.name
            checks[c["id"]] = c
    return checks


def load_catalog(dirpath: Path) -> dict:
    docs, mapping = {}, {}
    for f in sorted(dirpath.glob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        docs.update(data.get("documents") or {})
        for check_id, refs in (data.get("mapping") or {}).items():
            mapping.setdefault(check_id, []).extend(refs)
    return {"documents": docs, "mapping": mapping}


def load_profile(path: Path) -> dict:
    prof = yaml.safe_load(path.read_text(encoding="utf-8"))
    if prof.get("extends"):
        base = load_profile(path.parent / f"{prof['extends']}.yaml")
        merged = copy.deepcopy(base)
        for k in ("id", "title", "description", "docs"):
            if k in prof:
                merged[k] = prof[k]
        merged["include"] = prof.get("include", base.get("include", ["*"]))
        merged["exclude"] = base.get("exclude", []) + prof.get("exclude", [])
        merged["params"] = {**base.get("params", {}), **prof.get("params", {})}
        return merged
    prof.setdefault("include", ["*"])
    prof.setdefault("exclude", [])
    prof.setdefault("params", {})
    return prof


def select_checks(checks: dict, profile: dict) -> list[dict]:
    out = []
    for cid, c in checks.items():
        if any(fnmatch.fnmatch(cid, p) for p in profile["include"]) and \
                not any(fnmatch.fnmatch(cid, p) for p in profile["exclude"]):
            c = {**c, **(profile["params"].get(cid) or {})}
            out.append(c)
    return out


# ----------------------------------------------------------------------------- факты
def derived_facts(platform: str, facts: dict) -> dict:
    """Вычисляемые факты, чтобы проверки оставались декларативными."""
    f = dict(facts)
    f["listening_ports"] = sorted({int(x["port"]) for x in facts.get("listening") or []
                                   if str(x.get("port")).isdigit()})
    if platform == "linux":
        act = facts.get("services_active") or {}
        f["time_sync_active"] = any(act.get(s) == "active" for s in
                                    ("chronyd", "chrony", "ntp", "ntpd", "systemd-timesyncd"))
        f["firewall_active"] = any(act.get(s) == "active" for s in ("firewalld", "ufw", "nftables", "iptables"))
    if platform == "windows":
        users = facts.get("users") or []
        f["users_no_password_required"] = [u["name"] for u in users
                                           if not u.get("disabled") and not u.get("password_required")]
        fw = facts.get("firewall") or {}
        f["firewall_all_enabled"] = bool(fw) and all(fw.values())
        d = facts.get("defender") or {}
        f["antivirus_present"] = bool(facts.get("antivirus")) or bool(d.get("enabled") and d.get("realtime"))
    return f


def get_fact(facts: dict, path: list) -> Any:
    cur: Any = facts
    for i, key in enumerate(path):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        elif isinstance(cur, dict) and isinstance(key, str) and key.lower() in {k.lower() for k in cur}:
            cur = next(v for k, v in cur.items() if k.lower() == key.lower())
        else:
            # родительский раздел есть, ключа нет -> можно применить значение по умолчанию
            return ("__absent_key__" if isinstance(cur, dict) and i == len(path) - 1 else _MISSING)
        if cur is None:
            # коллектор пишет null для незаданного параметра (например, значения реестра)
            return "__absent_key__" if i == len(path) - 1 else _MISSING
    return cur


# ----------------------------------------------------------------------------- операторы
def _num(x):
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return None


def _norm(x):
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x).strip().lower()


def evaluate(op: str, actual: Any, value: Any) -> bool:
    if op == "eq":
        a, v = _num(actual), _num(value)
        return a == v if a is not None and v is not None else _norm(actual) == _norm(value)
    if op == "ne":
        return not evaluate("eq", actual, value)
    if op in ("ge", "le", "gt", "lt"):
        a, v = _num(actual), _num(value)
        if a is None or v is None:
            return False
        return {"ge": a >= v, "le": a <= v, "gt": a > v, "lt": a < v}[op]
    if op == "range":
        a = _num(actual)
        return a is not None and _num(value[0]) <= a <= _num(value[1])
    if op == "in":
        return _norm(actual) in {_norm(v) for v in value}
    if op == "not_in":
        return _norm(actual) not in {_norm(v) for v in value}
    if op == "regex":
        return re.search(value, actual if isinstance(actual, str) else json.dumps(actual, ensure_ascii=False),
                         re.M | re.I) is not None
    if op == "not_regex":
        return not evaluate("regex", actual, value)
    if op == "empty":
        return not actual
    if op == "not_empty":
        return bool(actual)
    if op in ("contains", "not_contains"):
        items = value if isinstance(value, list) else [value]
        pool = {_norm(x) for x in actual} if isinstance(actual, (list, set, tuple)) else None
        hit = any((_norm(i) in pool) if pool is not None else (_norm(i) in _norm(actual)) for i in items)
        return hit if op == "contains" else not hit
    if op == "subset_of":
        return {_norm(x) for x in (actual or [])} <= {_norm(v) for v in value}
    if op == "mode_le":
        # права не шире заданных: в фактических нет битов, которых нет в разрешённых
        try:
            return int(str(actual), 8) & ~int(str(value), 8) == 0
        except ValueError:
            return False
    raise ValueError(f"Неизвестный оператор {op}")


def _expected_text(op, value) -> str:
    sym = {"eq": "=", "ne": "≠", "ge": "≥", "le": "≤", "gt": ">", "lt": "<", "in": "одно из", "not_in": "не из",
           "regex": "соответствует", "not_regex": "не содержит", "empty": "пусто", "not_empty": "не пусто",
           "contains": "содержит", "not_contains": "не содержит", "subset_of": "только",
           "mode_le": "права не шире", "range": "в диапазоне"}.get(op, op)
    if op in ("empty", "not_empty"):
        return sym
    if isinstance(value, bool):
        return f"{sym} {'да' if value else 'нет'}"
    if op == "range":
        return f"{sym} {value[0]}–{value[1]}"
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    return f"{sym} {value}"


def _short(x, limit=160) -> str:
    if isinstance(x, bool):
        return "да" if x else "нет"
    if isinstance(x, (list, dict)):
        x = json.dumps(x, ensure_ascii=False)
    s = str(x)
    return s if len(s) <= limit else s[:limit] + "…"


def render_title(check: dict) -> str:
    v = check.get("value")
    if isinstance(v, list) and check.get("op") == "range" and len(v) == 2:
        v = f"{v[0]}–{v[1]}"
    return check["title"].replace("{value}", str(v))


_SECRET_KEYS = {"password", "secret", "community", "key-string", "key", "pre-shared-key", "cipher",
                "irreversible-cipher", "auth-password", "priv-password", "authentication-key"}
# слова синтаксиса между ключом и значением: тип шифрования, режим доступа
_MODIFIERS = {"0", "5", "6", "7", "8", "9", "md5", "sha", "sha256", "sha512", "plain", "simple", "cipher",
              "irreversible-cipher", "read", "write", "encrypted", "unencrypted"}
_NOT_SECRET_AFTER_KEY = {"chain", "config-key", "encryption", "-encryption"}
_DEFAULT_SECRETS = {"public", "private"}   # значения по умолчанию — это и есть находка, их не скрываем


def mask_secrets(text: str) -> str:
    """Скрывает пароли, хэши, ключи и SNMP-сообщества в строках, попадающих в отчёт."""
    out_lines = []
    for line in text.split("\n"):
        parts = re.split(r"(\s+)", line)          # сохраняем исходные пробелы
        words = [i for i in range(0, len(parts), 2)]
        k = 0
        while k < len(words):
            w = parts[words[k]].lower()
            if w in _SECRET_KEYS:
                j = k + 1
                while j < len(words) and parts[words[j]].lower() in _MODIFIERS:
                    j += 1
                if j < len(words):
                    val = parts[words[j]]
                    if val.lower() not in _DEFAULT_SECRETS and val.lower() not in _NOT_SECRET_AFTER_KEY:
                        parts[words[j]] = "******"
                k = j + 1
            else:
                k += 1
        out_lines.append("".join(parts))
    return "\n".join(out_lines)


def _shown_for_text(op: str, actual: str, pattern: str, result: str) -> str:
    """Для regex-проверок по большому тексту (конфиг, PAM) показываем суть, а не весь текст."""
    lines = [mask_secrets(l.strip()) for l in actual.splitlines() if re.search(pattern, l, re.I)]
    if op == "not_regex":
        return "; ".join(lines[:3]) + (" …" if len(lines) > 3 else "") if lines else "не найдено"
    return "; ".join(lines[:2]) if lines else "строка не найдена"


def applies(check: dict, asset: sqlite3.Row) -> bool:
    plats = check.get("platform")
    plats = [plats] if isinstance(plats, str) else plats
    if plats and asset["platform"] not in plats:
        return False
    cond = check.get("applies_if") or {}
    if "os_id" in cond and (asset["os_id"] or "").lower() not in [x.lower() for x in cond["os_id"]]:
        return False
    if "os_id_not" in cond and (asset["os_id"] or "").lower() in [x.lower() for x in cond["os_id_not"]]:
        return False
    return True


def run_checks(con: sqlite3.Connection, checks_dir: Path, catalog_dir: Path, profile_path: Path) -> dict:
    checks = load_checks(checks_dir)
    catalog = load_catalog(catalog_dir)
    profile = load_profile(profile_path)
    selected = select_checks(checks, profile)
    con.execute("DELETE FROM check_result WHERE profile = ?", (profile["id"],))
    stats = {"pass": 0, "fail": 0, "na": 0, "error": 0}
    for asset in con.execute("SELECT * FROM asset WHERE facts IS NOT NULL").fetchall():
        facts = derived_facts(asset["platform"], json.loads(asset["facts"]))
        done: dict[str, str] = {}
        for c in selected:
            if not applies(c, asset):
                continue
            expected = c.get("expected_text") or _expected_text(c["op"], c.get("value"))
            failed_req = [r for r in c.get("requires", []) if done.get(r) == "fail"]
            if failed_req:
                # параметр без подключённого механизма не имеет смысла: «значение по умолчанию» не действует
                result, shown = "fail", f"не выполнено условие {', '.join(failed_req)}"
                done[c["id"]] = result
                stats[result] += 1
                refs = [{"doc": r["doc"], "item": r.get("item")} for r in catalog["mapping"].get(c["id"], [])
                        if r["doc"] in profile.get("docs", catalog["documents"].keys())]
                con.execute("INSERT INTO check_result(asset_id,profile,check_id,title,result,actual,expected,severity,"
                            "remediation,refs) VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (asset["id"], profile["id"], c["id"], render_title(c), result, shown, expected,
                             c.get("severity", "medium"), c.get("remediation"), json.dumps(refs, ensure_ascii=False)))
                continue
            actual = get_fact(facts, c["fact"])
            if actual == "__absent_key__":
                actual = c["default"] if "default" in c else _MISSING
            if actual is _MISSING:
                result = c.get("missing", "na")
                shown = "нет данных" if result == "na" else "не задано"
            else:
                try:
                    result = "pass" if evaluate(c["op"], actual, c.get("value")) else "fail"
                except Exception as e:      # ошибка в описании проверки не должна ронять прогон
                    result, actual = "error", f"{type(e).__name__}: {e}"
                if c["op"] in ("regex", "not_regex") and isinstance(actual, str) and "\n" in actual:
                    shown = _shown_for_text(c["op"], actual, c["value"], result)
                else:
                    shown = mask_secrets(_short(actual))
            done[c["id"]] = result
            stats[result] += 1
            refs = [{"doc": r["doc"], "item": r.get("item")}
                    for r in catalog["mapping"].get(c["id"], []) if r["doc"] in profile.get("docs", catalog["documents"].keys())]
            con.execute("INSERT INTO check_result(asset_id,profile,check_id,title,result,actual,expected,severity,"
                        "remediation,refs) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (asset["id"], profile["id"], c["id"], render_title(c), result, shown, expected,
                         c.get("severity", "medium"), c.get("remediation"), json.dumps(refs, ensure_ascii=False)))
    con.commit()
    return {"profile": profile["id"], "checks_in_profile": len(selected), **stats}
