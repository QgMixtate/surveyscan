"""Сравнение версий (dpkg, rpm, общее) и разбор диапазонов версий из БДУ ФСТЭК.

В БДУ версии затронутого ПО заданы свободным текстом на русском:
«от 2.0 до 2.4.54 включительно», «до 9.3p2», «1.2.3 и ранее», «4.0, 4.1»...
parse_bdu_versions() превращает такую строку в список ограничений либо
возвращает None, если строка не разобрана (такие записи идут в ручную проверку).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Optional

_DIGITS = "0123456789"


# --------------------------------------------------------------------------- dpkg
def _dpkg_order(c: str) -> int:
    if c in _DIGITS:
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def verrevcmp(a: str, b: str) -> int:
    """Алгоритм сравнения из dpkg (lib/dpkg/version.c)."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and a[i] not in _DIGITS) or (j < lb and b[j] not in _DIGITS):
            ac = _dpkg_order(a[i]) if i < la else 0
            bc = _dpkg_order(b[j]) if j < lb else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and a[i] in _DIGITS and j < lb and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i] in _DIGITS:
            return 1
        if j < lb and b[j] in _DIGITS:
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def split_dpkg(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def dpkg_cmp(a: str, b: str) -> int:
    ea, ua, ra = split_dpkg(a)
    eb, ub, rb = split_dpkg(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return verrevcmp(ua, ub) or verrevcmp(ra, rb)


# --------------------------------------------------------------------------- rpm
def rpmvercmp(a: str, b: str) -> int:
    """Алгоритм rpmvercmp (rpmio/rpmvercmp.c), включая ~ и ^."""
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)

    def isalnum_ascii(c: str) -> bool:
        return c.isascii() and c.isalnum()

    while i < la or j < lb:
        while i < la and not isalnum_ascii(a[i]) and a[i] not in "~^":
            i += 1
        while j < lb and not isalnum_ascii(b[j]) and b[j] not in "~^":
            j += 1
        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < la and j < lb):
            break
        si, sj = i, j
        isnum = a[i] in _DIGITS
        if isnum:
            while i < la and a[i] in _DIGITS:
                i += 1
            while j < lb and b[j] in _DIGITS:
                j += 1
        else:
            while i < la and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < lb and b[j].isascii() and b[j].isalpha():
                j += 1
        seg_a, seg_b = a[si:i], b[sj:j]
        if not seg_b:
            return 1 if isnum else -1
        if isnum:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def split_rpm(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        ver, rel = v.rsplit("-", 1)
    else:
        ver, rel = v, ""
    return epoch, ver, rel


def rpm_cmp(a: str, b: str) -> int:
    ea, va, ra = split_rpm(a)
    eb, vb, rb = split_rpm(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra and rb else 0)


# --------------------------------------------------------------------------- upstream
_UP_RE = re.compile(r"\d+(?:[.\-_]?[0-9a-z]+)*", re.I)


def upstream_of(version: str, ecosystem: str) -> str:
    """Выделяет «исходную» (upstream) версию, сопоставимую с версиями в БДУ."""
    v = (version or "").strip()
    if not v:
        return ""
    if ecosystem in ("deb", "rpm"):
        _, up, _ = split_dpkg(v) if ecosystem == "deb" else split_rpm(v)
        # Astra/Debian: 1.9.15p5+dfsg -> 1.9.15p5
        up = re.split(r"[+~]", up, maxsplit=1)[0]
        return up
    if ecosystem == "kernel":
        m = re.match(r"\d+(?:\.\d+)+", v)
        return m.group(0) if m else v
    # Сервисы из Nmap: "8.9p1 Ubuntu 3ubuntu0.10" -> "8.9p1"
    return v.split()[0].lstrip("vV")


def generic_cmp(a: str, b: str) -> int:
    """Сравнение «upstream»-версий; dpkg-порядок корректно работает с 9.3p2, 1.0rc1~ и т.п."""
    return verrevcmp(a.strip().lower().lstrip("v"), b.strip().lower().lstrip("v"))


def numeric_tuple_cmp(a: str, b: str) -> int:
    """Сравнение версий вида 10.0.19045.4291 (сборки Windows)."""
    ta = [int(x) for x in re.findall(r"\d+", a)]
    tb = [int(x) for x in re.findall(r"\d+", b)]
    return (ta > tb) - (ta < tb)


# --------------------------------------------------------------------------- БДУ
@dataclass
class Constraint:
    lo: Optional[str] = None
    lo_incl: bool = True
    hi: Optional[str] = None
    hi_incl: bool = False
    exact: Optional[str] = None
    any_version: bool = False

    def contains(self, v: str) -> bool:
        if self.any_version:
            return True
        if self.exact is not None:
            return generic_cmp(v, self.exact) == 0
        if self.lo is not None:
            c = generic_cmp(v, self.lo)
            if c < 0 or (c == 0 and not self.lo_incl):
                return False
        if self.hi is not None:
            c = generic_cmp(v, self.hi)
            if c > 0 or (c == 0 and not self.hi_incl):
                return False
        return True

    def to_dict(self) -> dict:
        return asdict(self)


V = r"([0-9][0-9a-z.\-_+:~]*)"
_PATTERNS: list[tuple[re.Pattern, callable]] = [
    (re.compile(rf"^от {V} до {V}( включительно)?$"),
     lambda m: Constraint(lo=m[1], lo_incl=True, hi=m[2], hi_incl=bool(m[3]))),
    (re.compile(rf"^с {V} по {V}$"),
     lambda m: Constraint(lo=m[1], hi=m[2], hi_incl=True)),
    (re.compile(rf"^(?:до|ниже|менее) {V}( включительно)?$"),
     lambda m: Constraint(hi=m[1], hi_incl=bool(m[2]))),
    (re.compile(rf"^{V} и (?:ранее|ниже|более ранние|предыдущие|младше)$"),
     lambda m: Constraint(hi=m[1], hi_incl=True)),
    (re.compile(rf"^(?:от|начиная с) {V}( и (?:выше|позднее|более поздние|новее|старше))?$"),
     lambda m: Constraint(lo=m[1])),
    (re.compile(rf"^{V} и (?:выше|позднее|более поздние|новее|старше)$"),
     lambda m: Constraint(lo=m[1])),
    (re.compile(rf"^{V} - {V}$"),
     lambda m: Constraint(lo=m[1], hi=m[2], hi_incl=True)),
    (re.compile(rf"^(<=|<|>=|>) ?{V}$"),
     lambda m: {"<=": Constraint(hi=m[2], hi_incl=True), "<": Constraint(hi=m[2]),
                ">=": Constraint(lo=m[2]), ">": Constraint(lo=m[2], lo_incl=False)}[m[1]]),
    (re.compile(rf"^{V}$"), lambda m: Constraint(exact=m[1])),
    (re.compile(r"^(?:все версии|любая версия|все)$"), lambda m: Constraint(any_version=True)),
]


def _clean(text: str) -> str:
    t = text.lower().replace("ё", "е").replace(" ", " ")
    t = re.sub(r"\(\s*включительно\s*\)", " включительно", t)
    t = re.sub(r"\([^)]*\)", " ", t)              # прочие пояснения в скобках
    t = re.sub(r"\b(?:версии|версия|версий|вер\.|ver\.?|version)\b", " ", t)
    t = t.replace("v.", " ").replace("–", "-").replace("—", "-")
    t = re.sub(r"\s+", " ", t).strip(" ,;.")
    return t


def _split_clauses(t: str) -> list[str]:
    # «до 9.6.22, от 10.0 до 10.17» и «4.0, 4.1, 4.2» — запятая/точка с запятой/«, а также»
    parts = re.split(r"\s*(?:[,;]|\s и\s(?=от |до ))\s*", t)
    return [p.strip() for p in parts if p.strip()]


def parse_bdu_versions(text: Optional[str]) -> Optional[list[Constraint]]:
    if not text:
        return None
    t = _clean(text)
    if not t or t in ("-", "?", "н/д", "нет данных"):
        return None
    result: list[Constraint] = []
    for clause in _split_clauses(t):
        clause = re.sub(r"\bвключ\.?$", "включительно", clause).strip()
        for pat, build in _PATTERNS:
            m = pat.match(clause)
            if m:
                result.append(build(m))
                break
        else:
            return None   # хотя бы одна часть не разобрана — вся строка в ручную проверку
    return result or None


def version_in(version: str, constraints: list[Constraint]) -> bool:
    return any(c.contains(version) for c in constraints)
