"""Нормализация имён ПО и словарь синонимов «пакет / продукт ↔ название в БДУ»."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

_TRASH = re.compile(r"[™®©]")
_NON_ALNUM = re.compile(r"[^0-9a-zа-я]+")


def norm_name(s: str) -> str:
    s = _TRASH.sub("", (s or "").lower().replace("ё", "е"))
    return _NON_ALNUM.sub(" ", s).strip()


@dataclass
class Product:
    key: str
    bdu: list[str]
    packages: list[re.Pattern] = field(default_factory=list)
    windows: list[re.Pattern] = field(default_factory=list)
    services: list[re.Pattern] = field(default_factory=list)
    vendors: list[str] = field(default_factory=list)


class Catalog:
    """Загружает rules/products.yaml и отвечает на вопрос «какие названия БДУ соответствуют этому ПО»."""

    def __init__(self, path: Path):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self.products: list[Product] = []
        for key, p in (data.get("products") or {}).items():
            self.products.append(Product(
                key=key,
                bdu=[norm_name(x) for x in p.get("bdu", [key])],
                packages=[re.compile(f"^(?:{x})$", re.I) for x in p.get("packages", [])],
                windows=[re.compile(x, re.I) for x in p.get("windows", [])],
                services=[re.compile(x, re.I) for x in p.get("services", [])],
                vendors=[norm_name(v) for v in p.get("vendors", [])],
            ))
        self.ignore = [re.compile(f"^(?:{x})$", re.I) for x in data.get("ignore_packages", [])]

    def _ignored(self, name: str) -> bool:
        return any(rx.match(name) for rx in self.ignore)

    def for_package(self, name: str) -> tuple[Optional[str], list[str]]:
        """Пакет ОС (deb/rpm) -> (ключ продукта или None, названия в БДУ)."""
        if self._ignored(name):
            return None, []
        for p in self.products:
            if any(rx.match(name) for rx in p.packages):
                return p.key, p.bdu
        # запасной вариант: имя пакета совпадает с названием в БДУ
        return None, [norm_name(name)]

    def for_windows(self, display_name: str) -> tuple[Optional[str], list[str]]:
        for p in self.products:
            if any(rx.search(display_name) for rx in p.windows):
                return p.key, p.bdu
        # «Notepad++ 8.6.2 (64-bit x64)» -> «notepad»; берём часть до первой цифры версии
        base = re.split(r"\s+v?\d", display_name, maxsplit=1)[0]
        return None, [norm_name(base)]

    def for_service(self, product: str) -> tuple[Optional[str], list[str]]:
        for p in self.products:
            if any(rx.search(product) for rx in p.services):
                return p.key, p.bdu
        return None, [norm_name(product)]
