"""Шифрование секретов учётных записей (пароли, SNMP community) для хранилища УЗ.

Секреты в БД лежат только в зашифрованном виде (Fernet / AES-128-CBC+HMAC). Мастер-ключ
берётся из переменной окружения SURVEYSCAN_SECRET_KEY и в БД НЕ хранится — поэтому дамп
базы сам по себе пароли не раскрывает. Если переменная не задана, ключ генерируется и
кладётся файлом рядом с прикладной БД (в томе данных), с предупреждением в лог: для
продакшена задавайте SURVEYSCAN_SECRET_KEY явно (иначе ключ привязан к тому и теряется
вместе с ним).

SURVEYSCAN_SECRET_KEY может быть как готовым Fernet-ключом (44 символа urlsafe base64),
так и произвольной парольной фразой — из неё ключ выводится через SHA-256.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet

_fernet: Fernet | None = None


def _coerce_key(s: str) -> bytes:
    b = s.encode()
    try:
        Fernet(b)                 # уже валидный Fernet-ключ?
        return b
    except Exception:
        return base64.urlsafe_b64encode(hashlib.sha256(b).digest())   # вывести ключ из фразы


def _load_key() -> bytes:
    env = os.environ.get("SURVEYSCAN_SECRET_KEY")
    if env:
        return _coerce_key(env)
    kp = Path(os.environ.get("SURVEYSCAN_APP_DIR", "/tmp/surveyscan_app")) / "secret.key"
    kp.parent.mkdir(parents=True, exist_ok=True)
    if kp.exists():
        return kp.read_bytes().strip()
    key = Fernet.generate_key()
    kp.write_bytes(key)
    try:
        os.chmod(kp, 0o600)
    except OSError:
        pass
    print(f"[surveyscan] сгенерирован ключ шифрования УЗ -> {kp} "
          f"(для продакшена задайте SURVEYSCAN_SECRET_KEY)", flush=True)
    return key


def _f() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt(plain: str) -> str:
    return _f().encrypt((plain or "").encode()).decode()


def decrypt(token: str) -> str:
    return _f().decrypt((token or "").encode()).decode()
