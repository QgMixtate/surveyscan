"""Общие настройки тестов: изолированная прикладная БД задач/коннекторов."""
import os
import tempfile

# один каталог-метка на сессию -> стабильная, но отдельная от прода прикладная БД
os.environ.setdefault("SURVEYSCAN_APP_DIR", tempfile.mkdtemp(prefix="surveyscan-apptest-"))
