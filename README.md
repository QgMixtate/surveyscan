# SurveyScan

Платформа постоянной инвентаризации и реестра ИТ-активов на Go. Код — в [`v2/`](v2/), документация и план — в [`docs/`](docs/).

Прежняя версия (v1, Python-сканер с nmap и разовыми отчётами) выведена из основной линии; её код остаётся в истории git (коммит bd26e78). Перенос данных v1 не нужен
(решение 2026-11-12, пакет C32 — «не требуется»).

## Что это

Постоянный реестр вместо разовых сканов: данные поступают непрерывно и сводятся в карточку актива с историей и происхождением.

- **Источники данных:** постоянный агент на Linux (systemd) и Windows (служба SCM); площадочный collector; безагентный сбор по SSH, WinRM и SNMPv3; разовый portable-аудит без установки службы (файл или HTTPS-загрузка).
- **Центр:** приём подписанных наблюдений (mTLS, Ed25519), сопоставление с активами (в т.ч. автоматическое сведение по сильным идентификаторам), проекции фактов, история, outbox и аудит; секреты и ключи — в OpenBao.
- **Интерфейсы:** отдельный Web UI (реестр, карточка актива с инвентаризацией из 12 разделов, источники, **схема сети L3**), CLI `surveyscanctl`, HTTP API с JSON-Schema-контрактами.
- **Стек:** Go 1.27, PostgreSQL 17, OpenBao 2.7, React 19 + TypeScript (без CDN, закрытый контур), nginx; dev-стенд на Docker Compose.

Документация — [оглавление docs/](docs/README.md). Главное:
- [Текущее состояние](docs/STATUS.md) — где мы сейчас, затыки, следующие шаги
- [Спецификация](docs/specifications/go-asset-management-v2.md) и [план работ](docs/plans/surveyscan-v2/README.md)
- [Сборка и dev-стенд v2](v2/README.md), [стенд на ВМ](docs/plans/surveyscan-v2/handoffs/C15-vm-stand-runbook.md)

Ветки: `main` — проверенное состояние, `develop` — рабочая (все коммиты идут сюда).
Файлы `AGENTS.md` и `CLAUDE.md` в корне — инструкции для ИИ-ассистентов, которые ведут разработку.

Быстрый просмотр продукта на одной машине (настоящий центр + Web UI + демо-данные):

```sh
cd v2
python3 -m venv .contract-tools && .contract-tools/bin/pip install -r ../docs/plans/surveyscan-v2/contracts/C03/checks/requirements.txt
make build && (cd web && npm ci && npm run build) && python3 scripts/dev.py up
.contract-tools/bin/python scripts/demo_stand.py   # нужен Chromium для Playwright; скриншоты и вывод CLI — в v2/.local/demo
```
