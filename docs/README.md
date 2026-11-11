# Документация SurveyScan v2 — оглавление

## Читать сначала
1. [STATUS.md](STATUS.md) — где мы сейчас: пакеты, стенд, затыки, следующие шаги.
2. [Спецификация](specifications/go-asset-management-v2.md) — требования к продукту (версия 0.5, проект ТЗ).
3. [Целевая архитектура](architecture/go-target-architecture.md).
4. [План работ](plans/surveyscan-v2/README.md) — 50 пакетов по эпохам; [индекс задач](plans/surveyscan-v2/TASK_INDEX.md).

## Ветки репозитория
| Ветка | Назначение |
|---|---|
| `main` | Проверенное состояние. Обновляется только перемоткой (fast-forward) с `develop` после проверок |
| `develop` | Рабочая ветка: сюда идут все коммиты |
| `legacy/v1` | Прежняя Python-версия (сканер). В `main` не возвращается; её данные нужны для пакета C32 |
| `archive/*` | Замороженные ветки прежних сессий с неперенесёнными коммитами — только для справки |

## Справочно
| Что | Где |
|---|---|
| Пакеты плана (описание каждого) | [plans/surveyscan-v2/packages/](plans/surveyscan-v2/packages/) |
| Принятые решения (ADR) | [plans/surveyscan-v2/decisions/](plans/surveyscan-v2/decisions/) |
| Контракты и фикстуры по пакетам | [plans/surveyscan-v2/contracts/](plans/surveyscan-v2/contracts/) |
| Стенд на ВМ: запуск центра и агентов | [handoffs/C15-vm-stand-runbook.md](plans/surveyscan-v2/handoffs/C15-vm-stand-runbook.md) |
| Матрица замечаний к требованиям | [specifications/requirements-traceability-v0.5.md](specifications/requirements-traceability-v0.5.md) |
| Обзор аналогов | [research/inventory-platform-analogues.md](research/inventory-platform-analogues.md) |
| Кандидат релиза E1 | [releases/surveyscan-v2-e1-candidate.md](releases/surveyscan-v2-e1-candidate.md) |

## Архив и журналы (для истории, читать не обязательно)
| Что | Где |
|---|---|
| Журнал всех поручений и результатов (R-001…) | [REQUESTS.md](REQUESTS.md) |
| Передачи между сессиями | [plans/surveyscan-v2/handoffs/](plans/surveyscan-v2/handoffs/) — актуальная: [handoff-3](plans/surveyscan-v2/handoffs/C15-C24-session-handoff-3.md) |
| Доказательства прогонов (JSON) | [plans/surveyscan-v2/evidence/](plans/surveyscan-v2/evidence/) |
| Промпты сессий по пакетам | [plans/surveyscan-v2/prompts/](plans/surveyscan-v2/prompts/) |
| Прежние записи STATUS | [plans/surveyscan-v2/STATUS_HISTORY.md](plans/surveyscan-v2/STATUS_HISTORY.md) |
| История правил для ассистентов | [plans/surveyscan-v2/AGENTS_HISTORY.md](plans/surveyscan-v2/AGENTS_HISTORY.md) |

## Файлы в корне репозитория
- `README.md` — что это за проект.
- `AGENTS.md`, `CLAUDE.md` — инструкции для ИИ-ассистентов (правила работы, журналирования, карта кода). Людям читать не обязательно.
