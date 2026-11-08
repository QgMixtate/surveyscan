# Текущее состояние surveyscan

8 ноября 2026. **57/200 done**, C15.02 in_progress; C01–C14 приняты в bounded Linux E1.
Ветка `codex/v2-c15-windows`, draft [PR5](https://github.com/QgMixtate/surveyscan/pull/5)
на базе draft E1 PR4. Код опубликован: `5fe78c5f844e6d1768fa343cdb64ed18178c5d1b`.
Main/release/production deploy/cloud settings не выполнялись.

## Последний CI: проверен через GitHub 08.11.2026

- v2 42309004958 / Web 42309004983 / native Linux boot 42309005065 /
  acceptance evidence 42309005140 — SUCCESS.
- Windows 42309005102 — FAILED: `TestAtomicReadersSeeWholeOldOrNewData`,
  `atomic_windows_test.go:149`, `atomic_rename code=5`. Причина пока не установлена.
  Предыдущий failed code32 сохранён; исправление bounded read retry не закрыло gate.
- Последний all5green private-root base — `c7e2f0a`; profile core — `4ff977f`.

## Реализовано и что дальше

C15 partial12/provider isolation/typed facts/relay/capabilities/profile1.2 core есть.
Private DACL/root-relative reads/create/exclusive lock проверены native Windows2022/elevated.
Atomic replace опубликован, но native gate failed; winstate ещё не подключён к runtime.
Windows continuous sender, durable cache/apply/ACK, host continuity, SCM/install/update,
ordinary rights/Windows11/reboot/full coverage ещё не приняты. Default inventory12 flag false.
SQL35/48ownedtables; applied0000–0034 immutable. C03/C09/C12 frozen.

Следующий шаг: разобрать atomic_rename code5, исправить и проверить exact-SHA CI,
затем bounded orphan recovery/privatefile+diskspool adapters/host binding/signed cache.
SCM C15.03/04 — после02acceptance. [Handoff](plans/surveyscan-v2/handoffs/C15.md),
[evidence](plans/surveyscan-v2/evidence/C15-winstate-atomic.json).

## Полный отчёт

[Word/PDF, схемы, спецификация и все 200 задач](reports/2026-11-08/README.md).
Архивный снимок на5fe78c5, 97 страниц PDF; 8 схем; FTS/geo/волны2–3 пока план.

E1 frozen24h/candidate сохранены: source8560f57/86400.914s;
authdelta39e401f/internal27files. Нового C15 24h, 100users/HA/geo/production SLA нет.
Не сбрасывать shared PG/Bao, не копировать ключи и не перезаписывать E1 reports.
