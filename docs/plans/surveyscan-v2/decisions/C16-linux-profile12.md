# C16: платформа Linux внутри профиля инвентаризации 1.2 (вариант 1, решение пользователя)

Статус: **проект и план этапов; код контракта не менялся**. Решение пользователя: добавить платформу Linux внутри 1.2
(те же эндпоинты/подписи/batch 1.2), а не отдельную версию 1.3.

## Факты по текущему коду (на c71b6b8)
- `contracts.InventoryPolicy12 = "windows-amd64-partial-baseline-v1"`, `InventoryPlatform12 = "windows/amd64"` — константы;
  в схемах (`c15-profile.schema.json`, `c15-records.schema.json`, `c15.openapi.json`, зеркало в docs/.../contracts/C15) это `const`.
- Центр строит конфиг `InventoryConfigFromCommon12(common)` без знания платформы источника; агент в запросе профиля шлёт `platform`,
  центр её не сверяет.
- Ключи записей `recordKey12` (modules/inventory/records12.go) и схемы записей Windows-специфичны: software требует `registry_key`
  (+`scope`, `source`), users_groups — `sid`, routes/neighbors — `interface_index`.
- Схемы ведутся вручную и дублируются (docs ↔ v2/contracts), тесты сверяют копии.

## Что менять (этапы; каждый — отдельный проверяемый шаг)
1. **Политики/платформа.** `policy_id` и `platform` из `const` → `enum` {windows-amd64-partial-baseline-v1 / windows/amd64,
   linux-amd64-partial-baseline-v1 / linux/amd64}; Go: функции по платформе вместо констант; обе копии схем; тесты wire.
2. **Откуда центр знает платформу.** ОТКРЫТО: брать из запроса агента (подписан агентом, но самозаявлен) или из регистрации источника
   (enroll/`source_profile`). Рекомендация: хранить платформу при регистрации и сверять с запросом (несовпадение → отказ); нужна миграция
   (append-only, 0035+), обновление ожиданий schema/table/backup/boot по AGENTS.md.
3. **Записи Linux.** Схемы `c15-records.schema.json` + openapi: Linux-варианты секций (software: source=dpkg|rpm|apk, name, architecture;
   users_groups: kind user|group|membership с uid/gid, без пароля; routes_ports: interface name вместо index; resources: mount;
   hardware: cpu/memory/dmi). `recordKey12`: ветвление по платформе (software: source+name+architecture; users_groups: kind+uid/gid(+group);
   routes: destination+gateway+interface).
4. **Capabilities** (`c15-capabilities.schema.json`): раздельные Linux-возможности по секциям/правам.
5. **Агент.** Linux-цикл (`runLoop12` уже платформенно-нейтрален): подключение `linuxinventory` в `Collect`, чтение /proc, запрос профиля с
   `runtime.GOOS`, диск-спул и блокировки Linux уже есть (`lock_linux.go`).
6. **Проверка.** Go-тесты схем/ключей; compiled mTLS/PG relay как у Windows (center_smoke) для Linux; затем реальные дистрибутивы (C16.04/C24).

## Риски
Затрагивает подписанные контракты, центр и миграции; default `inventory12_enabled=false` сохраняется. Windows-контракт обязан остаться
байт-совместимым (регрессионный тест существующих фикстур). Старые applied-миграции 0000–0034 неизменны.

## Состояние
Этап 1–6: **не начаты**. Парсеры (`internal/agent/linuxinventory`) готовы и не подключены.
