# Индекс чатов surveyscan v2

Архитектура 0.5, 50 пакетов / 200 подзадач. C01–C03 — документы/контракты; C04 — локальный Go-каркас, PG/Bao/proxy и проверки. C05 — локальный auth/tenant scope; C06 — локальный реестр/outbox; C07 — локальный collector/upload; C08 — live Linux host agent/heartbeat; C09 — отдельный Web UI/detail API; C10 recovery готов локально; C11 OpenBao/renewal принят локально, C12 CLI/profiles/diagnostics/operator готов локально; C13 done bounded E1; C14.01 in_progress; C14.02–C50 planned.
Один пакет ≈ один чат с возможным продолжением .a/.b. Вход — указанные зависимости с evidence.
Не читать все 50 подробных файлов: выберите текущий ID и его spec sections.

| Чат | Эпоха | Задача | Зависит от | Старт | Статус |
|---|---|---|---|---|---|
| [C01](packages/C01.md) | E0 | Границы первого релиза и карта решений | — | [Запрос](prompts/C01.md) | done (документы) |
| [C02](packages/C02.md) | E0 | Минимальная ER-модель и владение данными | C01 | [Запрос](prompts/C02.md) | done (документы) |
| [C03](packages/C03.md) | E0 | Контракты обмена и состояния доставки | C02 | [Запрос](prompts/C03.md) | done (контракты) |
| [C04](packages/C04.md) | E1 | Go-каркас и воспроизводимый dev-стенд | C03 | [Запрос](prompts/C04.md) | done (локально) |
| [C05](packages/C05.md) | E1 | Пользователи, tenant scope и базовая авторизация | C04 | [Запрос](prompts/C05.md) | done (локально) |
| [C06](packages/C06.md) | E1 | Постоянный реестр, история и outbox | C05 | [Запрос](prompts/C06.md) | done (локально) |
| [C07](packages/C07.md) | E1 | Площадочный collector и приём результатов | C06 | [Запрос](prompts/C07.md) | done (локально) |
| [C08](packages/C08.md) | E1 | Минимальный host agent и первый живой цикл | C07 | [Запрос](prompts/C08.md) | done (локально) |
| [C09](packages/C09.md) | E1 | Отдельный Web UI и базовая карточка | C06 | [Запрос](prompts/C09.md) | done (локально) |
| [C10](packages/C10.md) | E1 | Долговечная доставка и восстановление | C08 | [Запрос](prompts/C10.md) | done (локально) |
| [C11](packages/C11.md) | E1 | OpenBao и жизненный цикл машинных доступов | C10 | [Запрос](prompts/C11.md) | done (bounded E1) |
| [C12](packages/C12.md) | E1 | CLI, управление циклом и наблюдаемость | C09, C11 | [Запрос](prompts/C12.md) | done (local E1) |
| [C13](packages/C13.md) | E1 | Установка, сервисы, обновление и backup | C12 | [Запрос](prompts/C13.md) | done bounded E1 (two native VM9 + updater19) |
| [C14](packages/C14.md) | E1 | Приёмка и выпуск первого рабочего SMB | C13 | [Запрос](prompts/C14.md) | in_progress (01 matrix) |
| [C15](packages/C15.md) | E2 | Постоянный Windows-агент | C14 | [Запрос](prompts/C15.md) | planned |
| [C16](packages/C16.md) | E2 | Постоянный Linux-агент и platform parity | C14 | [Запрос](prompts/C16.md) | planned |
| [C17](packages/C17.md) | E2 | Безагентный SSH-сбор Linux | C14 | [Запрос](prompts/C17.md) | planned |
| [C18](packages/C18.md) | E2 | Безагентный WinRM-сбор Windows | C14 | [Запрос](prompts/C18.md) | planned |
| [C19](packages/C19.md) | E2 | SNMP и read-only сбор сетевых устройств | C14 | [Запрос](prompts/C19.md) | planned |
| [C20](packages/C20.md) | E2 | Многоисточниковое discovery | C17, C18, C19 | [Запрос](prompts/C20.md) | planned |
| [C21](packages/C21.md) | E2 | Presence и обнаружение пропавших/вернувшихся | C20 | [Запрос](prompts/C21.md) | planned |
| [C22](packages/C22.md) | E2 | Доказательная топология L2/L3 | C19, C20, C21 | [Запрос](prompts/C22.md) | planned |
| [C23](packages/C23.md) | E2 | Portable-аудит и безопасный offline-пакет | C10, C11, C17, C18, C19 | [Запрос](prompts/C23.md) | planned |
| [C24](packages/C24.md) | E2 | Приёмка агентного и безагентного сбора | C15, C16, C22, C23 | [Запрос](prompts/C24.md) | planned |
| [C25](packages/C25.md) | E3 | Полная reconciliation, merge и split | C24 | [Запрос](prompts/C25.md) | planned |
| [C26](packages/C26.md) | E3 | AM/CMDB, ПО, компоненты и связи | C25 | [Запрос](prompts/C26.md) | planned |
| [C27](packages/C27.md) | E3 | Полная ответственность и оргструктура | C26 | [Запрос](prompts/C27.md) | planned |
| [C28](packages/C28.md) | E3 | PoC полнотекстового поиска: Tantivy / Bluge | C25 | [Запрос](prompts/C28.md) | planned |
| [C29](packages/C29.md) | E3 | Поисковая проекция, API и UI | C26, C28 | [Запрос](prompts/C29.md) | planned |
| [C30](packages/C30.md) | E3 | Нагрузка 100 активных пользователей и E3 приёмка | C27, C29 | [Запрос](prompts/C30.md) | planned |
| [C31](packages/C31.md) | E4 | Интеграции и внешние контракты | C30 | [Запрос](prompts/C31.md) | planned |
| [C32](packages/C32.md) | E4 | Миграция данных Python v1 | C30 | [Запрос](prompts/C32.md) | planned |
| [C33](packages/C33.md) | E4 | Промышленная поставка и сопровождение | C31, C32 | [Запрос](prompts/C33.md) | planned |
| [C34](packages/C34.md) | E4 | Пилот, внедрение и стабилизация | C33 | [Запрос](prompts/C34.md) | planned |
| [C35](packages/C35.md) | E5 | Раздельные API/worker и несколько экземпляров | C34 | [Запрос](prompts/C35.md) | planned |
| [C36](packages/C36.md) | E5 | Пул SQL, индексы и эксплуатация PG | C35 | [Запрос](prompts/C36.md) | planned |
| [C37](packages/C37.md) | E5 | Каталог шардов и перенос tenant | C36 | [Запрос](prompts/C37.md) | planned |
| [C38](packages/C38.md) | E5 | HA PostgreSQL и георезервирование | C37 | [Запрос](prompts/C38.md) | planned |
| [C39](packages/C39.md) | E5 | Восстановление всего контура | C38 | [Запрос](prompts/C39.md) | planned |
| [C40](packages/C40.md) | E5 | Enterprise-приёмка и критерии выделения сервисов | C39 | [Запрос](prompts/C40.md) | planned |
| [C41](packages/C41.md) | W2 | Процессы ЖЦ и модель склада | C30 | [Запрос](prompts/C41.md) | planned |
| [C42](packages/C42.md) | W2 | Жизненный цикл и передачи активов | C41 | [Запрос](prompts/C42.md) | planned |
| [C43](packages/C43.md) | W2 | Склад, партии, резервы и остатки | C41 | [Запрос](prompts/C43.md) | planned |
| [C44](packages/C44.md) | W2 | Запчасти, ремонт и движение компонентов | C42, C43 | [Запрос](prompts/C44.md) | planned |
| [C45](packages/C45.md) | W2 | Физическая инвентаризация и приёмка волны 2 | C44 | [Запрос](prompts/C45.md) | planned |
| [C46](packages/C46.md) | W3 | Модель ITSM и каталог услуг | C45 | [Запрос](prompts/C46.md) | planned |
| [C47](packages/C47.md) | W3 | Инциденты и проблемы | C46 | [Запрос](prompts/C47.md) | planned |
| [C48](packages/C48.md) | W3 | Запросы обслуживания и портал | C46 | [Запрос](prompts/C48.md) | planned |
| [C49](packages/C49.md) | W3 | Изменения и влияние на услуги | C47, C48 | [Запрос](prompts/C49.md) | planned |
| [C50](packages/C50.md) | W3 | SLA, интеграции и приёмка ITSM | C49 | [Запрос](prompts/C50.md) | planned |
