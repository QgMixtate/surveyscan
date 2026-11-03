# Покрытие архитектуры 0.5 планом работ

Все строки — плановое покрытие, не результаты проверки. Семейство требований сопоставлено
с пакетами-владельцами; при выполнении конкретные test IDs и evidence добавляются в handoff.
В E1 проверяется минимальный объявленный профиль, полное покрытие — к соответствующей эпохе.

## Требования

| Семейство | ID требований | Пакеты-владельцы |
|---|---|---|
| ARC | ARC-01, ARC-02, ARC-03, ARC-04, ARC-05, ARC-06, ARC-07, ARC-08 | C01, C04, C13, C33 |
| SEC | SEC-01, SEC-02, SEC-03, SEC-04, SEC-05 | C05, C11, C24, C30, C40 |
| AM | AM-01, AM-02, AM-03, AM-04, AM-05, AM-06, AM-07, AM-08, AM-09, AM-10 | C02, C06, C25, C26, C27 |
| CM | CM-01, CM-02, CM-03, CM-04, CM-05 | C22, C26 |
| COL | COL-01, COL-02, COL-03, COL-04, COL-05, COL-06, COL-07, COL-08, COL-09, COL-10, COL-11, COL-12 | C08, C15, C16, C17, C18, C19, C24 |
| JOB | JOB-01, JOB-02, JOB-03, JOB-04, JOB-05, JOB-06, JOB-07, JOB-08 | C03, C07, C10, C12, C35 |
| PORT | PORT-01, PORT-02, PORT-03, PORT-04, PORT-05, PORT-06 | C23, C24 |
| PKG | PKG-01, PKG-02, PKG-03, PKG-04, PKG-05, PKG-06, PKG-07, PKG-08, PKG-09, PKG-10, PKG-11, PKG-12, PKG-13, PKG-14, PKG-15, PKG-16 | C03, C07, C10, C23, C24 |
| DB | DB-01, DB-02, DB-03, DB-04, DB-05, DB-06, DB-07 | C02, C04, C06, C32, C36 |
| SCALE | SCALE-01, SCALE-02, SCALE-03, SCALE-04, SCALE-05, SCALE-06, SCALE-07, SCALE-08, SCALE-09, SCALE-10 | C35, C36, C37, C38 |
| API | API-01, API-02, API-03, API-04, API-05, API-06 | C03, C05, C06, C07, C12, C31 |
| UI | UI-01, UI-02, UI-03, UI-04, UI-05, UI-06, UI-07, UI-08 | C09, C22, C26, C29 |
| OPS | OPS-01, OPS-02, OPS-03, OPS-04, OPS-05, OPS-06, OPS-07, OPS-08, OPS-09 | C04, C12, C13, C14, C33, C34, C39, C40 |
| MIG | MIG-01, MIG-02, MIG-03, MIG-04, MIG-05, MIG-06 | C32 |
| VAULT | VAULT-01, VAULT-02, VAULT-03, VAULT-04, VAULT-05, VAULT-06, VAULT-07, VAULT-08, VAULT-09 | C11, C17, C18, C19, C23, C39 |
| ID | ID-01, ID-02, ID-03, ID-04, ID-05, ID-06, ID-07 | C02, C06, C25, C37 |
| DISC | DISC-01, DISC-02, DISC-03, DISC-04, DISC-05, DISC-06, DISC-07, DISC-08 | C20, C21, C24 |
| NET | NET-01, NET-02, NET-03, NET-04, NET-05, NET-06 | C19, C22, C24 |
| OWN | OWN-01, OWN-02, OWN-03, OWN-04, OWN-05 | C06, C27, C42 |
| CLI | CLI-01, CLI-02, CLI-03, CLI-04, CLI-05, CLI-06 | C12, C23, C31 |
| EVT | EVT-01, EVT-02, EVT-03, EVT-04, EVT-05, EVT-06, EVT-07 | C03, C06, C10, C29, C35, C39 |
| SEARCH | SEARCH-01, SEARCH-02, SEARCH-03, SEARCH-04, SEARCH-05, SEARCH-06, SEARCH-07, SEARCH-08 | C28, C29, C35, C39 |
| GEO | GEO-01, GEO-02, GEO-03, GEO-04, GEO-05, GEO-06, GEO-07, GEO-08 | C37, C38, C39, C40 |
| WEB | WEB-01, WEB-02, WEB-03, WEB-04, WEB-05, WEB-06 | C09, C30, C35 |
| MOD | MOD-01, MOD-02, MOD-03, MOD-04, MOD-05, MOD-06, MOD-07, MOD-08, MOD-09 | C02, C04, C26, C35, C40 |
| PERF | PERF-01, PERF-02, PERF-03, PERF-04 | C30, C36, C40 |
| DEP | DEP-01, DEP-02, DEP-03, DEP-04, DEP-05, DEP-06, DEP-07, DEP-08 | C04, C35, C40 |
| AGT | AGT-01, AGT-02, AGT-03, AGT-04, AGT-05, AGT-06, AGT-07, AGT-08, AGT-09, AGT-10, AGT-11, AGT-12 | C08, C10, C11, C13, C15, C16, C24 |
| CON | CON-01, CON-02, CON-03, CON-04, CON-05, CON-06, CON-07, CON-08, CON-09, CON-10 | C10, C12, C13, C14, C24, C39 |
| INC | INC-01, INC-02, INC-03, INC-04, INC-05, INC-06, INC-07, INC-08 | C01, C14, C24, C33, C40, C41, C46 |

## Критерии приёмки

| AC | Пакеты реализации/проверки |
|---|---|
| AC-01 | C13, C14, C33 |
| AC-02 | C15, C16, C23, C24 |
| AC-03 | C10, C23, C24 |
| AC-04 | C23, C24 |
| AC-05 | C23, C24 |
| AC-06 | C08, C09, C14, C24 |
| AC-07 | C15, C16, C17, C18, C24 |
| AC-08 | C06, C10, C23, C24 |
| AC-09 | C05, C09, C12, C14, C24 |
| AC-10 | C23, C24 |
| AC-11 | C10, C23, C24 |
| AC-12 | C10, C24, C35 |
| AC-13 | C11, C14, C17, C18, C19, C23, C24 |
| AC-14 | C15, C16, C17, C18, C19, C24 |
| AC-15 | C25 |
| AC-16 | C06, C14, C25, C27 |
| AC-17 | C25, C26, C42 |
| AC-18 | C07, C10, C14, C23 |
| AC-19 | C13, C33, C39 |
| AC-20 | C32 |
| AC-21 | C09, C22, C26, C33 |
| AC-22 | C35, C36, C40 |
| AC-23 | C37 |
| AC-24 | C38, C40 |
| AC-25 | C11, C14 |
| AC-26 | C11, C23, C24 |
| AC-27 | C06, C14, C25, C37 |
| AC-28 | C06, C14, C27 |
| AC-29 | C12, C14, C31 |
| AC-30 | C20, C24 |
| AC-31 | C21, C24 |
| AC-32 | C06, C10, C14, C29 |
| AC-33 | C28, C29, C30 |
| AC-34 | C29 |
| AC-35 | C19, C24 |
| AC-36 | C22, C24 |
| AC-37 | C05, C29, C37 |
| AC-38 | C38, C39, C40 |
| AC-39 | C37, C38, C39, C40 |
| AC-40 | C09, C14, C30, C35 |
| AC-41 | C35, C40 |
| AC-42 | C02, C04, C26, C35, C40 |
| AC-43 | C30, C40 |
| AC-44 | C04, C35, C40 |
| AC-45 | C10, C24, C35, C39 |
| AC-46 | C08, C13, C14 |
| AC-47 | C10, C14 |
| AC-48 | C12, C14, C21 |
| AC-49 | C08, C11, C25 |
| AC-50 | C10, C14, C24 |
| AC-51 | C23, C24 |
| AC-52 | C05, C08, C11, C14 |
| AC-53 | C14 |
| AC-54 | C13, C14, C33 |
| AC-55 | C01, C14, C24, C40 |

## Волны 2 и 3

§25 и INC-08 не содержат полного утверждённого process scope/AC. C41 и C46 создают и согласуют
отдельные процессные спецификации/приёмку до реализации; C45 и C50 проверяют соответствующие волны.
Склад и ITSM не объявляются принятыми по техническим AC первой волны.

## Замечания U-01–19

| Замечание | Основные пакеты |
|---|---|
| U-01 local agent / collector / portable | C03,C07,C08,C10,C23 |
| U-02 OpenBao | C11,C17–19,C23,C39 |
| U-03 agentless / netdev | C17–19,C22,C24 |
| U-04 ER / asset_uid | C02,C06,C25–26,C37 |
| U-05 discovery / missing | C20–21,C24 |
| U-06 ответственность | C06,C27,C42 |
| U-07 API / CLI | C03,C05,C06,C12,C31 |
| U-08 geo shards | C37–40 |
| U-09 events без шины | C03,C06,C10,C29,C35 |
| U-10 FTS | C28–30,C35 |
| U-11 ЖЦ | C41–42,C45 |
| U-12 склад / запчасти / движение | C41,C43–45 |
| U-13 ITSM | C46–50 |
| U-14 отдельный Web UI | C09,C30,C35 |
| U-15 100 active users | C30,C35–36,C40 |
| U-16 модульность / последующее разделение | C02,C04,C26,C35,C40 |
| U-17 SMB→enterprise | C01,C08,C14 и последовательность эпох |
| U-18 непрерывная работа | C08,C10–14,C24,C35,C38–39 |
| U-19 аналоги | Исследование 0.5 как вход C01; уточнять только влияющие на текущий пакет вопросы |
