# Аналоги surveyscan: архитектурные паттерны и ограничения доказательств

Дата: 2026-11-03, Москва. Основание: R-011, исследование официальных репозиториев.
Цель — уточнить архитектуру постоянно работающего inventory/AM-продукта и этапы SMB → enterprise.
Это не закупочный рейтинг и не испытание продуктов. Бюджет/редакции для покупки не заданы.
Веса и баллы не применяются: без подтверждённых комплектаций и измерений итоговый рейтинг был бы необоснованным.

## 1. Метод и границы

Изучены официальные материалы Device42, GLPI/GLPI Agent, runZero и Snipe-IT.
Доказательства привязаны к конкретным Git commit SHA, прочитанным 3 ноября 2026.
Это снимки опубликованной документации/README, а не подтверждённые версии установленных продуктов.
У GLPI и Snipe-IT HEAD может содержать ещё не выпущенные возможности. Для пилота нужен конкретный stable release.

Сайты docs.device42.com, docs.lansweeper.com, www.runzero.com, glpi-agent.readthedocs.io,
snipe-it.readme.io, www.servicenow.com и www.securityvision.ru вернули отказ сетевого прокси 403.
Использованы разрешённые первичные источники GitHub; сетевые ограничения не обходились.
Lansweeper, ServiceNow и Security Vision ASSET остаются дополнительными кандидатами:
их актуальные возможности/редакции в этом исследовании не подтверждены. Прежний ответ из
вставленной переписки не считается свежим доказательством их функций.

Обозначения: **Д** — подтверждено прочитанной документацией; **В** — вывод для surveyscan;
**Н** — неизвестно/нужна проверка. «Д» не означает собственный прогон или гарантию поставщика.

## 2. Первичные источники

| ID | Прочитанный материал | Снимок / ограничения |
|---|---|---|
| G1 | [GLPI Agent: usage](https://github.com/glpi-project/doc-agent/blob/e64d61a89498bc52f3abc65e2295eac2598bf7c8/source/usage.rst) | managed, half-managed, autonomous; расписания, jitter, offline |
| G2 | [GLPI: Proxy Server Plugin](https://github.com/glpi-project/doc-agent/blob/e64d61a89498bc52f3abc65e2295eac2598bf7c8/source/plugins/proxy-server-plugin.rst) | агент → proxy → server; локальное сохранение, optional plugin |
| G3 | [GLPI: Remote inventory](https://github.com/glpi-project/doc-agent/blob/e64d61a89498bc52f3abc65e2295eac2598bf7c8/source/tasks/remote-inventory.rst) | agentless SSH/WinRM; серверное управление remotes ограничено по тексту этой версии |
| G4 | [GLPI: Network inventory](https://github.com/glpi-project/doc-agent/blob/e64d61a89498bc52f3abc65e2295eac2598bf7c8/source/tasks/network-inventory.rst) и [discovery](https://github.com/glpi-project/doc-agent/blob/e64d61a89498bc52f3abc65e2295eac2598bf7c8/source/tasks/network-discovery.rst) | SNMP, VLAN, topology, capabilities/credentials |
| G5 | [GLPI: карточка компьютера](https://github.com/glpi-project/doc/blob/f868e7fa28f87789a192d891fe9783dd485c47e6/source/modules/assets/computers.rst) | ручные locks, technician/group/user, UUID, last contact/inventory |
| G6 | [GLPI: расходники](https://github.com/glpi-project/doc/blob/f868e7fa28f87789a192d891fe9783dd485c47e6/source/tabs/consumables.rst), [компоненты](https://github.com/glpi-project/doc/blob/f868e7fa28f87789a192d891fe9783dd485c47e6/source/tabs/components.rst) | выдача пользователю/группе, возврат в stock, состав оборудования |
| D1 | [Device42: Remote Collector](https://github.com/device42/device42-docs/blob/03e4b8b332db860540a621556eed43f89ec86463/docs/auto-discovery/remote-collector-rc.mdx) | RC отдельно от Main Appliance, задания по расписанию, HTTPS, для Windows discovery требуется WDS |
| D2 | [Device42: Agent-Based Discovery](https://github.com/device42/device42-docs/blob/03e4b8b332db860540a621556eed43f89ec86463/docs/auto-discovery/agent-based-discovery.mdx) | optional agents, supported OS, service wrappers; ограничения RU/database discovery |
| D3 | [Device42: Offline Discovery](https://github.com/device42/device42-docs/blob/03e4b8b332db860540a621556eed43f89ec86463/docs/auto-discovery/agent-based-offline-discovery.mdx) | offline files + processing/upload utility; описанный utility Windows-based, совместимость от 15.14.04 |
| D4 | [Device42: API](https://github.com/device42/device42-docs/blob/03e4b8b332db860540a621556eed43f89ec86463/docs/integration/api-overview.mdx) | REST, create/update/retrieve, pagination/GET limits |
| D5 | [Device42: Warm HA](https://github.com/device42/device42-docs/blob/03e4b8b332db860540a621556eed43f89ec86463/docs/administration/appliance-manager/warm-ha-setup-failover-and-automated-backups.mdx) | standby и периодический restore backup; не доказательство нулевого RPO или multi-writer |
| R1 | [runZero: Custom Integrations README](https://github.com/runZeroInc/runzero-custom-integrations/blob/8675db4f2f56e8ba79c7de4a58bdacaf7355136a/README.md) | Console, постоянно работающие Explorers, offline CLI, active/passive/API, SaaS/on-prem; точные права редакций не проверены |
| R2 | [runZero Python SDK README](https://github.com/runZeroInc/runzero-sdk-py/blob/74a4a40b0545977c9661b87ced041c670dceada4/README.md) | org/site/task API, стабильный import id, runZeroID; указана Platform license для используемых API |
| S1 | [Snipe-IT README](https://github.com/snipe/snipe-it/blob/9ac7de97532d24bc6e10e6465127bfd2f2f242ad/README.md) | check-in/out, передача пользователям, granular roles, REST, backups, multi-company; README HEAD не заменяет release notes |
| G7 | [GLPI Agent README/license](https://github.com/glpi-project/glpi-agent/blob/56ae91dda38d74ce98cdfabaecf842b5983f5a6a/README.md) | пакеты Windows/macOS/Linux, Perl runtime, GPLv2+ для этого компонента |

## 3. Сравнение атомарных критериев

Приоритет М — обязательный сценарий surveyscan; Э — последующая эпоха. Неизвестное не оценивается как отсутствие функции.

| Критерий | Приоритет | Device42 | GLPI / Agent | runZero | Snipe-IT | Вывод для surveyscan / уверенность |
|---|---|---|---|---|---|---|
| Постоянная эксплуатация и расписания | М/E1 | Д: scheduled RC, agents; D1/D2 | Д: managed daemon/service; G1 | Д: Explorers как services; R1 | Д: постоянно работающий web asset register; автоматический host-cycle Н | В: постоянные источники, не только one-shot; высокая |
| Минимальный host agent → площадочный relay | М/E1 | Д: agents и RC; именно цепочка agent→RC Н | Д: managed agent + proxy plugin; G1/G2; это не гарантия end-to-end ACK | Д: Explorer; host agent этой роли Н | Н: host agent/relay не установлен по README | В: отдельные роли host agent и collector, проверить spool/ACK; высокая |
| Разовый offline-аудит | М/E2 | Д: файлы и processing tool; D3 | Д: autonomous + deferred upload; G1 | Д: offline CLI; R1 | Д: CSV import; эквивалент portable discovery Н | В: portable не является установленной постоянной службой; высокая |
| Безагентный сбор | М/E2 | Д: RC discovery; D1/D2; Windows WDS prerequisite | Д: SSH/WinRM и SNMP; G3/G4 | Д: active/passive/API как обзор, точный protocol matrix Н | Д: интеграции с MDM/RMM; собственный discovery Н | В: agent и agentless сосуществуют; высокая |
| Сетевые устройства и топология | М/E2 | Д: RC SNMP; глубина L2/L3 не проверена здесь | Д: SNMP, VLAN/topology; G4 | Д: network visibility; полная L2/L3 Н | Н | В: evidence/confidence, coverage по vendor; средняя |
| Идентичность при повторных импортах | М/E1–E3 | Д: настройки precedence/alias; D2; полный merge ADR Н | Д: UUID и import rules; G4/G5 | Д: stable source import id и runZeroID; R2 | Д: asset register; reconciliation semantics Н | В: source id ≠ canonical asset_uid; высокая |
| Freshness и источник данных | М/E1 | Н: подробная модель не проверена | Д: last contact отдельно от last inventory, G5 | Д: first/last seen import fields, R2 | Н | В: source health, inventory freshness и presence раздельны; высокая |
| Ответственность и ручные поля | М/E1+ | Н по выбранным страницам | Д: technician/group/user, manual locks; G5 | Н по выбранным страницам | Д: transfers и check-in/out; S1 | В: fallback team сразу, бизнес-поля не затирать; высокая |
| Документированный API | М/E1+ | Д: REST; D4 | Н: API GLPI в этом чтении не изучался | Д: API/SDK, Platform license caveat; R2 | Д: JSON REST; S1 | В: UI/CLI через общий API, права по операциям; высокая |
| HA / geo DR | Э/E5 | Д: warm standby из backups; D5; geo/residency/fencing/RPO Н | Н | Н | Д: backups; S1; HA/geo Н | В: backup не равен geo HA; не обещать RPO без опыта; высокая |
| Полнотекстовый движок / outbox / OpenBao | М по эпохам | Н | Н | Н | Н | Выбрано пользователем для surveyscan, не переносится из неподтверждённых аналогов |
| 100 активных пользователей | Э/E3+ | Н: сопоставимого теста нет | Н | Н | Н | Нельзя ранжировать без общего workload/данных/железа |

## 4. Эксплуатация, безопасность и стоимость

| Продукт / вариант | Подтверждённая особенность | Что требует отдельной проверки |
|---|---|---|
| Device42: Main Appliance + RC + optional agent | отдельные appliances/компоненты, Windows WDS, version coupling RC/MA по FAQ | точная редакция/модули, стоимость, hardening, backup RPO, география, поддержка и матрица обновления |
| GLPI + GLPI Agent + выбранные plugins | daemon/service и autonomous, proxy optional, Perl runtime, agent GPLv2+; поля ответственных и locks | stable GLPI/Agent/plugin matrix, поддержка, API/RBAC, HA/DR, данные реального vendor OID, стоимость сопровождения |
| runZero: Console + Explorers + CLI | SaaS/on-prem в R1; стабильные IDs, API; R2 указывает Platform license | текущие edition entitlements, пределы API и scans, geo/retention, RBAC/audit, стоимость и поддержка |
| Snipe-IT: self-hosted / hosted | web register, backups, REST, roles, перенос пользователю; README различает ограничения hosted integrations | текущая stable версия/лицензия, покрытие stock/parts и concurrency, HA/DR, границы сторонних discovery-интеграций, цены |

Сертификация и регуляторная применимость не подтверждены ни для одного кандидата; выводов о соответствии нет.
Численные лицензии, цена, TCO и пределы производительности не рассчитывались. Лицензия SDK
не является лицензией всей платформы; GPL Agent не означает автоматического права встроить его код в любой продукт.
В surveyscan заимствуются архитектурные идеи, исходники аналогов не копируются.
Некоторые старые примеры в vendor docs предлагают слабые настройки TLS/WinRM и передачу паролей
в аргументах. Они не перенесены в требования surveyscan: проверка TLS, ограниченные доступы и отсутствие
секретов в process list/logs остаются обязательными.

## 5. Что применить в surveyscan

1. **GLPI — основной референс разделения managed agent / autonomous audit / proxy.**
   Для нас явная цепочка agent→collector→center, минимальный агент и outbound-only соединение агента.
   Полный набор deployment/RMM функций GLPI не включать в минимального агента.
2. **Device42 — референс площадочного collector и разделения способов discovery.**
   Документировать зависимости протоколов и реальные поддержанные платформы. Offline utility
   проверять как отдельную поставку. Warm HA не выдавать за георезервирование без потерь.
3. **runZero — референс Console/Explorer/CLI и объединения источников.**
   Стабильные ID импортируемых записей, source provenance и first/last seen; неоднозначность не сливать автоматически.
4. **Snipe-IT и GLPI — референсы ответственности и будущих процессов волны 2.**
   Назначение ответственного требуется с E1; склад/выдачи/возвраты и сложный ЖЦ расширяются позже.

Это рекомендация набора референсов, а не выбор продукта-победителя. Она изменится при подтверждении
обязательных customer-сценариев, редакций и испытаний. Дополнительный приоритет — проверить
Lansweeper и Security Vision после предоставления доступной документации либо разрешения доменов.

## 6. Проверки, которые нужны перед заявлением паритета

- Постоянный агент и relay: restart, outage, reconnect storm, заполнение spool; отдельно receipt и applied ACK.
- Один хост через agent, SSH и portable: смена IP/имени, re-enrollment, клон VM, конфликт serial/UUID.
- Полное и неполное discovery: недоступная площадка не создаёт массовый missing.
- SNMP/topology: выбранные модели Cisco/Huawei; отличать LLDP от предположений по FDB.
- Нагрузка: одинаковые операции и данные, 100 одновременно активных пользователей плюс импорт; p95/p99, errors, ресурсы.
- Restore и update: UID, история, права, очереди, секреты; HA/DR с измеренным RPO/RTO и fencing.
- Процессы: назначение/передача ответственности; далее две конкурентные выдачи одной запчасти и восстановление остатков.

Пилоты не выполнялись. Документальные выводы учтены в спецификации 0.5; реализация не начата этим исследованием.
