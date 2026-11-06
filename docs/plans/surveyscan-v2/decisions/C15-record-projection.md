# C15.02 — проекция частичных records observation 1.2

Отдельная миграция0033_records12 добавляет record_facts12 и record_section_state12.
Текущий C15 catalog34/47owned tables (48 with ledger); E1/frozenC14 остаётся33/45.
Применённые SQL0000–0032 и C03/C09 contracts не менялись. Downgrade старым binary
после добавленной миграции запрещён checksum/schema check; update требует checkpoint.

ProjectPartial12 — внутренний primitive, HTTP/collector/runtime его ещё не вызывают.
Caller обязан проверить подпись, tenant/source binding/continuity, сохранить immutable
observation, создать asset link и обычные history/audit/outbox в той же transaction.
PG тесты отдельно создают signed synthetic evidence и откатывают transaction;
это не доказательство signed1.2delivery или admission. C15.02 остаётся in_progress.

Полный draft Payload validator до SQL, duplicate locators reject до writes.
Принимаются только partial/unavailable/unsupported/not_requested, complete=false.
Нет DELETE и утверждения о полном покрытии. Факт — отдельное JSON поле с собственными
observation_id/link_id и revision: пропущенное поле сохраняет старое происхождение.
Секция хранит last attempt/status/clock; успешная полная коллекция здесь не моделируется.
Тот же source/generation/record сравнивается по uint64 sequence; между sources —
существующий trusted clock/priority/time rank. Skewed/future sections не проецируются.
Transaction advisory lock tenant/asset сериализует даже первые inserts; запросы и FK
всегда включают tenant. Старые C09 tables/reads не получают новых rows.
Legacy Project()/flatten() теперь явно отвергают неизвестные sections, включая пустые.

## Provider locators (SHA256 от JCS object с явными именами полей)

| Секция | Ключ внутри asset/section |
|---|---|
| identity, os | singleton host |
| network | interface name |
| hardware, resources | kind + name |
| software | source + scope + registry_view + registry_key + principal_sid |
| updates | source + KB/id |
| services | service name |
| users_groups | kind + SID; membership также group SID |
| routes_ports | kind + family + destination/gateway/interface или socket endpoints/interface |
| protection | kind + provider + name |
| neighbors | family + interface_index + address |

Это provider locators, не глобальные/persistent component UID и не asset_uid.
Name/ifindex/endpoint смена даёт новый locator; старые partial rows пока сохраняются.
Неоднозначные одинаковые locators (даже одинаковые rows) отвергаются, не схлопываются.
В ПО нельзя использовать mutable version/vendor/display name как identity. Новый draft
требует Uninstall registry_key; HKCU дополнительно current token principal_sid, machine
записи не могут содержать principal_sid. Native adapter читает только собственный HKCU,
не загружает другие hives. Registry key/service name сравниваются без учёта регистра.
Упавшее чтение token SID исключает только HKCU baseline; machine rows остаются partial.

Проверки: 12секций, typed fields, mutable field key stability, duplicate/complete failclosed,
software principal separation, сохранение old field provenance, late sequence rejection,
unavailable provider preservation, tenant predicate, неизменный C09 detail. Реальный PG
upgrade33→34 сохраняет старые evidence/facts/assets/ledger bytes; повторное применение0.
Полные field/coverage semantics, negotiated envelopes/limits, versioned paginated API,
concurrent collection/heartbeat, Windows rights/service/reboot ещё остаются gates.
