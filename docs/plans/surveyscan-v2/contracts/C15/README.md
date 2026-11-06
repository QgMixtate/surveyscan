# C15.02 — черновик observation 1.2

Изолированный аддитивный контракт для 12 Windows inventory sections. C03/C09 не изменены;
контракт включён только в отдельный Go payload validator; upload, projection и detail API
остаются прежними. Старый runtime
не принимает новый inventory. C15.02 не завершён до сквозной реализации и настоящего Windows сбора.

Schema version 1.2 относится к observation, не к C12 profile/receipt/enrollment. Используются
прежние origin/source/generation/UID/sequence правила. Новые receipt capabilities и detail API
ещё предстоит спроектировать; без согласованной поддержки collector + center агент не отправляет 1.2.
Это не изменение immutable C03 compatibility policy задним числом.

Каждый полный снимок содержит ровно 12 разных секций; отключённые обозначаются not_requested.
`record_count == len(records)` и уникальность имён — дополнительные обязательные semantic checks
в validate.py и будущей Go реализации. Для unavailable/unsupported/not_requested
records пусты и complete=false; partial сохраняет доступные rows и имеет complete=false.
Достоверный ok требует complete=true, но может содержать пустой список в заявленном scope.
Wire `coverage` уточняет machine/current-user, QFE subset и локальный neighbor cache.

Поля записей типизированы, дополнительные поля запрещены; raw command_line/password не разрешены.
Go payload validator дополнительно проверяет IP/family/prefix, время секции, uint64 sequence,
JCS, duplicate keys и общий лимит1MiB. Это не замена runtime secret filtering, SID validation и объектных ACL. Неизвестные значения
не заполняются выдуманными строками. Large integer facts ограничены безопасным JCS диапазоном;
ограничение числа rows не разрешает превышать общий лимит bytes/admission/spool.
Лимит1MiB изолированного валидатора не расширяет прежний64KiB signed payload или batch admission:
окончательные transport limits/negotiation и остальные per-field semantic checks ещё в работе.
Status unknown остаётся только в старом import формате; native observation1.2 его не отправляет.

Проверка из корня репозитория:

```sh
python docs/plans/surveyscan-v2/contracts/C15/validate.py
```

Зависимости зафиксированы в requirements.txt (jsonschema + RFC3339 validator). Fixtures синтетические: 8 положительных, 16 отрицательных, включая
independent section failure, старую версию, missing/duplicate section, count mismatch,
несовместимые status/complete/records, raw command line, неизвестное поле и unsafe integer.
Нет Windows API, HTTP, подписи/JCS, БД, SCM, reboot или проверки реальных привилегий.

Изолированный Go validator: `NewInventory12().Payload`, 3 новых top-level tests,
19 corpus subtests,7 semantic counterexamples и3 malformed/duplicate/oversize probes.
Он не вызывается production handlers и не проверяет подпись, scope authorization или UID adoption.
Старый validator явно отвергает новые valid payloads; bytes C03/C09 сохранены.

Hosted Windows первый запуск42125403759 на bb5c344 failed до Go/version: Python
прочитал UTF-8 fixtures через cp1252. Исправлено явным UTF-8; repeat требуется.
Это дефект нового checker, а не пройденная проверка native inventory.

C15 draft software rows now require registry_key (Uninstall subkey); current_user also requires
principal_sid from the current token. Machine rows cannot carry principal_sid. These are
provider-local locators, not asset_uid. Historical 19-fixture evidence stays historical; current corpus24.
