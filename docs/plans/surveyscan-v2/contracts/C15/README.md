# C15.02 — черновик observation 1.2

Изолированный аддитивный контракт для 12 Windows inventory sections. C03/C09 не изменены;
этот файл пока не включён в Go validator, upload, projection или detail API. Старый runtime
не принимает новый inventory. C15.02 не завершён до сквозной реализации и настоящего Windows сбора.

Schema version 1.2 относится к observation, не к C12 profile/receipt/enrollment. Используются
прежние origin/source/generation/UID/sequence правила. Новые receipt capabilities и detail API
ещё предстоит спроектировать; без согласованной поддержки collector + center агент не отправляет 1.2.
Это не изменение immutable C03 compatibility policy задним числом.

Каждый полный снимок содержит ровно 12 разных секций; отключённые обозначаются not_requested.
`record_count == len(records)` и уникальность имён — дополнительные обязательные semantic checks
в validate.py и будущей Go реализации. Для unavailable/unsupported/not_requested/unknown
records пусты и complete=false; partial сохраняет доступные rows и имеет complete=false.
Достоверный ok требует complete=true, но может содержать пустой список в заявленном scope.
Wire `coverage` уточняет machine/current-user, QFE subset и локальный neighbor cache.

Поля записей типизированы, дополнительные поля запрещены; raw command_line/password не разрешены.
Это не замена runtime secret filtering, IP/SID validation и объектных ACL. Неизвестные значения
не заполняются выдуманными строками. Large integer facts ограничены безопасным JCS диапазоном;
ограничение числа rows не разрешает превышать общий лимит bytes/admission/spool.
Окончательные transport limits/negotiation и per-field semantic checks ещё в работе.

Проверка из корня репозитория:

```sh
python docs/plans/surveyscan-v2/contracts/C15/validate.py
```

Нужен jsonschema 4.x. Fixtures синтетические: 7 положительных, 12 отрицательных, включая
independent section failure, старую версию, missing/duplicate section, count mismatch,
несовместимые status/complete/records, raw command line, неизвестное поле и unsafe integer.
Нет Windows API, HTTP, подписи/JCS, БД, SCM, reboot или проверки реальных привилегий.
