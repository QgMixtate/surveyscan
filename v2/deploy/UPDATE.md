# C13 — ручное проверяемое обновление

Реализованы prepare/apply/recover/status, signed releases, persistent fence/journal и точная
проверка схемы. Process-controller rehearsal:19 checks passed с настоящими server/PG/TLS,
failed startup/rollback, SIGKILL и изолированной compiled schema34 fixture. Два независимых
Debian12/systemd VM прошли actual reboot и combined server/collector/agent update (9+9 checks).
Production KMS/HA/physical power loss остаются вне этой bounded E1 проверки.

Каждый новый bundle содержит `schema.json` из `surveyscan-server schema-catalog`:
ordered migration ID/owner/SHA256 точных embedded SQL bytes, без DB/SQL contents.
`schema-check` с private PG credentials требует точного совпадения DB ledger с бинарником.
Каталоги проверяются после подписи и сверяются с исполняемым schema-catalog до остановки сервиса.
Wire major и existing SQL prefix должны совпасть. Unit/sysusers changes требуют отдельной
установки и приёмки, не применяются переключением symlink. Первичная установка должна
иметь новые ConditionPathExists=!/opt/surveyscan/update.fence во всех server/migrate/collector/agent units.

```sh
python3 scripts/updater.py prepare --root / --bundle /private/verified-release \
  --public-key /trusted/release.pub
python3 scripts/updater.py status --root / --public-key /trusted/release.pub
python3 scripts/updater.py apply --root / --public-key /trusted/release.pub \
  --health-url https://server.example/health/ready --ca-file /trusted/https-ca.pem
```

Команды apply/recover CLI обслуживают выбранный combined server на systemd;
`--components server collector agent` добавляет совместно установленные службы. Server обязателен;
набор сохраняется в journal и должен совпадать при recover. Prepare/status
также работают на staging root. Operator root владеет program dirs; service users их не меняют.
Корневой URL readiness проверяется с TLS, redirects запрещены. HTTP допустим лишь по явному
флагу --dev-loopback-http и literal loopback. Нет паролей/token в argv/EnvironmentFile.
Transient schema-check/migrate tasks имеют User/Group surveyscan-server, LoadCredential PG
password, private UMask и sandbox properties. Transient D-Bus команды используют явный
`/run/credentials/<unique-unit>.service/pg_password`: expansion `%d` здесь не применяется.
Actual transient tasks и healthy-проверка каждой выбранной службы выполнены в двух VM.

Prepare проверяет новую подпись/bytes/modes, immutable version directory и каталог, публикует
кандидат, оставляя current и процессы на старой версии. Повтор точно той же signed версии
после rollback допускается; тихая подмена существующей версии и implicit downgrade запрещены.
Schema-changing update дополнительно требует `--checkpoint /private/common-checkpoint`,
проверенный через checkpoint.py; digest повторно сверяется перед apply. Полнота/согласованность
backup и отдельная recovery custody остаются operator prerequisite.

Apply удерживает общий flock, сохраняет fsync journal/fence, останавливает выбранные службы/migrate,
проверяет actual old DB schema, запускает candidate migrate, повторно проверяет новую схему,
атомарно переключает current, снимает gate и ждёт active+ready. Configs/keys/state не заменяются.
При failed startup сначала снова ставится gate и останавливается новый process. Возврат разрешён
только если actual DB точно подходит старому binary. Schema downgrade никогда не выполняется.
Если старая схема не совпадает или restart не удался, gate остаётся и journal= recovery_required.

```sh
python3 scripts/updater.py recover --root / --public-key /trusted/release.pub \
  --health-url https://server.example/health/ready --ca-file /trusted/https-ca.pem
```

Recover заново проверяет installed signatures и actual DB. Interrupted migrating/start выбирает
подходящую новую версию либо совместимую старую; unknown/drifted schema не запускает writers.
Не удалять gate/редактировать current вручную ради запуска несовместимого binary. Если ни один
каталог не подходит, использовать изолированное восстановление общего checkpoint по BACKUP.md.
Rolled_back и recovery_required возвращают ненулевой exitcode, даже если прежний сервис доступен.

`scripts/update_smoke.py` проверяет настоящие signed binaries/PG/TLS/version/login/UID,
неизменность private configs/TLS keys/artifact, запрет downgrade, bad-listen startup rollback,
actual SIGKILL после committed migrate0, durable fence/journal и recovery. Drift — явная test SQL
metadata fixture. Отдельный compiled candidate с test-only appended migration34 реально меняет
схему изолированной БД: проверяются обязательный checkpoint, committed DDL, отказ старого33
rollback и явное восстановление новой версии. В продуктовых SQL migration34 нет.
Real systemd controller и две свежие Debian12 VM проверены; physical power loss ещё unrun. Проверка C11→current
реальных миграций отдельно в upgrade_smoke.py. Legacy unsigned staging не считается установкой.
