# C13.01 — Linux/systemd staging (в работе)

Units предназначены для Debian/Ubuntu Linux, systemd>=252. Это шаблоны и staging,
не завершённая production установка. Host managed среды не PID1systemd; службы на нём не ставятся.
Windows service — C15. PostgreSQL17 и OpenBao2.7.2 executable — внешние prerequisites.

`python scripts/stage_install.py --root /absolute/empty/staging`
копирует только четыре `.dist` бинарника, public contracts, отдельный `web/dist`, unit/sysusers files.
Root должен быть пустым; `/` запрещён. Existing data/configs не заменяются. Результат development/unsigned,
не release: C13.02 ещё должен добавить versioned manifest/checksums/SBOM/signature и checked update.
Program/unit dirs0755/0644; binaries0755; state0700. Sysusers/root ownership и StateDirectory chown
применяются только при настоящей установке на целевой машине, stage их на host не выполняет.

На целевой системе оператор создаёт accounts через sysusers и конфиги/DB/PKI; private source config0600
загружается PID1 через LoadCredential, приложение читает %d/config, не root-owned sourcefile.
Agent/collector state содержит persistent origin key/identity/queues (private0700). Не копировать их
вgolden image и не запускать второй writer. Initial prepare/enroll должны выполняться под тем же
service user и с private config, например отдельным systemd-run oneshot с теми же StateDirectory/
LoadCredential properties. Grant file — отдельный краткоживущий credential, не argv value и не image.
Оператор проверяет CA/public pins и source/collector assignment до запуска run-службы.

Server требует root-provided /etc/surveyscan-server/server.env (без паролей в URL), PG password,
machine.json, bao.json, scoped bao_token и server.key. LoadCredential даёт приложению private копии;
вmachine.json надо ссылаться на /run/credentials/surveyscan-server.service/server_key и /bao_config,
а вbao.json token_file=/run/credentials/surveyscan-server.service/bao_token. Public CA/certificate paths
могут быть в /etc/surveyscan-server с0644; JSON/privatekey/token sourcefiles0600. Никакогоroot Bao token
вapp. Actualproduction TLS issuance/listener configs оператор готовит отдельно; loopback bootstrap
изC11 не считать production certificate. Изменение LoadCredential требует restart для перечитывания.

Migrate oneshot uses тот же PG secret, After/Requires postgresql.service; server Requires migrate.
Это выбранный local PostgreSQL system installation path, не настройка remoteDB. Миграция выполняется
перед serverstart и drift не игнорируется. Upgrade/rollback data procedure ещё C13.02/03, не просто
symlink rollback после изменённой schema. Snapshot/keys/Bao state не пересоздавать ради установки.

Bao unit запускает собственный binary и Raft directory /var/lib/surveyscan-bao. HCL оператор должен
задать HTTPSlistener/publiccert+LoadCredential listener_key path,privateRaft/audit paths иcustody.
Service auto-start не означает auto-unseal: после cold restart без externalKMS требуется authorized
operator unseal. App может читать publicregistry/spool при sealedBao,но keyops не готовы.
Не хранить recovery/unseal/root материал у app UID и не писать unseal key вunit/EnvironmentFile.
Auto-unseal/KMS и recovery должны быть выбраны/проверены отдельно; сейчас этого нет.

`python scripts/unit_check.py` проверяет четыре app/migrate unit реальным system-mode
systemd-analyze в одноразовом networkless/read-only/cap-drop container. В него копируются только public
parser/libs/targets и собственный staged filesystem. Bao unit не проверяет внешний binary/runtime.
Это статическая проверка, НЕ реальные boot/reboot/services/PG/Bao starts. Нет production/systemd/DR claim.
Для C13.01 done нужен отдельный clean boot stand; затем C13.02 release,03backup/restore,04repeatability.
