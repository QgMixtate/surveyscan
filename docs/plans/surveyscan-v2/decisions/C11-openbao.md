# C11 — scoped OpenBao и хранение ключей

2026-11-04 (Москва). Локально реализовано; production deployment не выполнялся.
Bao 2.7.2 Raft из C04, PG17, Go1.27.3. TLS leaf issuer использует Transit через
crypto.Signer: CA и ключ подтверждений Ed25519 non-exportable, plaintext backup запрещён.
Это узкий X.509 issuer поверх Transit, не включение OpenBao PKI secrets engine.

## Bootstrap и минимальная политика

Оператор один раз инициализирует Bao, распределяет Shamir shares между хранителями,
сохраняет recovery material отдельно от приложения и проверяет unseal. C04 локально
использует один share в ignored private .local/bao-init.json: это исключительно dev,
не образец production custody. Существующие тома/ключи не сбрасывать.

Оператор создаёт отдельные Transit keys ca/center (type ed25519, exportable=false,
allow_plaintext_backup=false) и KV v2 mount. Scoped periodic renewable service token
содержит одну application policy; приложение отвергает root/посторонние/identity policies.
Ключи, версии и public pins заранее задаются оператором в private JSON profile.
Reference alias не принимается из клиентского API. Никаких паролей/токенов в PG.
Минимальная policy: read auth/token/lookup-self, update auth/token/renew-self,
update <transit>/sign/ca и /sign/center, read <transit>/keys/ca и /keys/center,
read ровно <kv>/data/server/runtime. Нет wildcard, export, sys/mounts, иных KV/keys.
Рабочий пример provisioning/policy: v2/scripts/bao_fixture.py (только local tests).
Root используется только оператором тестового стенда, никогда сервером/issuer command.

Приложению передаются только scoped token file0600 и private config0600. Token читается
перед каждой операцией, проверяется lookup-self; TTL<60s вызывает renew-self.
Фоновая проверка каждые30s поддерживает lease при отсутствии запросов. Оператор заменяет
scoped token file атомарно, приложение подхватывает его без restart. Нельзя выдавать
приложению права создавать/расширять собственную policy. На production root/unseal material
вообще отсутствует у app UID/контейнера; dev harness под одним UID этого не доказывает.

Config содержит address, tls_ca_file, token_file, policy, transit_mount, kv_mount,
keys {ca,center:{name,version,public_key}}, secrets {alias:{path,field}}. Public key —
base64url без padding. Значения секретов не кэшируются и не сериализуются в отчёты.
HTTPS проверяет system/custom CA, TLS>=1.2, redirects запрещены. HTTP допустим только
явным dev_loopback_http на loopback и при machine dev_mode=true. В production этот
флаг не разрешает HTTP. Скрипты тестируют loopback HTTP, реальный HTTPS Bao ещё unrun.

Операторская dev-команда bootstrap-issuer --config <private.json> --output-directory <newdir>
создаёт только public ca.pem/server.pem и local TLS server.key0600 (24h loopback leaf).
CA/receipt private keys не экспортирует; existing files не перезаписывает. Это dev bootstrap,
не production DNS/certificate rotation. Machine config: openbao_config_file и UUID
center_signing_key_id; ca_private_key_file/center_signing_key_file обязаны отсутствовать.
Закреплённые public CA/center pins проверяются; CA и receipt keys различаются.

## Отказ и аудит

При sealed/unreachable/denied Bao нет local private-key fallback. Certificate issuance
получает ошибку; valid inventory может commit/checkpoint, но очередь удерживает raw batch
до signed durable ACK. Dependency retry30s не расходует budget deadletter5 для ошибок данных.
Readonly API и restart работают по public metadata без доступа к token/Bao.
Readiness проверяет scoped token lookup/renew по фактическому profile endpoint: sealed/unreachable/
revoked/неверная policy дают503. Readonly API при этом доступен; startup не требует online Bao.

Bao2.7 audit управляется декларативно: audit "file" "surveyscan" в deploy/bao.hcl,
/openbao/file/surveyscan-audit.jsonl, log_raw=false, стандартный HMAC tokens/secret fields.
API sys/audit enable отключён в этой версии. Журнал приватный и сохраняется в volume;
production требует контролируемого доступа, ротации/retention и capacity monitoring.
Полный audit никогда не печатать/прикладывать. Local check ищет own test canary/tokens
внутри журнала и публикует только boolean. Не отключать единственный sink для обхода I/O error.

## Backup key procedure и восстановление

Non-exportable Transit key не копируют отдельно: он находится в зашифрованном Raft snapshot.
Оператор с отдельной минимальной snapshot policy снимает snapshot save в private directory,
проверяет размер/контрольную сумму, шифрует для внешних хранителей и переносит off-host.
Вне app host отдельно сохраняются Shamir threshold shares, cluster identity, CA/public pins,
версии keys, политики и snapshot metadata; не кладутся вместе с snapshot/app config.
Первоначальный root после provisioning отзывается; для последующих действий отдельная
операторская identity и documented recovery process. Потеря threshold shares + ключей
шифрования snapshot означает потерю закрытых ключей; pub pins не заменяют backup.

Restore только на isolated recovery cluster, с отдельным listener/network и теми же
поддерживаемыми Bao version/config. Оператор восстанавливает snapshot и unseal,
проверяет public key/version против сохранённых pins, затем тестовую подпись/readref,
audit, token revocation/renewal и health. До сверки не направлять production traffic.
После успешной проверки согласованно переключаются endpoints/pins; не генерировать
новые ca/center под прежними именами для маскировки утраты ключей. Restore rehearsal,
несколько хранителей, off-host storage и DR RPO/RTO здесь описаны, но ещё не выполнены (C14/DR).

## Приёмка текущего среза

bao_smoke.py:4 live checks scoped KV/Transit/root rejection/actual403/audit/issuer bootstrap.
bao_pipeline.py:17 live checks compiled center+collector+PG, synthetic signed agent,
actual seal/unseal, readonly sealed restart, retained staging и automatic signed ACK без дублей.
C11.03 renewal/rotation/clone ещё не принят; весь C11 не done. JSON C03/C09 и прежний SQL сохранены.

## Renewal — реализованная часть C11.03

C03 JSON неизменен. Новая append-only0030: renewal_challenges (отдельно от heartbeat),
renewal_receipts (tenant/renewal UUID+digest/source/generation/key+public result).
Подпись origin signing key в домене SURVEYSCAN-RENEWAL-V1 привязывает CSR, source/generation,
nonce и tenant. Collector relay проверяет CA-attested agent scope/signature; backend ещё раз
проверяет active source/generation/assignment/current courier и signing binding.
Source lock сериализует issuance/revoke; receipt+challenge consume+new TLS identity коммитятся
в одной PG transaction. Точный retry возвращает прежний сертификат до проверки истечения
challenge; другой digest под тем же ID→409. Expired peer/revoked source не получают renewal.
Ключи подписи origin/center при обычном TLS renewal не меняются; старые pending signatures
продолжают проверяться. Collector сам ещё не обновляет свой TLS credential (следующий шаг).

Agent renew --config использует тот же process lock, что daemon; новый Ed25519 TLS private key,
CSR и signed request сохраняются в renewal.pending.json0600 до HTTP. После trusted CA/key/
source/generation/collector/center attestation checks сертификат и matching private key
коммитятся одним atomic tls-identity.json0600 (fsync/rename/dirsync), затем pending удаляется.
Исходные tls.key/identity.json остаются для upgrade history, новый bundle имеет приоритет;
повреждённый/public bundle запрещает startup, fallback к старому не выполняется.
Daemon проверяет renewal за1h до expiry и повторяет pending каждую минуту. Lifecycle lead window
проверен unit-тестом; реальный24h timer/soak не запускался. CLI force renew проверен на реальном agent.
Запрос с expired challenge после409 получает новый nonce в следующей попытке; committed result
находится до этой проверки. Потеря ACK после commit проверена реальным TLS socket shutdown.

Старый TLS certificate сохраняет исходный validity window; немедленная блокировка всех old/new
credentials происходит через source revoke в центре. Offline collector не обещает мгновенный
отзыв уже известного CA cert; receipt/heartbeat/renewal backend gates его проверяют при связи.
Нельзя считать копию всех private keys отличимым новым хостом: до hardware-backed key/local
identity continuity gate это не реализовано. Не включать state/keys в golden images;
cloned/reinstalled host подготавливает новый source и проходит новый grant/resolution.
Смена generation/ключей подписи и автоматическое сопоставление после переустановки здесь не реализованы.
При TLS expiry после длительного offline автоматическое renewal не обходит mTLS expiry;
нужна отдельная административная recovery procedure (ещё не принята). Старый spool не удалять.
