# surveyscan v2 — проверяемый кандидат E1

C14 завершён в ограниченном Linux E1-объёме. Это внутренний кандидат, опубликованный исходным
кодом в PR4; официальный GitHubRelease, слияние main и production deployment не выполнялись.
Go source: `39e401f6f0d5564ea132c8ad8accab84f4ff6a3e`, development version `0.0.0-c13`.
Web имеет независимую версию `0.1.0-c14-web`, clean source8560f57; API hashes совпадают.

## Что работает

Постоянный Linux/amd64 agent→site collector→Go center→PostgreSQL; identity/os/network,
heartbeat отдельно от inventory, устойчивые очереди/ACK/replay, неизменяемый asset_uid.
OpenBao KV/Transit и машинные TLS identities с renewal/revoke, без приватных CAключей
в приложении. Отдельные Web/CLI, tenant/role/Origin/CSRF, профили и безопасная диагностика.
Systemd/LoadCredential, проверяемая поставка, update rollback, PG/Bao/checkpoint restore.
Оператор предоставляет PG/Bao/TLS prerequisites; test-operator provisioning не является
production install wizard или auto-unseal.

## Проверки

Суточная база на frozen8560f57:86400.914s,2740samples,1419observations,2realcertificate
renewals, обе сетевые аварии/restart/finaldrain/oneUID/no duplicates. Это доказательство
для тех конкретных бинарных хешей, не утверждение о24hпрогоне новых candidate binaries.

Authdelta на39e401f: общийlogin budget5→8s, ниже serverWrite10s иCLI15s. При48%CPU
прежний вариант получал503 после6464ms проверкипароля; новый получил201 за6336ms и
создал1session, отозванную тестом. PGlock по-прежнему приводит к bounded503 без session.
Argon2id3passes/64MiB/1lane,2hashslots и rate/session limits неизменны; авторетрайPOST не добавлен.
Safe stage/reason/timing logs не содержат пользователя, пароль, SQL или rawerror.

Все4 hosted workflows39e401fpassed; PG51, native2freshVM9+9, controllednative10+10,
кандидат27files/signature/verify/staging иего точныеартефакты Chromium16passed.
UI partial/stale/unknown display cases mocked явно; source signed frames синтетические.
Virtual HPET отключён только в disposableVM после pre-PID1 stall; часы/сертификаты не подменялись.
Исторические failure/proof сохранены; точная причина конкретного старогоCLI503 безtrace неизвестна.

## Артефакты и ограничения

Локальный указатель: `v2/.local/c14-final-candidate.json`. В bundle есть manifest/signature,
Go binaries, staticWeb, API contracts, systemd files иSBOM; manifestSHA иprovenance в
`docs/plans/surveyscan-v2/evidence/C14-candidate-39.json`. Временный тестовый ключ удалён.
Тестовый public anchor не является production trust: оператор задаёт доверенный ключ явно.

Это baseline инвентарь Linux; Windows/C15, полные hardware/software/KB sections, agentless
адаптеры и enterprise функции выполняются следующими пакетами. Нет подтверждённого
100-user SLA, HA/geo, productionKMS, physicalpowerloss или Windows SCM/reboot acceptance.
Насыщение CPU и недоступные зависимости могут давать503; bounded fail-closed сохраняется.

Итоговая матрица15сценариев ииндексдоказательств: `docs/plans/surveyscan-v2/evidence/C14-acceptance.json`.
