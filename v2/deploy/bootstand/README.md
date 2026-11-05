# Изолированный C13 boot/reboot стенд

Это настоящий Debian12/kernel/systemd guest в QEMU TCG. Не требует /dev/kvm,
root PID1 хоста, writable host cgroups или host service install. Public tooling image
содержит PG17.11, Bao2.7.2, systemd252, Linux cloud kernel, QEMU/e2fs/nginx/Python.
Он не содержит runtime credentials/tenant data. Go binaries и отдельный static Web
собираются заранее; Go/Node внутри guest не нужны.

```sh
docker build --secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt \
  -t surveyscan-c13-boot-tools:local deploy/bootstand
GO=/path/to/go /path/to/contract-python scripts/boot_smoke.py
```

В managed cloud передать session public CA через BuildKit secret согласно runtime skill,
сохранив proxy/TLS verification. Каждый run создаёт fresh PG cluster, fresh Raft, отдельные
test TLS keys/tenant/source IDs и raw ext4 disk в private .local/c13-vm-*/. Signing key
удаляется до копирования guest seed; guest получает независимый public trust anchor.
Disk/seed/custody не входят в Git, Docker image layers или CI artifacts.

Первый boot — explicit test operator provisioning: scoped non-exportable Transit keys,
private LoadCredential configs, real CSR/enrollment, systemd enable/start. После inventory1
с signed ACK центр останавливается, restart agent создаёт durable packet на обоих hops.
Тест сохраняет private phase и делает настоящий systemctl reboot.

Второй boot подтверждает changed kernel boot_id/PID1systemd, automatic nonroot services,
NoNewPrivileges/LoadCredential, PG33 schema, preserved session/UID/queues. Cold Bao остаётся
sealed; ready503 и readonly registry сохраняются. Затем test operator использует отдельную
root-owned custody для unseal: это не product auto-unseal и не ключ у app UID/unit/env.
Pending replay применяется once, sequence продолжается >=3, обе очереди drain.
Проверяются actual updater SystemdController/transient credentials, healthy0.0.1-c13,
TLS static UI/API edge и shipped CLI login/read/logout без guest Go/Node tools.

PG stand unit использует настоящий sd_notify (сборка --with-systemd). Type=simple для
postgres был недостаточен: migration могла опередить готовность БД. Server Type=simple
также не доказывает готовность listener: тест ожидает /health/live, затем проверяет ready.
Transient D-Bus ExecStart/Environment не трактуются как unit-file %d: updater использует
известный уникальный /run/credentials/<unit>.service путь. Эти различия проверяются runtime.

Ограничения: development stand, локальная PG auth/единая машина, test operator custody,
никакого production KMS/split custody/physical power-loss/100-user/DR утверждения.
Первичная установка предполагает предоставленные оператором PG/Bao/TLS prerequisites;
guest.py — тестовый оператор с synthetic identities, не production provisioning wizard.

Только `SURVEYSCAN_BOOT_RESULT` со status=passed плюс exit0 разрешает accepted report.
Отсутствие результата, timeout или interrupted supervisor не считается pass. Supervisor
удаляет own containers/anonymous volumes, raw disk и private seed; sanitized JSON report
остаётся в .local/c13-boot-smoke.json. Raw prepare/serial logs приватны и не upload.
CI boot.yml повторяет factory на двух независимо созданных VM, сохраняет только JSON.
RAM2GiB, disk3GiB sparse, timeout15min/run; host networking/cgroup mounts не используются.
