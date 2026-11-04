# C13 — проверяемая поставка Linux/amd64 (кандидат)

Пока поддерживается подготовка подписанного directory bundle и пустого staging root.
Это не завершённый installer/upgrade: реальные systemd boot/reboot, работающий checked update,
backup/restore и приёмка двух чистых систем остаются открытыми задачами C13.
Службы на build host не устанавливаются и не запускаются.

## Сборка и происхождение

Из `v2/`, с выбранным Go toolchain:

```sh
make build VERSION=0.0.0-c13 GO=/path/to/go
(cd web && SURVEYSCAN_VERSION=0.0.0-c13 npm run build)
python3 scripts/release.py build --version 0.0.0-c13 --output .local/release-candidate --go /path/to/go
```

Повторное использование output запрещено. Bundle содержит `manifest.json` и `payload/`:
четыре статических ELF binary, отдельный static Web UI, public API contracts,
systemd/sysusers templates, `CHECKSUMS.sha256` и `sbom.spdx.json`.
Ни конфиги `.local`, ни identities/spools/пароли/ключи в поставку не входят.
PostgreSQL, OpenBao, systemd, TLS edge — внешние prerequisites, не часть bundle.

Сборка требует совпадения версии и revision всех пяти компонентов и current source HEAD,
а также совпадения hashes C03/C09/C12 API с Web manifest. Dirty tree не маскируется:
каждый компонент и release manifest сохраняют этот признак. Такой кандидат не объявляется
чистым reproducible release. `version`/`--version` работают у всех binaries без доступа к БД;
Web metadata — `/version.json`, формат C09 compatibility check сохранён.
Совместимость с C03 проверяется штатным `make verify`; это не обещание rolling upgrade.

SPDX 2.3 inventory берёт Go module/version/checksum из metadata каждого binary,
npm entries — из зафиксированного package-lock. В npm graph входят build dependencies;
это явно указано, наличие каждого package в конечном JS не аттестуется.
Отсутствующие license facts имеют `NOASSERTION`. Дата документа берётся из source commit
для повторяемости. SBOM не является vulnerability scan или проверкой лицензионного соответствия.

## Подпись и доверие

Оператор отдельно готовит Ed25519 release key. Приватный файл принадлежит текущему UID,
доступен только владельцу; release tooling не генерирует production keys и не берёт ключи из Bao/app.
Custody, ротация и доставка trust anchor требуют отдельной операционной процедуры.
Нужны Python 3 и OpenSSL 3 на машине проверки.

```sh
python3 scripts/release.py sign --bundle .local/release-candidate --key /secure/release-ed25519.pem
python3 scripts/release.py verify --bundle .local/release-candidate --public-key /trusted/release-ed25519.pub
python3 scripts/release.py stage --bundle .local/release-candidate --public-key /trusted/release-ed25519.pub --root /absolute/empty/staging
```

Trust anchor оператор получает по независимому доверенному каналу. Ключ из самой поставки
не устанавливает доверие. Detached signature покрывает точные bytes manifest;
manifest покрывает каждый payload file, его SHA256, размер и permissions.
Checksum без trusted signature не подтверждает подлинность.

Verifier не исполняет binaries из входящей поставки. Отвергаются unsigned bundle,
неверный ключ/алгоритм, изменённые manifest/files/modes, лишние или потерянные файлы,
symlinks/special files, traversal paths и duplicate JSON keys. Лимиты: 10000 файлов,
512 MiB payload, 2 MiB manifest. Изменение данных между проверкой и копированием
обнаруживается повторной проверкой private snapshot до публикации staging root.
Общая директория с параллельным недоверенным writer не поддерживается.

Staging root обязан быть пустым, `/` запрещён. Существующая установка/конфиги/данные
не заменяются. Публикуется versioned release и относительный `current`, private empty
state0700, public binary/unit paths0755/0644 и staging receipt. Chown/sysusers/enable/restart
на host не выполняются. Подпись и manifest сохраняются рядом с receipt для оператора.

## Граница обновления

Проверка новой поставки обязательна **до** изменения службы или схемы. Текущая команда
`stage` предназначена для проверки файлов на отдельном пустом root; применять её поверх
существующей установки нельзя. Переключение working `current`, draining очередей,
backup checkpoint и schema upgrade ещё не реализованы/не приняты.
Rollback symlink после миграции БД не считается безопасным rollback данных.
Нельзя удалять state directories, выдавать новый source ID или пересоздавать Bao storage
ради обновления binary. Эти сценарии должны войти в оставшуюся C13 приёмку.

Проверка реализации: `GO=/path/to/go python3 scripts/release_smoke.py`.
Создаёт только временные test keys и два filesystem staging root; оба удаляются.
Это не две загруженные чистые ОС и не production signing ceremony.
