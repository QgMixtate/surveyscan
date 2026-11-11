# Стенд на ВМ: центр на Ubuntu 24.04 + Windows Server 2019 агент (сквозной прогон V2)

Статус: **не выполнялся на ВМ**. Скрипт центра (`v2/scripts/vm_center.py --selftest`) проверен в CI с Linux-агентом (run12, enroll, факты в PG);
Windows-скрипты (`windows-vm-check.ps1`, `windows-vm-enroll.ps1`) проверены в CI на этапах prepare/службы под PowerShell 5.1,
enroll против настоящего центра с Windows-агентом — ещё нет. Стенд — тестовый (одноразовая dev-CA, dev_mode), не production.

## Linux-ВМ (центр), один раз
    sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git python3-venv openssl make
    sudo usermod -aG docker $USER      # перелогиниться
    curl -fsSL https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o /tmp/go.tgz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
    export PATH=$PATH:/usr/local/go/bin
    git clone -b claude/peaceful-goodall-a8u9sk https://github.com/QgMixtate/surveyscan.git && cd surveyscan/v2
    python3 -m venv .contract-tools && .contract-tools/bin/pip install -r ../docs/plans/surveyscan-v2/contracts/C03/checks/requirements.txt
    make build                               # бинарники в v2/.dist
    sudo ufw allow 18443/tcp                 # если ufw включён

## Запуск центра (держать открытым, например в tmux)
(Скрипт сам поднимает PostgreSQL/OpenBao через `scripts/dev.py up`, если они не запущены; можно выполнить `python3 scripts/dev.py up` заранее.)
    cd surveyscan/v2 && .contract-tools/bin/python scripts/vm_center.py --public-host <IP_Linux-ВМ> --collector-port 18443
Печатает `READY …`, затем `STATUS {...}` каждые 20 с. Файлы для агента — в `v2/.local/vm-center/` (ca.pem, agent-config.windows.json).

## Windows Server 2019 (PowerShell от администратора)
1. Скопировать с Linux на Windows в `C:\surveyscan\`: `ca.pem`, `agent-config.windows.json` (scp/WinSCP).
2. `powershell -ExecutionPolicy Bypass -File .\windows-vm-enroll.ps1 -Step prepare -ConfigTemplate C:\surveyscan\agent-config.windows.json -CA C:\surveyscan\ca.pem`
3. Скопировать `C:\surveyscan\vm\prepare.json` на Linux в `v2/.local/vm-center/prepare.json` → в окне центра появится `GRANT issued` и файл `grant.json` (действует 15 минут).
4. Скопировать `grant.json` на Windows в `C:\surveyscan\` и выполнить `-Step enroll -Grant C:\surveyscan\grant.json`.
5. В окне центра в течение 1–3 минут `observations` станет ≥1, `facts_by_section` перечислит секции (ожидаются 12 секций Windows).
6. `-Step status` — состояние службы/очередь; `-Step remove` — удалить службу.

## Что фиксируется
Вывод `STATUS`, `-Step status`, ошибки; SHA бинарника и коммита (BUILD.txt артефакта). Не проверено этим прогоном: reboot, обновление
зарегистрированной службы, обычные права, Windows 10/11, клоны.

## Предупреждение: время жизни центра стенда (добавлено 2026-11-10)
`vm_center.py` по истечении `--timeout` завершает сценарий, и харнесс УДАЛЯЕТ временную БД `ssv2machine_*` вместе с данными агента. Прежний дефолт был 4 часа:
ночной soak центра 9–10 ноября не состоялся (центр завершился ~01:55 UTC, через ~3 ч после soak-start; данные центра потеряны). Дефолт теперь 7 суток;
запускать в `tmux`/`screen` (закрытие SSH-окна тоже останавливает центр): `tmux new -s center`, затем `python scripts/vm_center.py --public-host <IP> --collector-port 18443`.
После любого перезапуска центра БД и CA новые: агентов регистрировать заново (prepare → grant → enroll).

## Постоянный режим центра (добавлено 2026-11-10, R-027): обновление без переподключения агентов
`vm_center.py --persistent` хранит в `v2/.local/vm-center-state/` (0700, секреты — не публиковать и не коммитить) базу,
CA центра, ресурсы OpenBao, учётную запись администратора и регистрацию collector. При перезапуске применяются только новые
миграции, выпускается свежий токен OpenBao и запускаются новые бинарники; агенты продолжают работать без prepare/grant/enroll.

Переход (один раз, после утреннего снимка soak; текущий центр временный, поэтому один раз агентов придётся подключить заново):
1. `tmux attach -t center`, Ctrl-C — старый центр остановится и удалит свою временную БД.
2. `cd ~/surveyscan && git pull && cd v2 && make build`
3. В tmux: `.contract-tools/bin/python scripts/vm_center.py --persistent --public-host 10.170.108.2 --collector-port 18443`
   — в выводе `PERSISTENT стенд создан`, затем `READY`.
4. Подключить источники заново тем же порядком, что раньше (prepare → grant → enroll): Windows-служба, surveyscan-agent, surveyscan-ssh1, surveyscan-winrm2.

Дальнейшие обновления центра: Ctrl-C → `git pull && make build` → та же команда из п.3 (в выводе `PERSISTENT стенд найден`); агентов не трогать.
Если центр стоял дольше часа — не страшно: токен OpenBao перевыпускается при старте. Сброс стенда: остановить центр и удалить `.local/vm-center-state`.
Проверено в песочнице: центр → Linux-агент (prepare/grant/enroll/run12) → остановка центра → повторный запуск → тот же агент без переподключения
продолжил доставку (observations 1 → 3, assets 1, новых grant нет). machine_smoke, vm_center --selftest, c15_center_smoke без флага — без изменений (rc=0).

## Состояние стенда (2026-11-11, R-027)
Переход на `--persistent` выполнен 11.11 11:46 UTC (сборка fc9397a), 4 источника переподключены. Особенности ВМ: репозиторий — `/root/surveyscan`,
центр работает от root (`sudo tmux attach -t center`); у root нет доступа к приватному GitHub — код доставлять `git bundle` с рабочей машины
(`git bundle create dev.bundle origin/develop` → scp → `git fetch dev.bundle refs/remotes/origin/develop:refs/remotes/origin/develop && git checkout -B develop origin/develop`)
или настроить deploy key. При разборе target.json для повторной регистрации не использовать `eval`: имя `AWM\scanwinrm` теряет обратный слеш.
