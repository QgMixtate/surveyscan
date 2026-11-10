# Передача сессии №2: C15–C24 (E2) — состояние на 2026-11-10 ~17:20 UTC

Ветка `claude/peaceful-goodall-a8u9sk` (единственная рабочая), HEAD — см. `git log -1`. Журнал: docs/REQUESTS.md (R-026 — вся эта сессия).
Счётчик плана **57/200 НЕ менялся**, статусы пакетов C15–C24 не менялись (меняет только пользователь при приёмке). Матрица и блокеры: handoffs/C24-matrix.md (на момент её записи; ниже — что изменилось после).

## Сделано в этой сессии (подробно — R-026)
- **Живьём на стенде пользователя** (Ubuntu 24.04 10.170.108.2 — центр vm_center.py в tmux `center`; Windows Server 2019 DC awm.local 10.170.108.1):
  Linux-агент run12 как systemd-служба (сквозной путь, обновление бинарника с сохранением личности); SSH-цель `run-ssh12` → центр (склейка с агентом той же ВМ, assets);
  WinRM-цель `run-winrm12` без прав администратора → центр (склейка с Windows-агентом по MachineGuid); Windows-агент перерегистрирован в новом центре; soak №2 6,5 ч — без пропусков у 5 источников.
- **Дефекты, найденные вживую и исправленные:** privatefile vs systemd 255 credentials (0440 root ACL); vm_center падал на пустом prepare; 4-часовой таймаут центра (ночной soak №1 потерян);
  платформа профиля для виртуальной личности; потеря вывода WinRM при командах >30 с (таймауты long-poll); молчащий сценарий/классификация ошибок WinRM; пространства имён кандидатов WinRM;
  зависание SSH NewSession при отмене (найдено -race); сокеты в routes_ports SSH.
- **Код (локально проверен):** C16.02 rpm/apk/systemd/DMI; C17 SSH (+Bao-привязка, ssh-probe); C18 WinRM (+winrm-probe); C19 SNMPv3; C20 discovery; C21 presence; C22 topology;
  C23 portable: формат (подписанные записи) + `surveyscan-portable init/collect/verify` + импорт в центр `surveyscan-server portable-register/portable-import` (интеграция + e2e бинарниками на PG16);
  миграция **0036 acquisition** (agent|ssh|winrm; каталог 37 миграций) — в коде и тестах, НА ЦЕНТРЕ СТЕНДА НЕ РАЗВЁРНУТА (центр работает на старой сборке).

## Идёт / незакрыто
- **Суточный soak** на стенде пользователя: база 10.11 10:24 UTC, промежуточный снимок 16:58 UTC (R-026, bd8ef8a). Снять утренний снимок теми же командами soak-end (в R-026)
  и сравнить: пропуски, память Windows за ~22 ч (вопрос утечки), вытеснение квитанций в spool при лимите 1 МиБ, assets=3, центр жив. Центр НЕ перезапускать, ВМ НЕ перезагружать до снимка.
  ВНИМАНИЕ: напоминание send_later на 11.11 09:00 МСК привязано к СТАРОЙ сессии — в новой поставить своё.
- **Локальный повтор CI v2 (job c04) в песочнице** с Docker (dockerd в песочнице работает, образы тянутся): на 5f3d1cb шаги 01–08 rc=0 (verify/контракты, race, сборка, Web, release bundle,
  unit_check, dev.py up, integration PG17). Шаги 09–36 (smoke: auth/machine/agent/recovery/diskfault/bao/c15/vm_center selftest/renewal/cli/profiles/reconnect/backup/bao_restore/checkpoint/
  upgrade/update) — результат НЕ получен (прогон остался в старой песочнице). Отличия от hosted: Python 3.13 (не 3.12), Node 22 (не 24). В новой сессии: `dockerd &`, venv
  `.contract-tools` + requirements C03 + pyyaml, затем шаги из .github/workflows/v2.yml по порядку (раннер был в scratchpad, не в репо — написать заново или сохранить в v2/scripts).
- **Hosted CI заблокирован биллингом GitHub** — ничего после bf6c299 не проверено hosted.
- **Найденный общий пробел C09:** сводка источников карточки (InventoryDetail.Sources) строится только из проекции 1.0 — источники данных 1.2 (агенты и portable) не перечислены.

## Локальный повтор CI v2 — результат на момент передачи (код 5f3d1cb, песочница с dockerd)
Прогресс: 01 rc=0   20.5s Format, architecture, unit tests, vet and C03 contracts;02 rc=0   22.4s Agent collection ownership, heartbeat progress and capability chain race checks;03 rc=0   21.9s Build server, collector, agent and CLI;04 rc=0    5.0s Build separate Web UI;05 rc=0    1.3s Signed release bundle, independent Web version and verified staging;06 rc=0    2.6s Static systemd unit verification (not boot acceptance);07 rc=0   33.6s Start local PostgreSQL, OpenBao, backend and proxy;08 rc=0   66.2s Real PostgreSQL integration tests;09 rc=0    5.7s HTTP, dependency outage and restart checks;10 rc=0    3.5s Real binary auth, console bootstrap and restart checks;11 rc=1   11.5s Compiled collector, mTLS and signed center result;12 rc=1   11.5s Live host agent, three scheduled cycles and heartbeat;13 rc=1   11.5s Real daemon SIGKILL, offline spools and reconnect;14 rc=0    0.7s Real ENOSPC in disposable tmpfs;15 rc=0    0.9s Scoped OpenBao KV, Transit, token renewal and masked audit;16 rc=0   36.1s OpenBao seal, restart, durable ACK and renewal relay;17 rc=0    3.4s Opt-in inventory1.2 center, scoped Transit, projection and typed API;18 rc=0    5.3s Opt-in inventory1.2 collector relay, offline spool and cold restart;
**ПРОВАЛЫ 11–13** (machine_smoke, agent_smoke, recovery_smoke): `RuntimeError: machine/collector binary did not start` — за 10 с нет ответа /health/live на TLS-порту центра
(`.dist/surveyscan-server serve` с машинной конфигурацией); в center.log только строка старта, ошибки нет. Причина НЕ установлена: возможна особенность песочницы
(сеть/прокси/порты), возможна регрессия после C14 (миграция 0036, приём portable, ConfigureMachine). Шаг 10 (auth_smoke, сервер без машинной конфигурации) прошёл.
ПЕРВОЕ ДЕЛО новой сессии: воспроизвести `python scripts/machine_smoke.py` после `dev.py up`, посмотреть, слушает ли центр TLS-порт (ss -ltnp), и сравнить с кодом bf6c299
(последний hosted-зелёный), чтобы отделить регрессию от песочницы. Стенд пользователя этим не проверен: центр vm_center там собран из старого кода.

## Стенд пользователя (что изменено для тестов — откатить после пилота)
DC: пользователь AWM\scanwinrm (Remote Management Users), самоподписанный сертификат WIN-AREDINOV.awm.local + HTTPS-listener 5986, правило firewall от 10.170.108.2,
ACE S-1-5-32-580 в WinRM RootSDDL. Linux: службы surveyscan-agent (run12), surveyscan-ssh1 (run-ssh12 → 127.0.0.1:22, пользователь scanprobe), surveyscan-winrm2 (run-winrm12),
surveyscan-winrm1 выключена (с drop-in debug.conf); /root/winrm (CA и пароль), /root/sshprobe (ключ). git на ВМ — кэш учётных данных в памяти (credential.helper cache).

## Предложенный порядок дальше
1. Утренний снимок суточного soak → запись в R-026.
2. Довести локальный повтор CI v2 до конца (шаги 09–36), записать провалы как факты; при восстановлении биллинга — hosted.
3. Пробел C09: источники 1.2 в карточке актива.
4. Решения пользователя: приёмка C15.02 по V1–V4/V9 (исключения: V5 обычные права, V6 Win10/11, V7 клон, откат), биллинг CI.
5. Далее: HTTPS-загрузка portable, перезапуск центра стенда с acquisition, WinRM с правами WMI, C25 (merge/split — в т.ч. отдельный актив WinRM1).
