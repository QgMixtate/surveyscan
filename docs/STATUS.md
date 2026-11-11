# Текущее состояние surveyscan

**8 ноября 2026 (Claude, R-024).** Работа продолжается в ветке claude/peaceful-goodall-a8u9sk
(от 5fe78c5 fast-forward, единственный писатель; codex-ветки заморожены). 57/200 done, C15.02 in_progress.
Закрыт C15-D11: atomic_rename ACCESS_DENIED (0xc0000022) при читателе — FileRenameInformationEx с POSIX-семантикой.
Добавлен winstate.RecoverOrphans (только .tmp-* под lock, небезопасный остаток сохраняется).
Windows-адаптеры privatefile/diskspool (Lock/Atomic/SyncDir/RecoverTemps) над winstate — 1c29799: c15, v2, boot success; Capacity/Data не портированы.
Проверено на 7d67248: c15 Windows Server 2022 (42515541316), v2 (42515541308), boot (42515541314) — success;
web/evidence на этот SHA не запускались (path-фильтры), «все 5 workflow» не заявляется. Не runtime, не ordinary rights/Win11.
Windows runtime путь 1 (отдельный цикл): W1 state/lock, W2 batch 1.2, W3a доставка, W3b цикл RunWindows, W4a Prepare — зелёные (последний e3802d5). Решение пользователя: сквозная интеграция — на Windows-ВМ по runbook handoffs/C15-windows-vm-integration.md (в CI не гоняется); enroll/bind-host/renew и RunWindows не проверены. C15.03 начат: доверие ACL для SYSTEM/Administrators и пакет winservice (SCM) зелёные на 9355cfb. Команды агента install-service/uninstall-service/service и нативный тест SYSTEM-службы (доходит до Open, ACL администратора принят, uninstall) зелёные на e3759bd. Не проверено: перезагрузка, обновление, Win11/обычные права, ВМ. Дальше: C15.04 (обновление/перезагрузка), сквозной прогон на ВМ.
**10 ноября 2026 (Claude, R-025).** На реальной ВМ Windows Server 2019 пройдены V1–V4 и первая оценка V9 (служба, сквозной enroll→центр на Ubuntu 24.04, reboot, подмена бинарника); Linux-платформа внутри профиля 1.2 (этапы 1–6, run12, collect12) закрыта в CI. 57/200 не менялся; C15.02 in_progress. Состояние и открытые проверки — handoffs/C15-C16-session-handoff.md.
**10 ноября 2026 (Claude, R-026).** Код C16.02 (rpm/apk/systemd/DMI), C17 (SSH + Bao-привязка + run-ssh12), C18 (WinRM + run-winrm12), C19 (SNMPv3), C20–C22 (discovery/presence/топология), C23 (формат и импорт portable) написан и проверен локально; матрица и блокеры — handoffs/C24-matrix.md. CI заблокирован биллингом GitHub; живые проверки (ВМ, WinRM, железо), soak-end и сквозная доставка не выполнены. 57/200 не менялся, статусы пакетов не менялись.
**10 ноября 2026, вечер (Claude, R-026).** Живые проверки на стенде пользователя: Linux run12 systemd, SSH- и WinRM-цели до центра со склейкой активов, soak №2 без пропусков; C23 portable со сбором и импортом в центр; миграция 0036 acquisition; 9 дефектов найдено вживую и исправлено. Hosted CI заблокирован биллингом; локальный повтор CI v2: шаги 01–08 ок, остальные не завершены. Передача: handoffs/C15-C24-session-handoff-2.md. 57/200 не менялся.
**10 ноября 2026, поздний вечер (Claude, R-027).** Локально: C09 карточка перечисляет источники профиля 1.2; тестовый CA smoke совместим с Python 3.13 (7 smoke зелёные); C23.03 HTTPS-загрузка portable (эндпоинт+nginx, integration PG16). Ждут стенда: утренний снимок soak 11.11, перезапуск центра с acquisition, WinRM с правами WMI. Передача: handoffs/C15-C24-session-handoff-3.md. 57/200 не менялся.
**11 ноября 2026 (Claude, R-027).** По поручению пользователя main перемотан (fast-forward) на текущее состояние рабочей ветки (ec0e168 и далее). Релиз/теги/развёртывание не делались; hosted CI на этом SHA не прогонялся (квота Actions исчерпана до 1 декабря).
Историю вести в REQUESTS (R-024+) и handoffs/C15.md; ниже — прежний срез Codex от 6 ноября.

6 ноября 2026.57/200done; C15.02 in_progress. Ветка codex/v2-c15-windows,
worktree /workspace/surveyscan-c15, draftPR5/baseE1PR4. Последний проверенный published
product4ff977f — all5hostedSUCCESS; C15-hosted-profile.json. Profile core опубликован. Main/release/deploy/cloudsettings не выполнялись.

Новый profile1.2 core: отдельные schema/DTO/signatures и center+collector endpoint,
common cadence +fixed12partial policy/30sworker/420ssweep, отдельный applied-progress
и tenant-scoped readAPI. Sources0034 appended:35migrations/48ownedtables; old0000–0033
immutable, privateupdatefixture0035/schema35→36. Defaultoptin flagsfalse, C03/C09/C12
unchanged. Go agent FetchInventoryProfile12 requires fresh private three-hop proof and
returns a verified profile/limits; it does not apply/persist/report application yet.

Localverify/build/C03 58, PG60, racewire/agent/collector, Windowscrossbuild/vet passed.
Compiled actualmTLS/scopednonexportableTransit/PGrelay11passed with synthetic enrolled
agent; explicit Linux fsync acceptancefixture precedes appliedACK. Not Windows cache.
MockSigner-failure/no-fallback uses realTLS/PG; actualTransit verified separately.
[Evidences](plans/surveyscan-v2/evidence/C15-inventory-profile12.json),
[design](plans/surveyscan-v2/decisions/C15-inventory-profile12.md).

Next: secure Windows DACL/reparse/root-relative private files, exclusive lock/atomic
state/hostcontinuity, then durable signed acceptancecache/offline/applied reporting.
Native12provider process isolation exists but actual Windows daemon is not enabled.
SCM/install/update/rebootC15.03/04 follow02acceptance. Global57done unchanged.
[Handoff](plans/surveyscan-v2/handoffs/C15.md); historical failures D06/D07/D08 retained;
D07originalcauseunconfirmed, priorrepeatVM9+9 passed, independentbackofffixd4allgreen.

E1frozen24h/candidate preserved:source8560f57/86400.914s, authdelta39e401f/internal27files.
No new24h or100user/productionSLA claim. Use C15binaries/ownDB/ports/scopedmounts/reports
with E1devcredentials read-only; nevercopyprivatekeys/overwriteE1reports/resetshared
PG/Bao blindly. AppliedSQL0000–0034 immutable; continueautomatically R020/022/023.

Следующий localincrement — isolated platform/winstate: protected privateDACL/root-relative
NtCreateFile/bounds/no-overwrite/exclusive process lock. Crosscompile/vet passed; native
Windows execution pending. Не подключён к runtime; atomic replace/cache/hostbinding
ещёне реализованы. Proof C15-winstate-primitives.json иновыйWindowsCIstep.

Private-root base c7e2f0a now all5hostedSUCCESS; native DACL/drift/null/reparse/hardlink/
crossprocesslock/redaction passed. D09 fixed; old57e failedrun retained. New localatomic
increment requires lock and uses root-relative NT rename, optional read errors distinguished;
Wincompile/vetpassed, nativepending. Stillnotadopted/cache/hostbinding/cleanup. Read
C15-winstate-atomic.json andC15-hosted-winstate-base.json.57done.
