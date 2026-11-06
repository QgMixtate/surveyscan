# Текущее состояние surveyscan

Обновлено: 6 ноября 2026. **C14 завершён в пределах Linux E1; 57/200 подзадач выполнены**,
включая проектирование C15.01. [Протокол приёмки](plans/surveyscan-v2/evidence/C14-acceptance.json).

Суточный прогон: 86400,914 с, 2740 измерений, 1419 наблюдений, два настоящих продления
сертификатов; очереди опустели, UID и отсутствие дублей сохранены. Это frozen source8560f57.
Исправление входа проверено отдельно на39e401f: бюджет5→8с, без изменения Argon2, лимитов
попыток и двух hashslots. При48%CPU прежний вариант давал503 после6464мс проверки пароля;
исправленный вернул201 за6336мс и создал ровно одну сессию, затем штатно отозванную тестом.
Блокировка БД по-прежнему возвращает ограниченный503 без создания сессии.

39e401f: все4 hosted workflows SUCCESS (v242183074129, native42183074101, Web42183074062,
evidence42183074089), две свежие VM9+9, локальный PG51 и точные артефакты кандидата Chromium16.
[Доказательства](plans/surveyscan-v2/evidence/C14-hosted-39.json). Причина конкретного старого
503 без backendtrace недоказуема; воспроизведённый класс исправлен, безопасная диагностика сохранена.
Виртуальный HPET отключён только в тестовой VM; исходный зависший запуск остался failed.

[Кандидат](plans/surveyscan-v2/evidence/C14-candidate-39.json):27 файлов, подпись/verify/staging
проверены, временный ключ удалён. Go39e401f и независимый Web8560f57. Это внутренний кандидат;
официальный GitHubRelease, слияние main и production deployment не выполнялись.
E1 source опубликован в [PR4](https://github.com/QgMixtate/surveyscan/pull/4).

**Следующая работа — C15.02**, worktree `/workspace/surveyscan-c15`, ветка codex/v2-c15-windows,
[PR5](https://github.com/QgMixtate/surveyscan/pull/5). C15.01done, C15.02partial: базовые адаптеры всех12native
секций проверены на WindowsServer2022 с elevatedtoken; полного покрытия ещё нет. Новый
observation1.2 пока изолирован: signed delivery/storage/detail API, DACL/spool locks, host
continuity, SCM lifecycle, обычные права, Windows11 и настоящий reboot ещё не приняты.
Продолжать автоматически с этого пункта по R-020/R-022/R-023. Настройки среды не публиковать.

Архитектура0.5: OpenBao, отдельный Web, CLI/API, неизменяемый asset_uid, событийный outbox
без внешней шины. E1 — постоянный Linux цикл с identity/os/network; полная инвентаризация
и платформы расширяются в E2. Enterprise HA/geo/100users не являются подтверждённым SLA.

Текущий checkout — C15 worktree. Комбинированный981f4e7 (E1 auth8s + C15 baseline)
прошёл все5hosted workflows. C14final metadata получена изE1fa73e47, статусыplan/CSV57done
согласованы; C15 evidence использует локальныеpaths. Следующий код — локальные users/groups/SID.

Последний C15 кодf577436: Windows42188089781 SUCCESS,5native testfunctions.
Users5/groups27/memberships8 и25ARP/NDPcache rows прочитаны без вывода имён/SID.
Полнота секций не заявлена; envelopesynthetic, нет scheduled delivery/SCM/reboot.
C15.02остаётсяIP; текущая полная Linux regression/boot этогоsource ещёвыполняется.

C15 текущий source d9e6206: все4hosted workflows SUCCESS, включая actualWindows
QFE5/protection6 иfaulttests worker timeout/crash/oversize/invalid/isolated section failure.
Worker30s/1MiB/typedJSON/kill+reap; C15-D03 io.Copy обход bounds исправлен и проверен.
57done сохраняется: C15.02 не закрыт. Следующий блок — protocol negotiation, корректная
проекция/identity/coverage новых rows, совместимый detail API и отдельная collectiontask
в scheduler. Нельзя просто включить1.2: старый flatten() молча игнорирует новые sections.

C15.02 новый локальный increment: отдельные record_facts12/record_section_state12,
append-only0033 (34migrations/47tables), field provenance/partial preservation/ranking.
Legacy unknown sections failclosed; C09 detail unchanged. PG53 + отдельный upgrade33→34
passed; draft24/24, makeverify/C03 58, Windowscrosscompile/vet passed. Hosted новогоsource
ещёpending. Runtime1.2 не включён; fullcoverage/negotiation/API/scheduler/SCM/reboot pending.
Решение decisions/C15-record-projection.md;57done не изменяется.

999c6e1 опубликованPR5: Windows42197490157SUCCESS, new HKCU/registry locator schema24
проверен actualWindows. Linuxboot42197490003FAILED наstale fixture expected33 после
успешных5checks/reboot/sameUID: catalog34. C15-D04, fixlocalpendingrepeat; wholeCIнеgreen.

Следующий C15 increment local: GETinventory/facts/{section} + C15 OpenAPI, typedJSON/
per-field evidence, lastattempt,100items/2MiB, scope+revision cursor и409наизменение.
RealTLS/auth/PG56passed (synthetic internal committed projection, не machine admission).
Unit/schema/OpenAPI/cursor checks passed; финальные verify/build4binaries/Winbuild+vet passed.
999c6e1 завершил v242197490009/Web42197490098/Windows42197490157SUCCESS; bootfailed
C15-D04fixturecount33→34 исправленлокально, repeatpending. C15.02IP/57done unchanged.

f6e3047 API/bootfix: все5hosted SUCCESS, Windows42199513841/v242199513647/
boot42199513709/Web42199513708/evidence42199513646; двеfreshVM9+9, C15-D04fixed.
Новый локальный increment: opt-in signed/batch12validator и all-hop limits helper
512/576/768KiB (HTTPstillC03), authoritativebinding/crypto/bytebounds tests passed.
C15-D05collectorJSON: actualmTLS/C03 batch479558→oldpacket2324798>2MiB, fixed479799;
disk/replay202/race wire+collector/verify/C03 58/build/Winwirecrosscompile+vet passed.
Cap/profile1.2networkexchange и machine runtime ещёнеподключены; C15.02IP/57done.
