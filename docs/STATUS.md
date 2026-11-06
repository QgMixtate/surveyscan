# Текущее состояние surveyscan

6 ноября 2026. **57/200 done; C15.02 in_progress.** C14 принят в bounded Linux E1,
C15.01 — проектирование done; C15.03/04 и C16–C50 не приняты.

Рабочая ветка codex/v2-c15-windows, /workspace/surveyscan-c15,
[draft PR5](https://github.com/QgMixtate/surveyscan/pull/5), base E1 изPR4.
Последний product code —2fe4b93: частичный inventory1.2 center+collector relay,
две подписанные capabilities роли/Go agent negotiation, независимый read-only
collection worker и serial state actor, все12Windowsproviders через bounded ownbinary
процессы. Default inventory12_enabled у центра/коллектора false; Windows daemon ещё
не включён. Complete/deletion1.2 отклоняется. C03/C09/C12 неизменны; SQL34/47ownedtables.

Фактические проверки на2fe4b93: fullv2 42233416953 SUCCESS, Windows42233417128 SUCCESS,
Web42233417240/evidence42233417031 SUCCESS. PG58, scopedBao20, center6/relay10,
realcompiledLinuxagent11 (3cycles+restart4th/UID/counters/verifiedACK/lock/revoke),
wire/collector/agent race. Native Windows2022/elevated: all12processes, COM+software
crash isolation и kill/reap passed. Данные relay синтетические; native SDK проверен
отдельно. [Exact runs/reports](plans/surveyscan-v2/evidence/C15-hosted-2fe.json).

**Boot42233416959 FAILED**: firstVM после reboot, second_queue_drain,4checks.
Причина C15-D07 неизвестна. Добавлена безопасная диагностика counts/closedreasoncodes,
8redaction tests passed; product behavior/timeout не менялись по догадке. Одна свежая
localVM с тем же Linuxproductcode прошла9checks/reboot/update/CLI (login4.938s).
Две instrumented hostedVM ещё pending. Не выдавать четыре green workflows за all5.
C15-D06 isolatedBao restore: activeleader readiness перед единственным force-write;
local9 и новый hostedrestore9 passed. HTTPstatus старого failure не сохранился,
его точная причина не доказана. Исторические failures сохранены в C15-defects.json.

Следующий Windows runtime блок — [точный план](plans/surveyscan-v2/decisions/C15-windows-profile-next.md):
отдельный profile1.2/overall budget/appliedprogress/offlinecache, затем secure Windows
state/DACL/reparse/locks/hostcontinuity, SCM/update/ordinaryrights/Windows11/actualreboot.
Новый actor удерживает один provider slot при noncooperative cancel; это не обещание
убить произвольный in-process call. Windows SDK использует отдельные child processes.
[Handoff](plans/surveyscan-v2/handoffs/C15.md), [scheduler](plans/surveyscan-v2/evidence/C15-independent-collection.json),
[providers](plans/surveyscan-v2/evidence/C15-all-provider-workers.json).

E1 frozen: actualsoak86400.914s/2740samples/1419observations/двеrenewals, одинUID/queuesempty,
source8560f57; отдельный authdelta39e401f (5→8s без ослабленияArgon2/rates/slots) all4hosted
иVM9+9. Candidate27files/Chromium16 — внутренний, не официальныйrelease. C15 binaries
не подменяют этот candidate или24hproof; нового24h прогона нет.

Продолжать автоматически по R020/022/023; mainmerge/officialrelease/productiondeploy/
повторная cloud settings publication не выполнялись. E1 private keys/reports не копировать
и не перезаписывать. C15 stand — свои DB/ports/scopedmounts/processes, E1devcredentials
read-only; не запускать C15dev up/down/reset с общими E1project/ports.57done не увеличивать
без фактической приёмки. История — REQUESTS, подробные proof/ограничения — handoff/evidence.
