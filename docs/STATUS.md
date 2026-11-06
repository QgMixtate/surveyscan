# Текущее состояние surveyscan

6 ноября 2026. **57/200 done; C15.02 in_progress.** C14 принят в bounded Linux E1,
C15.01 design done; C15.03/04 и C16–C50 ещё не приняты.

Рабочая ветка codex/v2-c15-windows, worktree /workspace/surveyscan-c15,
[draft PR5](https://github.com/QgMixtate/surveyscan/pull/5), base E1 изPR4.
**Последний product code —d4ae425; все5 hosted workflows SUCCESS.**
[Exact SHA/runs +23sanitized reports иboot hashes](plans/surveyscan-v2/evidence/C15-hosted-d4.json).
Docs-only commits с[skip ci] не меняют проверенный product code.

Реализовано в текущем C15 срезе:

- Opt-in partial inventory1.2 center+collector admission/crypto/scope/durable relay,
  typed per-field projection/provenance и revision-bound fact-page API. Default
  inventory12_enabled false. Complete/deletion отклоняется; C03/C09/C12 неизменны.
- Две подписанные capabilities роли, nonce/tenant/audiences/generations/expiry,
  pinned center иTLS-attested collector keys, quota-aware three-hop intersection.
  Go agent method готов; Windows daemon его ещё не вызывает.
- Один read-only collection task вне serial state actor: heartbeat продолжает
  работать при blocked collection; counters/sign/TLS/spool меняет только actor.
- Все12native Windows providers — bounded ownbinary child processes. Сбой одного
  сохраняет остальные. Backoff sender сбрасывается на durable verifiedACK progress,
  даже если новый пакет ещё processing; transport receipt не считаетсяprogress.

Проверки d4: PG58, verify/C03 58, agent/collector/wire race, center6/relay10 на настоящих
mTLS/scopednonexportableTransit/PG (agentdata синтетические), livecompiledLinuxagent11,
real3agent reconnect/quota/replay5, isolatedBao restore9 идвеfreshLinuxVM9+9 с реальным
kernelreboot/systemd/update/CLI. NativeWindows2022/elevated all12 иCOM+software failure/
kill-reap passed. Это не Windows11/ordinaryrights/SCM/continuousWindowsdelivery.

C15-D06 restore readiness guard прошёл; исходный HTTPstatus/rootcause не сохранился.
C15-D07 старый bootqueue timeout не повторился в3freshVM на прежнем productcode и
2freshVM с новым независимым D08fix; историческая причина не доказана.
[Журнал дефектов](plans/surveyscan-v2/evidence/C15-defects.json) сохраняет failures.

**Следующий код:** [Windows profile1.2/runtime plan](plans/surveyscan-v2/decisions/C15-windows-profile-next.md).
Нужны отдельный profile/budget/appliedprogress/offlinecache и secure Windows state/
DACL/reparse/atomicfiles/lock/hostcontinuity внутриC15.02. SCM/install/update/reboot —
C15.03/04 после его приёмки. Полное providercoverage не заявлено. Не увеличивать57done.
[Handoff](plans/surveyscan-v2/handoffs/C15.md); текущие правила AGENTS83lines,
полный прежний checkpointarchive сохранён без потерь в AGENTS_HISTORY.md.

E1 frozen: actualsoak86400.914s/2740samples/1419observations/2renewals/oneUID/queuesempty
на8560f57. Отдельный authdelta39e401f all4hosted/VM9+9, candidate27files/Chromium16 —
внутренний. C15 binaries не подменяют candidate/24hproof; нового24h прогона нет.

Продолжать автоматически по R020/022/023. Mainmerge/officialrelease/productiondeploy/
повторная cloud settings publication не выполнялись. SQL34/47ownedtables, applied0000–0033
immutable. E1 privatekeys/reports не копировать/не перезаписывать; C15test свои DB/ports/
mounts/processes, E1devcredentials read-only. Не запускать C15dev up/down/reset с общими
E1project/ports. История в REQUESTS и handoff/evidence; старые pending markers исторические.
