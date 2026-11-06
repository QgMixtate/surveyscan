# E1 — черновик приёмки, не release approval

Версия архитектуры0.5. Текущий итог: C14.01/02 выполнены; C14.03 выполняется; C14.04planned.
Поставка ограничена Linux/amd64 E1:3-section host inventory, постоянный agent→collector→center,
PG17, OpenBao2.7 scopednon-exportable PKI, отдельный Web/CLI,32+1immutable SQL migrations.
Windows/native8-section baseline — отдельный C15/E2, не часть E1 acceptance.

Actual24h на clean8560f57 завершён6ноября00:31:51UTC (03:31:51МСК):86400.914s,2740samples,
1419observations,2realcertificate renewals, recovery fault points, finaldrain/UID/dedup passed.
Воспроизводимость/scope/хеши — C14-soak-result.json и неизменённый C14-soak.json.
После measurement auth diagnostics менялись: отдельная delta-regression обязательна;
не выдавать frozen measured binary за hash нового release candidate.

Блокирующие пункты: D08 recurringCLI503/internalcause не установлен; D09 localHPETkernelstall
fixture replacement pending. Успешные native repeats не стирают failures.
Controlled PGdeadline rollback проверен, CPUcounterexample ещё выполняется.

Готовность будущей C14.04: повторить затронутое, собрать кандидатизточного проверенногоsource,
проверить manifest/signature/checksums/staging/version/rollback и staticWeb на егоартефактах;
свести15сценариев C14-plan.json в итоговый протокол с failed/unrun иограничениями.
Test signing anchor не является production trust; ключи не публиковать.
Mainmerge/productiondeployment/официальный GitHubRelease этим документом не выполняются.

Проверено только bounded Debian12/systemd252 VM иdevstand; externalPG/Bao/TLS prerequisite
предоставляетсяоператором. Нет productionKMS/HA/geo/100-userSLA/physicalpowerloss/Windowsreboot
илиполного Linuxinventory claim.
