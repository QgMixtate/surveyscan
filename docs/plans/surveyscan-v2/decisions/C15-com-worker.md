# C15: ограниченный COM/WMI worker

Windows-only `surveyscan-agent inventory-worker updates|protection` читает только
фиксированные локальные API. Команда не открывает agent config/keys/enrollment и
не принимает executable, namespace, WQL, script или target из профиля.

Parent использует текущий executable, Context30s, terminate+Wait/reap и1MiB stdout
limit. Stderr не экспортируется. Ответ проходит draft1.2 Section schema/JCS/
count/name/time validation. Timeout/cancel/crash/oversize/malformed становятся
безопасным unavailable; остальные native секции продолжаются. Блокировка COM
ограничена жизнью worker, не оставляет зависшую goroutine внутри agent.

COM worker привязан к OS thread, CoInitializeEx(MTA)/CoUninitialize, освобождает
IUnknown/IDispatch/VARIANT/enumerator references. go-ole1.3.0(MIT) зафиксирован
вgo.mod/go.sum; shell/PowerShell и Win32_Product не используются.

Updates: локальный QFE subset, HotFixID/Description и только однозначнаяISOdate.
Локализованные/FILETIME InstalledOn не угадываются; нет обещания полного patch history.
Protection: INetFwPolicy2 boolean perDomain/Private/Public; MSFT_MpComputerStatus
boolean properties; SecurityCenter2 AV displayName и opaque productState без
предположений о bitfields. Missing provider/denied/error не означают отсутствие AV.
Partial rows сохраняются, fullcoverage/новый wire pipeline пока не приняты.

Tests distinguish actual Windows agent subprocess/COM from synthetic child
hang/crash/oversize/canary/malformed probes. Ordinary-user/LocalService/Windows11
и direct production service lifecycle пока unrun. Worker child inherits process
account; принцип наименьших прав и Windows DACL — следующий lifecycle gate.
