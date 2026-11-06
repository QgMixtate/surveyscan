# Native Windows inventory baseline

Windows/amd64 SDK собирает12partialsections. Он ещё не подключён к enrollment,
постоянной Windows-службе и доставке observations. Native WindowsServer2022/elevated
на2fe4b93 проверен workflow42233417128; это не Windows11/ordinary rights/SCM/reboot.

Каждая секция запускается отдельным child того же agent binary через закрытый
inventory-worker <section>:30s context deadline,1s WaitDelay,1MiB stdout, schema/
semantic validation, cancellation/kill/wait. Raw stderr не экспортируется. Worker
не читает config/keys/grants и не принимает executable/query/remote target. Сбой
одного provider сохраняет остальные sections. Это process isolation; sandbox или
отдельный Windows security token не заявлен. Общий12-section sweep имеет отдельный
parent deadline и может длиться дольше30s.

Read-only источники:

- Identity/OS/network: GetComputerNameEx, ограниченный HKLM64 MachineGuid, RtlGetVersion,
  локальные NIC/IPv4/IPv6. MachineGuid — candidate/continuity input, не asset_uid.
- Hardware/resources: CPU/RAM/BIOS, fixed volumes/free space. Remote/removable probes
  запрещены; full hardware coverage не заявлен.
- Software: Uninstall HKLM32/64 и HKCU текущего token, registry_key/provider scope/view,
  current-token SID дляHKCU. Другие user hives не загружаются; Win32_Product не используется.
- Services: read-only SCM CONNECT/ENUMERATE; command lines/config/ALL_ACCESS не запрашиваются.
- Accounts: local SAM NetUserEnum/NetLocalGroupEnum/NetLocalGroupGetMembers, публичные
  SID/membership; bounded pages/rows/buffers. AD resolution иSAM/LSA secrets отсутствуют.
  На domaincontroller local SAM unsupported, API перечисления не вызываются.
- Routes/neighbors: локальные IPv4/IPv6 route tables иARP/NDP cache, без discovery packets,
  neighbor resolution/LLDP/CDP. Interface index связывает текущий снимок, не постоянный NICUID.
- Updates/protection: QFE subset/ISO dates, firewall INetFwPolicy2, Defender boolean
  properties, opaque SecurityCenter2 productState. COM references освобождаются в child.

Все baseline sections остаются partial/complete=false. Недоступный provider не означает
пустой ok; authoritative scoped deletion не реализовано. Worker output1MiB не расширяет
transport: canonical512KiB/envelope576KiB/batch768KiB и negotiated lower ceilings.

Проверка на Windows из v2:

```powershell
go build -o surveyscan-agent.exe ./cmd/surveyscan-agent
$env:SURVEYSCAN_C15_TEST_AGENT = (Resolve-Path .\surveyscan-agent.exe).Path
go test -count=1 -v ./internal/agent/windowsinventory
```

Built binary обязателен для native worker tests; без него они явно skip. Override
SURVEYSCAN_C15_TEST_AGENT используется только testmain, production — os.Executable.
Native tests и synthetic timeout/crash/invalid/overflow/canary/kill-reap тесты различаются.
Новый software crash test сохраняет identity/OS и последующие services.

На C15 ветке Linux agent scheduler уже разделяет read-only collection и serial state
actor. Windows profile1.2/overall budget, secure DACL/reparse/atomic files, host binding,
exclusive process lock, SCM/update/ordinary rights/actual reboot ещё gates. Старые E1
soak/candidate относятся к frozen Linux binaries и не подтверждают новый Windows runtime.
