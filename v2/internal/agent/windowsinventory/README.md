# Изолированный native Windows baseline

Пакет C15.02 пока не вызывается agent.Collect/scheduler/enrollment и не отправляет observations.
Windows/amd64: GetComputerNameEx, ограниченное чтение MachineGuid (HKLM64,258bytes),
RtlGetVersion и локальные интерфейсы Go/Windows. Добавлены CPU/RAM/BIOS,
Uninstall HKLM32/64 + current-user, read-only SCM service states, fixed volumes/free space,
IPv4/IPv6 route table. Службы перечисляются с CONNECT/ENUMERATE, без ALL_ACCESS;
command lines/config не запрашиваются. Блокированы remote/removable drive probes. Без shell/PowerShell, удалённых целей,
секретов и пользовательских файлов. MachineGuid — только inventory candidate, не asset_uid.

Десять секций реализованы как baseline partial; neighbors ожидают Windows CI.
Две секции — updates/protection — unsupported. Девять прежних секций уже проверены. с
ADAPTER_NOT_IMPLEMENTED. Нет утверждения о полном Windows inventory; недоступная API-секция
не маскируется пустым ok. Контекст проверяется между вызовами, но не прерывает синхронный Win32
вызов посередине. До COM/QFE нужны отдельные конечные timeout/worker limits.

`go test -v ./internal/agent/windowsinventory` запускается только на Windows. Native facts
проверяются через отдельный payload validator с синтетическим origin/scope/sequence;
нет HTTP/mTLS/БД/projection, host binding, DACL/spool/process lock, SCM, update/reboot.
CI runner Windows Server 2022 имеет свои права; это не стандартный пользователь/LocalService
и не Windows 11 compatibility proof. Полные C15.02–04 ещё не завершены.

Local accounts: NetUserEnum0/FILTER_NORMAL_ACCOUNT, NetLocalGroupEnum0 и
NetLocalGroupGetMembers0. Только локальный SAM, имена и публичные SID/member SID;
32 bounded pages/64KiB buffer,512groups/10000totalrows, cancellation between calls.
SID lookup квалифицирован локальным NetBIOS host или BUILTIN; group members не
разрешаются через AD. На domaincontroller local SAM отсутствует: секция unsupported,
API перечисления не вызываются. SAM/LSA secrets и пароли не запрашиваются.
Обычные права/LocalService/DC и подробные safe reasoncodes ещё требуют полной матрицы C15.

Соседи: GetIpNetTable2/FreeMibTable читает только локальный ARP/NDP cache, без
пакетов discovery/neighbor resolution/LLDP/CDP. ABI MIB_IPNET_ROW2 проверяется на
Windows/amd64:88bytes/row, table row offset8; максимум10000rows. Interface_index
добавлен в draft networkRow для связи NIC/routes/neighbors внутри текущего снимка,
это не постоянный NICUID. Полнота топологии не заявлена.
