# Изолированный native Windows baseline

Пакет C15.02 пока не вызывается agent.Collect/scheduler/enrollment и не отправляет observations.
Windows/amd64: GetComputerNameEx, ограниченное чтение MachineGuid (HKLM64,256bytes),
RtlGetVersion и локальные интерфейсы Go/Windows. Без shell/PowerShell, удалённых целей,
секретов и пользовательских файлов. MachineGuid — только inventory candidate, не asset_uid.

Три секции всегда partial (baseline coverage), ещё девять — unsupported с
ADAPTER_NOT_IMPLEMENTED. Нет утверждения о полном Windows inventory; недоступная API-секция
не маскируется пустым ok. Контекст проверяется между вызовами, но не прерывает синхронный Win32
вызов посередине. До COM/QFE нужны отдельные конечные timeout/worker limits.

`go test -v ./internal/agent/windowsinventory` запускается только на Windows. Native facts
проверяются через отдельный payload validator с синтетическим origin/scope/sequence;
нет HTTP/mTLS/БД/projection, host binding, DACL/spool/process lock, SCM, update/reboot.
CI runner Windows Server 2022 имеет свои права; это не стандартный пользователь/LocalService
и не Windows 11 compatibility proof. Полные C15.02–04 ещё не завершены.
