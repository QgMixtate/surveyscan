# C15.01 — Windows: capabilities, права и границы проверки

Дата: 2026-11-06, Москва. Подготовка по R-023 параллельна C14.02; C14 остаётся
непринятым до фактического суточного PASS. Документ описывает целевую реализацию,
а не уже поддержанные Windows API. Код измеряемого Linux-прогона не меняется.

## ОС и профили

Первые цели реализации: Windows 11 x64 и Windows Server 2022 x64, включая Server Core.
Это инженерный выбор для C15, не подтверждённая совместимость. Windows ARM64,
Windows 10, старые Server и доменная GPO-доставка пока вне проверенной матрицы.
Hosted Windows Server полезен для API/SCM, но не подтверждает Windows 11 или reboot.

Два обязательных профиля проверки: обычный локальный пользователь без elevation
для доступной части инвентаря; установленная служба с явно документированной учётной
записью и ACL. Установка/удаление службы требует elevation. Целевой runtime —
LocalService с service SID и доступом только к своей конфигурации/очереди; временное
использование LocalSystem в стенде должно быть явно отмечено и не доказывает работу
LocalService. Учётная запись не получает PG/Bao credentials или секреты remote targets.

## Матрица §6.1

В колонке прав — ожидания проектирования. ACL, редакция ОС, политики и провайдеры
могут ограничивать даже администратора; доступ проверяется фактически для каждой секции.
Все API локальные, только чтение; PowerShell, cmd, WMI CLI и произвольные скрипты не нужны.

| Секция / поля | Основной API / источник | Обычные права и ограничения |
|---|---|---|
| identity: hostname/FQDN, domain, UUID/serial | GetComputerNameExW, NetGetJoinInformation; MachineGuid из HKLM 64-bit, SMBIOS UUID/serial отдельно | Hostname обычно доступен; registry/SMBIOS могут быть запрещены. DNS resolution не заменяет локальный факт домена |
| os: версия/build/arch/boot | RtlGetVersion, GetNativeSystemInfo, GetTickCount64; CurrentVersion registry для product metadata | Не полагаться на manifest-dependent GetVersionEx; boot time из uptime помечать оценкой |
| hardware: CPU/RAM/BIOS/disks | GetNativeSystemInfo, GlobalMemoryStatusEx, GetSystemFirmwareTable; SetupAPI для устройств | SMBIOS/устройства могут быть неполными; парсер проверяет размеры и границы, serial не генерируется |
| software: name/version/vendor/arch | HKLM Uninstall 64/32-bit, HKCU текущей учётной записи | HKCU службы не означает ПО всех пользователей; охват явно machine + current-user. Не обходить чужие профили |
| updates: KB и installation metadata | локальный WMI COM Win32_QuickFixEngineering; отдельный ограниченный вызов | QFE не является полной историей всех обновлений. Отсутствие provider = unavailable/unsupported, не «патчей нет» |
| services: name/display/state/start/account/path | SCM EnumServicesStatusExW, QueryServiceConfigW/2W | Пообъектные ACL; успешная часть сохраняется. Raw command line не экспортируется: только безопасно извлечённый executable, при сомнении поле опускается |
| users/groups: local SID, accounts, membership | NetUserEnum, NetLocalGroupEnum, NetLocalGroupGetMembers | Только локальные объекты, paging и лимиты; доступ к составу может быть запрещён. Не читать SAM/LSA secrets/hashes |
| network: NIC/MAC/IP/prefix/DNS/DHCP/gateway | GetAdaptersAddresses / IP Helper | Обычно доступно; VPN/virtual NIC сохраняются с признаками, loopback scope задаётся явно |
| routes/ports: route/metric/TCP/UDP/state | GetIpForwardTable2, GetExtendedTcpTable, GetExtendedUdpTable | Таблицы обычно доступны; owner details могут требовать больше прав. Нет packet capture и активного сканирования |
| resources: volumes/free/shares/USB | GetVolumePathNamesForVolumeNameW, GetDiskFreeSpaceExW, NetShareEnum, SetupAPI | Только разрешённые volumes/shares; административные детали ограничены. Не монтировать носители и не читать файлы пользователей |
| protection: firewall/AV/Defender/privileges | COM INetFwPolicy2; WMI COM SecurityCenter2 и Defender providers; token privileges | SecurityCenter2 отсутствует на ряде Server, Defender может быть удалён. Проверять каждый provider; не объявлять «защиты нет» по ошибке API |
| neighbors: ARP/NDP | GetIpNetTable2 | Только локальный cache, не полный список устройств/топология. LLDP/CDP данным host adapter не обещаны |

Не использовать Win32_Product: запрос может инициировать MSI consistency checks/repair,
что нарушает read-only сбор. AppX/MSIX и ПО других профилей не выдавать за охваченное
Uninstall-реестром; расширение coverage требует отдельного источника и проверки.

## Семантика результата и ограничения

- `ok` с пустым списком допустим только после успешного полного перечисления в заявленном scope.
- `partial` сохраняет успешные записи при ошибке объекта, достижении лимита или неполном coverage;
  недоступная секция — `unavailable`, отсутствующий в данной ОС API/provider — `unsupported`.
- Отключённая профилем секция — `not_requested`. Unknown не подменяет известную ошибку сбора.
- Причины — стабильные безопасные коды: ACCESS_DENIED, API_UNAVAILABLE, PROVIDER_UNAVAILABLE,
  TIMEOUT, LIMIT_REACHED, INVALID_API_DATA. Не отправлять raw COM/registry exceptions и command lines.
- Отдельные collected_at/count/complete для каждой секции; ошибка одной не сбрасывает остальные.
  Heartbeat не обновляет время успешного inventory. Не синтезировать значения при ошибках.
- Предлагаемые начальные пределы: 512 NIC, 100000 записей на секцию, 64 MiB общего снимка,
  30 s на секцию, 120 s на цикл. Их надо согласовать с wire/admission/spool limits до включения;
  достигнутый предел означает partial, а не молчаливое усечение.
- Контекст проверяется между страницами/вызовами. Для COM-провайдеров нужен конечный deadline
  и ограниченный worker lifecycle; timeout не должен оставлять растущее число заблокированных goroutines.

## Совместимость и обязательные изменения C15.02/03

Текущий `v2/contracts/wire.schema.json` (запечатанный C03) разрешает только identity/os/network
и фиксированные формы записей. Успешная Windows-кросс-сборка не расширяет контракт:
agent.Collect/localMachineID и process locks пока Linux-only; privatefile.Read проверяет POSIX
mode bits и ещё не подтверждает Windows DACL. Нет Windows SCM lifecycle.

Порядок реализации: сначала отдельный аддитивный C15 observation/detail contract и fixtures,
затем validator/storage/projection/API, затем Windows adapter и сервис. C03/C09 и применённые
SQL не редактировать. Номер нового wire version закрепить в новом контракте, не переиспользовать
C12 profile version. До отправки новых секций проверить поддержку обоих relay/center;
старый collector/server должен дать явную несовместимость, без потери секций и ложного ACK.
Повторная доставка сохраняет подпись/байты/sequence, downgrade не переподписывает pending spool.
Расширение API должно сохранить старый C09 shape; новые детали получают отдельную версию.

MachineGuid — признак continuity, не asset_uid и не hardware attestation. Clone с тем же GUID
и скопированным ключом неразличим только по этому признаку; нужны существующие server-side
identity conflict/revoke правила. Замена GUID не вызывает автоматическую новую регистрацию.
Обновление/repair/reboot сохраняет source ID, ключи, host binding, spool и counters.

Перед запуском службы нужны реальные DACL проверки каталога/файла/владельца/reparse points,
Windows exclusive process lock, безопасная атомарная замена/flush и тест crash recovery.
`chmod(0600)` и скомпилированный `os.Rename` не доказывают эти свойства на Windows.
SCM stop должен завершать scheduler/HTTP в конечный срок, оставляя durable записи для replay.
Install/update проверяет подпись до замены; uninstall сохраняет данные по умолчанию.

## Проверка и приёмка

Фактически 2026-11-05 UTC: Linux Go 1.27.3, GOOS=windows GOARCH=amd64 CGO_ENABLED=0,
`go build ./cmd/surveyscan-agent` завершился exit 0 на source f253a27.
Получен PE32+ x86-64; Windows executable здесь не запускался. Это только compile evidence.
Все проверки живых Windows API, стандартных прав, DACL, SCM, reboot/update и ресурсов — unrun.

C15.04 проверяет обе целевые ОС и оба профиля прав: успешный сбор/достоверно пустую секцию,
access denied/provider missing/timeout, сохранность остальных секций, Unicode/IPv6/large lists,
secret canaries, restart/actual OS reboot, offline→replay, disk full, exclusive writer,
signed update/отказ bad signature, непрерывность UID/sequence/ключей. Зафиксировать idle/collect/
offline spool CPU/RSS/IO. Hosted Windows API/SCM тесты не заменяют реальный reboot стенда.

Источники для реализации: Microsoft Learn
[GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses),
[NetUserEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum),
[Service security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
[Win32_QuickFixEngineering](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering),
[Win32_Product limitations](https://learn.microsoft.com/en-us/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications).
Это ссылки на API/ограничения, не доказательство выполнения Windows тестов.
