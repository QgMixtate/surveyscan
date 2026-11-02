# Исполняются только выбранные блоки коллектора с заглушками команд, без опроса ОС.
$ErrorActionPreference = "Stop"
$source = Get-Content (Join-Path $PSScriptRoot "../collectors/windows_collect.ps1") -Raw
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) { throw ($errors | Out-String) }
function Slice($Start, $End) {
    $from = $source.IndexOf($Start)
    $to = $source.IndexOf($End, $from + $Start.Length)
    if ($from -lt 0 -or $to -lt 0) { throw "Не найден блок коллектора" }
    [scriptblock]::Create($source.Substring($from, $to - $from))
}
. (Slice '$collectionStatus =' 'function Get-RegValue')
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }

$empty = @(Read-Inventory "empty" { })
Assert ($empty.Count -eq 0 -and $collectionStatus.empty -eq "ok") "Пустой успешный сбор"
$denied = @(Read-Inventory "denied" { throw "denied" })
Assert ($denied.Count -eq 0 -and $collectionStatus.denied -eq "unavailable") "Недоступные данные"
$partial = @(Read-Inventory "partial" { [pscustomobject]@{id=1}; throw "interrupted" })
Assert ($partial.Count -eq 1 -and $collectionStatus.partial -eq "partial") "Сохранение частичных данных"

function Get-Process { [pscustomobject]@{Id=7; ProcessName="test"} }
function Get-NetTCPConnection { [pscustomobject]@{State="Established";LocalAddress="10.0.0.2";LocalPort=22;RemoteAddress="10.0.0.3";RemotePort=50000;OwningProcess=7} }
function Get-NetUDPEndpoint { throw "UDP denied" }
. (Slice '# --- Слушающие порты' '# --- Антивирус')
Assert ($connections.Count -eq 1 -and $collectionStatus.connections -eq "ok") "UDP не должен прерывать сбор TCP"
Assert ($collectionStatus.listening -eq "unavailable") "Нет данных о слушающих портах"

function Get-CimInstance($ClassName) {
    switch ($ClassName) {
        "Win32_Group" { [pscustomobject]@{Name="Operators";Domain="HOST";SID="S-1"} }
        "Win32_GroupUser" {
            if ($script:denyMembers) { throw "members denied" }
            [pscustomobject]@{GroupComponent=[pscustomobject]@{Name="Operators";Domain="HOST"};PartComponent=[pscustomobject]@{Name="alex";Domain="DOMAIN"}}
            [pscustomobject]@{GroupComponent=[pscustomobject]@{Name="Operators";Domain="OTHER"};PartComponent=[pscustomobject]@{Name="wrong";Domain="OTHER"}}
        }
        "Win32_LogicalDisk" { [pscustomobject]@{DeviceID="C:";VolumeName="System";Size=100GB;FreeSpace=0} }
        "Win32_Share" { }
        "Win32_PnPEntity" { throw "USB denied" }
        "Win32_NetworkAdapterConfiguration" { [pscustomobject]@{InterfaceIndex=1;Description="Ethernet";IPAddress=@("10.0.0.2","2001:db8::2");IPSubnet=@("255.255.255.0","64");DHCPEnabled=$false} }
        "Win32_NetworkAdapter" { throw "adapter denied" }
        "Win32_IP4RouteTable" { [pscustomobject]@{Destination="0.0.0.0";Mask="0.0.0.0";NextHop="10.0.0.1";InterfaceIndex=1;Metric1=0} }
        default { throw "Неожиданный запрос: $ClassName" }
    }
}
function Get-NetRoute { throw "Use fallback" }
. (Slice '# --- Сеть' '# --- Обновления')
Assert ($interfacesNet.Count -eq 1 -and $collectionStatus.nics -eq "partial") "Сохранение NIC при сбое метаданных адаптера"
Assert ($interfacesNet[0].mask[1] -eq "64") "Маски должны соответствовать IPv4/IPv6"
Assert ($routes.Count -eq 1 -and $collectionStatus.routes -eq "ok") "Запасной сбор маршрутов"

. (Slice '# --- Локальные группы' '# --- Локальная политика')
Assert ($groups[0].members.Count -eq 1 -and $groups[0].members[0] -eq "DOMAIN\alex") "CIM-ссылки и домены участников группы"
Assert ($disks[0].free_gb -eq 0) "Нулевое свободное место"
Assert ($shares.Count -eq 0 -and $collectionStatus.shares -eq "ok") "Пустые общие папки"
Assert ($usbDevices.Count -eq 0 -and $collectionStatus.usb_devices -eq "unavailable") "Недоступные USB"
$script:denyMembers = $true
. (Slice '# --- Локальные группы' '# --- Локальная политика')
Assert ($groups.Count -eq 1 -and $null -eq $groups[0].members -and $collectionStatus.groups -eq "partial") "Группы без доступного состава"
Write-Output "Windows inventory mocks passed"
