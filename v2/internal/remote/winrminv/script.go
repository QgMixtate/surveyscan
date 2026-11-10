package winrminv

// Script — единственный сценарий, выполняемый на цели. Только чтение (Get-CimInstance, Get-ItemProperty),
// ничего не пишется на диск цели, нет пользовательских данных в тексте сценария. Вывод — один JSON-объект, только ASCII.
// Каждая ошибка источника фиксируется в errors как «источник:категория» (категория PowerShell не зависит от языка ОС),
// общий сбой — поле fatal. Сценарий не должен молчать. Совместим с Windows PowerShell 5.1.
const Script = `
$ErrorActionPreference = 'Stop'
$errs = New-Object System.Collections.ArrayList
function Safe([string]$n, [scriptblock]$b) { try { & $b } catch { [void]$errs.Add($n + ':' + $_.CategoryInfo.Category); $null } }
function Out-Ascii([string]$s) { [regex]::Replace($s, '[^\x00-\x7F]', { param($m) ('\u{0:x4}' -f [int][char]$m.Value) }) }
try {
  $os   = Safe 'os'   { Get-CimInstance Win32_OperatingSystem }
  $cs   = Safe 'cs'   { Get-CimInstance Win32_ComputerSystem }
  $prod = Safe 'prod' { Get-CimInstance Win32_ComputerSystemProduct }
  $bios = Safe 'bios' { Get-CimInstance Win32_BIOS }
  $cpu  = Safe 'cpu'  { @(Get-CimInstance Win32_Processor) }
  $nics = Safe 'nics' { @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true') }
  $svcs = Safe 'svcs' { @(Get-CimInstance Win32_Service) }
  $guid = Safe 'guid' { (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid }
  $sw = New-Object System.Collections.ArrayList
  foreach ($v in @(@('64','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'), @('32','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'))) {
    $items = Safe ('sw' + $v[0]) { @(Get-ItemProperty -Path ($v[1] + '\*')) }
    foreach ($i in $items) { if ($i.DisplayName) { [void]$sw.Add([pscustomobject]@{ view = $v[0]; key = $i.PSChildName; name = $i.DisplayName; version = $i.DisplayVersion; vendor = $i.Publisher }) } }
  }
  $r = [ordered]@{ hostname = $env:COMPUTERNAME; errors = @($errs) }
  if ($cs)   { $r.domain = $cs.Domain }
  if ($prod) { $r.uuid = $prod.UUID }
  if ($guid) { $r.machine_guid = [string]$guid }
  if ($os)   { $r.os = [pscustomobject]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; arch = $os.OSArchitecture; boot = $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); memory_kb = $os.TotalVisibleMemorySize } }
  if ($bios) { $r.bios = [pscustomobject]@{ vendor = $bios.Manufacturer; version = $bios.SMBIOSBIOSVersion; serial = $bios.SerialNumber } }
  if ($cpu)  { $r.cpu_logical = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum; $r.cpu_name = $cpu[0].Name }
  $r.nics = @($nics | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ index = $_.InterfaceIndex; name = $_.Description; mac = $_.MACAddress; ips = @($_.IPAddress); masks = @($_.IPSubnet); dns = @($_.DNSServerSearchOrder); gateways = @($_.DefaultIPGateway); dhcp = [bool]$_.DHCPEnabled; mtu = $_.MTU } })
  $r.services = @($svcs | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ name = $_.Name; display = $_.DisplayName; state = $_.State; mode = $_.StartMode; account = $_.StartName; path = $_.PathName } })
  $r.software = @($sw)
  Out-Ascii (([pscustomobject]$r) | ConvertTo-Json -Depth 5 -Compress)
} catch {
  Out-Ascii ('{"fatal":"' + ([string]$_.CategoryInfo.Category) + '","errors":["fatal:' + ([string]$_.CategoryInfo.Category) + '"]}')
}
`
