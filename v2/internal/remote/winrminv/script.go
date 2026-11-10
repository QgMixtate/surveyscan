package winrminv

// Script — единственный сценарий, выполняемый на цели. Только чтение (Get-CimInstance, Get-ItemProperty),
// ничего не пишется на диск цели, нет пользовательских данных в тексте сценария. Вывод — один JSON-объект.
// Совместим с Windows PowerShell 5.1. Проверка на живой цели НЕ выполнена (см. C18.04).
const Script = `
$ErrorActionPreference = 'Stop'
function Safe([scriptblock]$b) { try { & $b } catch { $null } }
$os   = Safe { Get-CimInstance Win32_OperatingSystem }
$cs   = Safe { Get-CimInstance Win32_ComputerSystem }
$prod = Safe { Get-CimInstance Win32_ComputerSystemProduct }
$bios = Safe { Get-CimInstance Win32_BIOS }
$cpu  = Safe { @(Get-CimInstance Win32_Processor) }
$nics = Safe { @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true') }
$svcs = Safe { @(Get-CimInstance Win32_Service) }
$sw = @()
foreach ($v in @(@('64','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'), @('32','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'))) {
  $items = Safe { @(Get-ItemProperty -Path ($v[1] + '\*')) }
  foreach ($i in $items) { if ($i.DisplayName) { $sw += [pscustomobject]@{ view = $v[0]; key = $i.PSChildName; name = $i.DisplayName; version = $i.DisplayVersion; vendor = $i.Publisher } } }
}
$result = [pscustomobject]@{
  hostname = $env:COMPUTERNAME
  domain   = if ($cs) { $cs.Domain } else { $null }
  uuid     = if ($prod) { $prod.UUID } else { $null }
  os       = if ($os) { [pscustomobject]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; arch = $os.OSArchitecture; boot = $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); memory_kb = $os.TotalVisibleMemorySize } } else { $null }
  bios     = if ($bios) { [pscustomobject]@{ vendor = $bios.Manufacturer; version = $bios.SMBIOSBIOSVersion; serial = $bios.SerialNumber } } else { $null }
  cpu_logical = if ($cpu) { ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum } else { $null }
  cpu_name = if ($cpu) { $cpu[0].Name } else { $null }
  nics     = @($nics | ForEach-Object { [pscustomobject]@{ index = $_.InterfaceIndex; name = $_.Description; mac = $_.MACAddress; ips = @($_.IPAddress); masks = @($_.IPSubnet); dns = @($_.DNSServerSearchOrder); gateways = @($_.DefaultIPGateway); dhcp = [bool]$_.DHCPEnabled; mtu = $_.MTU } })
  services = @($svcs | ForEach-Object { [pscustomobject]@{ name = $_.Name; display = $_.DisplayName; state = $_.State; mode = $_.StartMode; account = $_.StartName; path = $_.PathName } })
  software = $sw
}
# Output is ASCII only (non-ASCII -> \uXXXX) so the WinRM console code page cannot corrupt the JSON.
$json = $result | ConvertTo-Json -Depth 5 -Compress
[regex]::Replace($json, '[^\x00-\x7F]', { param($m) ('\u{0:x4}' -f [int][char]$m.Value) })
`
