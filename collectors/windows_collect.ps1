<#
  Коллектор сканера обследования для Windows (PowerShell 5.1+).
  Только чтение: ничего не меняет на хосте (secedit /export пишет во временный файл и удаляет его).
  Запуск от имени локального администратора:
     powershell -NoProfile -ExecutionPolicy Bypass -File windows_collect.ps1 -Out C:\Temp\host.json
  Удалённо: Invoke-Command -ComputerName HOST -FilePath .\windows_collect.ps1 (результат — JSON в stdout).
#>
param([string]$Out = "")

$ErrorActionPreference = "SilentlyContinue"
$CollectorVersion = "0.1"

function Get-RegValue($Path, $Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# --- ОС
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cv = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$osInfo = [ordered]@{
    caption        = $os.Caption
    version        = $os.Version
    build          = [string]$os.BuildNumber
    ubr            = [string](Get-RegValue $cv "UBR")
    display_version = Get-RegValue $cv "DisplayVersion"
    edition_id     = Get-RegValue $cv "EditionID"
    installation_type = Get-RegValue $cv "InstallationType"   # Client / Server / Server Core
    architecture   = $os.OSArchitecture
    product_type   = [int]$os.ProductType                      # 1 АРМ, 2 КД, 3 сервер
    domain         = $cs.Domain
    part_of_domain = [bool]$cs.PartOfDomain
    last_boot      = [string]$os.LastBootUpTime
}

# --- Сеть
$netCfgs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True")
$ips = @($netCfgs | ForEach-Object { $_.IPAddress } | Where-Object { $_ })

# --- Сетевые интерфейсы (MAC, IP, маска, шлюз, DNS, DHCP)
$interfacesNet = @()
try {
    $adaptersByIdx = @{}
    Get-CimInstance Win32_NetworkAdapter -ErrorAction Stop | ForEach-Object { $adaptersByIdx[$_.InterfaceIndex] = $_ }
    $interfacesNet = @($netCfgs | ForEach-Object {
        $ad = $adaptersByIdx[$_.InterfaceIndex]
        [ordered]@{
            name = if ($ad) { $ad.NetConnectionID } else { $_.Description }
            mac = $_.MACAddress
            status = if ($ad) { switch ($ad.NetConnectionStatus) { 2 { "Connected" } 7 { "Disconnected" } default { [string]$ad.NetConnectionStatus } } } else { $null }
            ip = @($_.IPAddress)
            mask = @($_.IPSubnet | Where-Object { $_ -notmatch ":" })
            gateway = @($_.DefaultIPGateway)
            dns = @($_.DNSServerSearchOrder)
            dhcp_enabled = [bool]$_.DHCPEnabled
            dhcp_server = $_.DHCPServer
        }
    })
} catch {}

# --- Таблица маршрутизации
$routes = @()
try {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.NextHop -ne "0.0.0.0" -or $_.DestinationPrefix -ne "0.0.0.0/0" } | ForEach-Object {
        [ordered]@{ destination = $_.DestinationPrefix; gateway = $_.NextHop; interface = $_.InterfaceAlias; metric = $_.RouteMetric }
    })
} catch {
    try {
        $routes = @(Get-CimInstance Win32_IP4RouteTable -ErrorAction Stop | ForEach-Object {
            [ordered]@{ destination = "$($_.Destination)/$($_.Mask)"; gateway = $_.NextHop; interface = [string]$_.InterfaceIndex; metric = $_.Metric1 }
        })
    } catch {}
}

# --- Обновления (KB)
$hotfixes = @(Get-HotFix | ForEach-Object {
    [ordered]@{ id = $_.HotFixID; description = $_.Description; installed_on = [string]$_.InstalledOn }
})

# --- Установленное ПО (64 и 32 бит)
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$software = @(Get-ItemProperty $uninstallPaths | Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
    ForEach-Object {
        [ordered]@{ name = $_.DisplayName; version = [string]$_.DisplayVersion; vendor = $_.Publisher;
                    install_date = [string]$_.InstallDate }
    } | Sort-Object { $_.name } -Unique)

# --- Службы
$services = @(Get-CimInstance Win32_Service | ForEach-Object {
    [ordered]@{ name = $_.Name; display = $_.DisplayName; start_mode = $_.StartMode; state = $_.State;
                account = $_.StartName; path = $_.PathName; description = $_.Description }
})

# --- Локальные учётные записи и администраторы
$users = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
    [ordered]@{ name = $_.Name; disabled = [bool]$_.Disabled; password_required = [bool]$_.PasswordRequired;
                password_expires = [bool]$_.PasswordExpires; sid = $_.SID }
})
$admins = @()
try {
    $admins = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop | ForEach-Object { [string]$_.Name })
} catch {
    $admins = @((net localgroup Administrators 2>$null) | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch "^The command|^Команда" })
}

# --- Локальные группы безопасности и их состав
$groups = @()
try {
    $wmiGroups = @(Get-CimInstance Win32_Group -Filter "LocalAccount=True" -ErrorAction Stop)
    $wmiAssoc = @(Get-CimInstance Win32_GroupUser -ErrorAction Stop)
    $groups = @($wmiGroups | ForEach-Object {
        $g = $_
        $gnamePattern = 'Name\s*=\s*"' + [regex]::Escape($g.Name) + '"'
        $members = @($wmiAssoc | Where-Object { $_.GroupComponent.ToString() -match $gnamePattern } |
            ForEach-Object { if ($_.PartComponent.ToString() -match 'Name\s*=\s*"([^"]+)"') { $Matches[1] } })
        [ordered]@{ name = $g.Name; sid = $g.SID; description = $g.Description; members = $members }
    })
} catch {}

# --- Диски, общие папки, USB-устройства
$disks = @()
try {
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop | ForEach-Object {
        [ordered]@{ id = $_.DeviceID; name = $_.VolumeName; size_gb = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { $null };
                    free_gb = if ($null -ne $_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 1) } else { $null } }
    })
} catch {}
$shares = @()
try {
    $shares = @(Get-CimInstance Win32_Share -Filter "Type=0" -ErrorAction Stop | ForEach-Object {
        [ordered]@{ name = $_.Name; path = $_.Path; description = $_.Description }
    })
} catch {}
$usbDevices = @()
try {
    $usbDevices = @(Get-CimInstance Win32_PnPEntity -Filter "PNPDeviceID LIKE 'USB%'" -ErrorAction Stop |
        Where-Object { $_.Name } | ForEach-Object {
            [ordered]@{ name = $_.Name; device_id = $_.PNPDeviceID; description = $_.Description }
        })
} catch {}

# --- Локальная политика безопасности (secedit)
$secedit = [ordered]@{}
$tmp = [System.IO.Path]::GetTempFileName()
secedit /export /cfg $tmp /quiet | Out-Null
if (Test-Path $tmp) {
    $section = ""
    foreach ($line in Get-Content $tmp -Encoding Unicode) {
        if ($line -match "^\[(.+)\]$") { $section = $Matches[1]; $secedit[$section] = [ordered]@{}; continue }
        if ($section -and $line -match "^\s*(.+?)\s*=\s*(.*)$") { $secedit[$section][$Matches[1]] = $Matches[2] }
    }
    Remove-Item $tmp -Force
}

# --- Политика аудита (auditpol, CSV без локализации заголовков)
$auditpol = [ordered]@{}
$csv = auditpol /get /category:* /r 2>$null
if ($csv) {
    $csv | ConvertFrom-Csv | ForEach-Object {
        $guid = $_."Subcategory GUID"; if (-not $guid) { $guid = $_.PSObject.Properties.Value[3] }
        $setting = $_."Inclusion Setting"; if (-not $setting) { $setting = $_.PSObject.Properties.Value[4] }
        $name = $_.Subcategory; if (-not $name) { $name = $_.PSObject.Properties.Value[2] }
        # Setting Value не зависит от языка ОС: 0 — нет, 1 — успех, 2 — отказ, 3 — успех и отказ
        $value = $_."Setting Value"; if ($null -eq $value) { $value = $_.PSObject.Properties.Value[6] }
        if ($guid) { $auditpol[$guid.Trim("{}").ToUpper()] = [ordered]@{ name = $name; setting = $setting; value = [string]$value } }
    }
}

# --- Значения реестра, используемые проверками
$regList = @(
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"),
    @("HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"),
    @("HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature"),
    @("HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "MinEncryptionLevel"),
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin"),
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs"),
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"),
    @("HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "MaxIdleTime"),
    @("HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging")
)
$registry = [ordered]@{}
foreach ($r in $regList) {
    $key = ($r[0] -replace "^HKLM:\\", "HKLM\") + "\" + $r[1]
    $registry[$key] = Get-RegValue $r[0] $r[1]
}
$smb1Feature = $null
try { $smb1Feature = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}

# --- Межсетевой экран
$firewall = [ordered]@{}
try { Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $firewall[[string]$_.Name] = [bool]$_.Enabled } } catch {}

# --- Слушающие порты и установленные соединения
$listening = @()
$connections = @()
try {
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    $listening = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        [ordered]@{ proto = "tcp"; address = $_.LocalAddress; port = $_.LocalPort; process = $procs[[int]$_.OwningProcess] }
    })
    $listening += @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
        [ordered]@{ proto = "udp"; address = $_.LocalAddress; port = $_.LocalPort; process = $procs[[int]$_.OwningProcess] }
    })
    $connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
        [ordered]@{ local_address = $_.LocalAddress; local_port = $_.LocalPort;
                    remote_address = $_.RemoteAddress; remote_port = $_.RemotePort;
                    process = $procs[[int]$_.OwningProcess] }
    })
} catch {}

# --- Антивирус (Центр безопасности есть только на клиентских ОС) и Defender
$av = @()
try { $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
        ForEach-Object { [ordered]@{ name = $_.displayName; state = $_.productState } }) } catch {}
$defender = $null
try { $d = Get-MpComputerStatus -ErrorAction Stop
      $defender = [ordered]@{ enabled = $d.AMServiceEnabled; realtime = $d.RealTimeProtectionEnabled; signatures = [string]$d.AntivirusSignatureLastUpdated } } catch {}

# Вызовы, которые могут выбросить исключение, — отдельно: иначе при сбое (например, DNS)
# не соберётся вся итоговая структура
$isAdmin = $null
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
$hostname = $env:COMPUTERNAME
if (-not $hostname) { $hostname = [System.Net.Dns]::GetHostName() }
$fqdn = $null
try { $fqdn = [System.Net.Dns]::GetHostEntry($hostname).HostName } catch {}

$result = [ordered]@{
    meta     = [ordered]@{ collector = "windows_collect.ps1"; version = $CollectorVersion;
                           collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
                           is_admin = $isAdmin }
    host     = [ordered]@{ hostname = $hostname; fqdn = $fqdn; ips = $ips }
    os       = $osInfo
    hotfixes = $hotfixes
    software = $software
    facts    = [ordered]@{
        services = $services; users = $users; admins = $admins; groups = $groups; secedit = $secedit; auditpol = $auditpol;
        registry = $registry; smb1_enabled = $smb1Feature; firewall = $firewall; listening = $listening;
        connections = $connections; nics = $interfacesNet; routes = $routes;
        disks = $disks; shares = $shares; usb_devices = $usbDevices;
        antivirus = $av; defender = $defender
    }
}

$json = $result | ConvertTo-Json -Depth 6
if ($Out) { [System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false))) }
else { $json }
