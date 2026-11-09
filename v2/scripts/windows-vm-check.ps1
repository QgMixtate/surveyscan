<#
 Проверка службы агента на Windows-ВМ (C15.03, V1). Запуск от администратора, Windows PowerShell 5.1+.
 Без центра: состояние готовится командой prepare, служба LocalSystem должна дойти до этапа Open и
 остановиться с SERVICE_EXIT_CODE=2 (агент не зарегистрирован). Затем служба удаляется.
 Ничего не отправляет в сеть, ключи не печатает. Результат — на экран и в файл report.txt рядом с Root.
 Пример: powershell -ExecutionPolicy Bypass -File .\windows-vm-check.ps1 -Exe C:\surveyscan\surveyscan-agent.exe
#>
param(
  [string]$Exe = 'C:\surveyscan\surveyscan-agent.exe',
  [string]$Root = 'C:\surveyscan\vmcheck',
  [string]$ServiceName = 'SurveyscanAgentVmCheck',
  [switch]$KeepState
)
$ErrorActionPreference = 'Stop'
$report = New-Object System.Collections.Generic.List[string]
function Say([string]$m) { Write-Host $m; $script:report.Add($m) }
function Fail([string]$m) { Say "FAIL: $m"; Save; exit 1 }
function Save { [System.IO.File]::WriteAllLines((Join-Path (Split-Path -Parent $Root) 'vmcheck-report.txt'), $script:report.ToArray()) }
function Utf8NoBom([string]$path, [string]$text) { [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false))) }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'нужен запуск от администратора' }
if (-not (Test-Path -LiteralPath $Exe)) { Fail "нет файла $Exe" }
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$os = Get-CimInstance Win32_OperatingSystem
Say ("host: {0} build {1}; PowerShell {2}; {3}" -f $os.Caption, $os.BuildNumber, $PSVersionTable.PSVersion, (Get-Date -Format s))
Say ("exe sha256: " + (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLower())
$version = & $Exe --version
Say ("agent: " + ($version -join ' '))

# 1) состояние только для SYSTEM и Administrators (личный SID пользователя служба отвергла бы)
$cfg = Join-Path $Root 'cfg'; $state = Join-Path $Root 'state'
if (Test-Path -LiteralPath $Root) { Fail "$Root уже существует; удалите или укажите другой -Root" }
New-Item -ItemType Directory -Force -Path $cfg | Out-Null
& icacls $cfg /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'icacls для каталога' }
$config = @{ tenant_id = [guid]::NewGuid().ToString(); site_id = [guid]::NewGuid().ToString(); network_scope_id = [guid]::NewGuid().ToString();
  collector_url = 'https://collector.invalid'; collector_source_id = [guid]::NewGuid().ToString(); ca_certificate_file = (Join-Path $cfg 'ca.pem'); state_directory = $state } | ConvertTo-Json
$file = Join-Path $cfg 'agent.json'
Utf8NoBom $file $config
& icacls $file /inheritance:r /grant:r 'SYSTEM:F' 'BUILTIN\Administrators:F' | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'icacls для файла' }

# 2) prepare (идемпотентен)
$p1 = (& $Exe prepare --config $file | Out-String)
if ($LASTEXITCODE -ne 0) { Fail 'prepare не удался' }
$p2 = (& $Exe prepare --config $file | Out-String)
if ($LASTEXITCODE -ne 0) { Fail 'повторный prepare не удался' }
$a = $p1 | ConvertFrom-Json; $b = $p2 | ConvertFrom-Json
if ($a.source_id -ne $b.source_id -or $a.csr_sha256 -ne $b.csr_sha256) { Fail 'личность нестабильна между двумя prepare' }
if ($p1 -match 'PRIVATE KEY') { Fail 'prepare напечатал ключ' }
Say ("prepare: OK, source_id=" + $a.source_id)

# 3) служба
$errFile = Join-Path (Split-Path -Parent $Root) 'vmcheck-service-error.txt'
Remove-Item -LiteralPath $errFile -ErrorAction SilentlyContinue
& $Exe install-service --name $ServiceName --config $file --error-file $errFile
if ($LASTEXITCODE -ne 0) { Fail 'install-service не удался' }
$exit = $null
try {
  $qc = (& sc.exe qc $ServiceName) -join ' '
  Say ('sc qc: ' + ($qc -replace '\s+', ' '))
  if ($qc -notmatch 'LocalSystem') { Fail 'служба не LocalSystem' }
  if ($qc -notmatch 'AUTO_START\s+\(DELAYED\)') { Fail 'служба не delayed-auto' }
  $startOut = (& sc.exe start $ServiceName) -join ' '
  Say ('sc start: ' + ($startOut -replace '\s+', ' '))
  $seenRunning = $false
  for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 500
    $q = (& sc.exe queryex $ServiceName) -join ' '
    if ($q -match 'RUNNING|START_PENDING') { $seenRunning = $true }
    if ($q -match 'STOPPED' -and ($seenRunning -or $i -ge 4)) {
      Say ('sc queryex: ' + ($q -replace '\s+', ' '))
      if ($q -match 'SERVICE_EXIT_CODE\s*:\s*(\d+)') { $exit = [int]$Matches[1] }
      break
    }
  }
} finally {
  & $Exe uninstall-service --name $ServiceName
  $u = $LASTEXITCODE
  $gone = $false
  for ($i = 0; $i -lt 40; $i++) { & sc.exe query $ServiceName 2>$null | Out-Null; if ($LASTEXITCODE -eq 1060) { $gone = $true; break }; Start-Sleep -Milliseconds 500 }
  Say ("uninstall-service rc=$u, служба удалена=$gone")
}
if (Test-Path -LiteralPath $errFile) { Say ('service error file: ' + ((Get-Content -LiteralPath $errFile -Raw) -replace '\s+', ' ')) }

# 4) итог
if ($null -eq $exit) { Fail 'служба не остановилась с кодом этапа' }
if ($exit -eq 2) { Say 'RESULT: PASS — служба LocalSystem дошла до этапа Open (агент не зарегистрирован); состояние администратора принято.' }
elseif ($exit -eq 1) { Say 'RESULT: FAIL — этап 1: состояние/блокировка/ACL отвергнуты (см. service error file)' ; Save; exit 1 }
else { Say "RESULT: FAIL — неожиданный код этапа $exit"; Save; exit 1 }
if (-not $KeepState) { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue }
Save
Say ('report: ' + (Join-Path (Split-Path -Parent $Root) 'vmcheck-report.txt'))
exit 0
