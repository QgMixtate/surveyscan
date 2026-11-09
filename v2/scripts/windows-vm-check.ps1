<#
 Windows VM check of the agent service (C15.03, V1). Run as Administrator, Windows PowerShell 5.1+.
 No center needed: state is prepared by the agent 'prepare' command, then a LocalSystem service must
 reach the Open stage and stop with SERVICE_EXIT_CODE=2 (agent not enrolled). The service is then removed.
 Sends nothing over the network, prints no keys. Result: console + vmcheck-report.txt next to -Root.
 This file is ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less UTF-8 as ANSI.
 Example: powershell -ExecutionPolicy Bypass -File .\windows-vm-check.ps1 -Exe C:\surveyscan\surveyscan-agent.exe
#>
param(
  [string]$Exe = 'C:\surveyscan\surveyscan-agent.exe',
  [string]$Root = 'C:\surveyscan\vmcheck',
  [string]$ServiceName = 'SurveyscanAgentVmCheck',
  [switch]$KeepState
)
$ErrorActionPreference = 'Stop'
$report = New-Object System.Collections.Generic.List[string]
$reportPath = Join-Path (Split-Path -Parent $Root) 'vmcheck-report.txt'
function Say([string]$m) { Write-Host $m; $script:report.Add($m) }
function Save { [System.IO.File]::WriteAllLines($script:reportPath, $script:report.ToArray()) }
function Fail([string]$m) { Say "FAIL: $m"; Save; exit 1 }
function Utf8NoBom([string]$path, [string]$text) { [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false))) }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'run as Administrator' }
if (-not (Test-Path -LiteralPath $Exe)) { Fail "file not found: $Exe" }
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$os = Get-CimInstance Win32_OperatingSystem
Say ("host: {0} build {1}; PowerShell {2}; {3}" -f $os.Caption, $os.BuildNumber, $PSVersionTable.PSVersion, (Get-Date -Format s))
Say ("exe sha256: " + (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLower())
$version = & $Exe --version
Say ("agent: " + ($version -join ' '))

# 1) state readable only by SYSTEM and Administrators (a user-specific SID would be rejected by the service)
$cfg = Join-Path $Root 'cfg'; $state = Join-Path $Root 'state'
if (Test-Path -LiteralPath $Root) { Fail "$Root already exists; remove it or pass another -Root" }
New-Item -ItemType Directory -Force -Path $cfg | Out-Null
& icacls $cfg /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'icacls on directory' }
$config = @{ tenant_id = [guid]::NewGuid().ToString(); site_id = [guid]::NewGuid().ToString(); network_scope_id = [guid]::NewGuid().ToString();
  collector_url = 'https://collector.invalid'; collector_source_id = [guid]::NewGuid().ToString(); ca_certificate_file = (Join-Path $cfg 'ca.pem'); state_directory = $state } | ConvertTo-Json
$file = Join-Path $cfg 'agent.json'
Utf8NoBom $file $config
& icacls $file /inheritance:r /grant:r 'SYSTEM:F' 'BUILTIN\Administrators:F' | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'icacls on file' }

# 2) prepare (idempotent)
$p1 = (& $Exe prepare --config $file | Out-String)
if ($LASTEXITCODE -ne 0) { Fail 'prepare failed' }
$p2 = (& $Exe prepare --config $file | Out-String)
if ($LASTEXITCODE -ne 0) { Fail 'second prepare failed' }
$a = $p1 | ConvertFrom-Json; $b = $p2 | ConvertFrom-Json
if ($a.source_id -ne $b.source_id -or $a.csr_sha256 -ne $b.csr_sha256) { Fail 'identity is not stable between two prepare runs' }
if ($p1 -match 'PRIVATE KEY') { Fail 'prepare printed key material' }
Say ("prepare: OK, source_id=" + $a.source_id)

# 3) service
$errFile = Join-Path (Split-Path -Parent $Root) 'vmcheck-service-error.txt'
Remove-Item -LiteralPath $errFile -ErrorAction SilentlyContinue
& $Exe install-service --name $ServiceName --config $file --error-file $errFile
if ($LASTEXITCODE -ne 0) { Fail 'install-service failed' }
$exit = $null
$problem = $null
try {
  $qc = (& sc.exe qc $ServiceName) -join ' '
  Say ('sc qc: ' + ($qc -replace '\s+', ' '))
  if ($qc -notmatch 'LocalSystem') { $problem = 'service is not LocalSystem' }
  elseif ($qc -notmatch 'AUTO_START\s+\(DELAYED\)') { $problem = 'service is not delayed-auto' }
  else {
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
  }
} finally {
  & $Exe uninstall-service --name $ServiceName
  $u = $LASTEXITCODE
  $gone = $false
  for ($i = 0; $i -lt 40; $i++) { & sc.exe query $ServiceName 2>$null | Out-Null; if ($LASTEXITCODE -eq 1060) { $gone = $true; break }; Start-Sleep -Milliseconds 500 }
  Say ("uninstall-service rc=$u, service removed=$gone")
}
if (Test-Path -LiteralPath $errFile) { Say ('service error file: ' + ((Get-Content -LiteralPath $errFile -Raw) -replace '\s+', ' ')) }

# 4) verdict
if ($problem) { Fail $problem }
if ($null -eq $exit) { Fail 'service did not stop with a stage exit code' }
if ($exit -eq 1) { Fail 'stage 1: state/lock/ACL rejected (see service error file)' }
if ($exit -ne 2) { Fail "unexpected stage exit code $exit" }
Say 'RESULT: PASS - LocalSystem service reached the Open stage (agent not enrolled); administrator state was accepted.'
if (-not $KeepState) { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue }
Save
Say "report: $reportPath"
exit 0
