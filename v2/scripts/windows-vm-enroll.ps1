<#
 Windows VM: connect the agent to a test center (vm_center.py on a Linux host). Run as Administrator, PowerShell 5.1+.
 ASCII-only on purpose (Windows PowerShell 5.1 reads BOM-less UTF-8 as ANSI).
 Steps (run in this order):
   -Step prepare : needs -ConfigTemplate agent-config.windows.json and -CA ca.pem from the center host.
                   Creates private state, runs 'prepare', writes <Root>\prepare.json (copy it to the center host).
   -Step enroll  : needs -Grant grant.json from the center host (valid 15 minutes). Runs 'enroll', installs and starts
                   the LocalSystem service (inventory profile 1.2 loop), prints service state.
   -Step status  : service state, last error text, local queue files.
   -Step remove  : stops and removes the service (state and identity stay in <Root>).
 Example: .\windows-vm-enroll.ps1 -Step prepare -ConfigTemplate C:\surveyscan\agent-config.windows.json -CA C:\surveyscan\ca.pem
#>
param(
  [Parameter(Mandatory = $true)][ValidateSet('prepare', 'enroll', 'status', 'remove')][string]$Step,
  [string]$Exe = 'C:\surveyscan\surveyscan-agent.exe',
  [string]$Root = 'C:\surveyscan\vm',
  [string]$ConfigTemplate,
  [string]$CA,
  [string]$Grant,
  [string]$ServiceName = 'SurveyscanAgentVm'
)
$ErrorActionPreference = 'Stop'
function Fail([string]$m) { Write-Host "FAIL: $m"; exit 1 }
function Utf8NoBom([string]$path, [string]$text) { [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false))) }
function Protect([string]$path) {
  # explicit protected DACL: only SYSTEM and Administrators (inherited or user-specific entries are rejected by the agent)
  if ((Get-Item -LiteralPath $path).PSIsContainer) { & icacls $path /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null }
  else { & icacls $path /inheritance:r /grant:r 'SYSTEM:F' 'BUILTIN\Administrators:F' | Out-Null }
  if ($LASTEXITCODE -ne 0) { Fail "icacls failed for $path" }
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'run as Administrator' }
if (-not (Test-Path -LiteralPath $Exe)) { Fail "file not found: $Exe" }
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$cfgDir = Join-Path $Root 'cfg'
$cfgFile = Join-Path $cfgDir 'agent.json'
$errFile = Join-Path $Root 'service-error.txt'

if ($Step -eq 'prepare') {
  if (-not $ConfigTemplate -or -not (Test-Path -LiteralPath $ConfigTemplate)) { Fail '-ConfigTemplate file is required' }
  if (-not $CA -or -not (Test-Path -LiteralPath $CA)) { Fail '-CA file is required' }
  if (Test-Path -LiteralPath $cfgFile) { Fail "$cfgFile already exists: this agent is already prepared (use -Step enroll), or remove $Root to start over" }
  New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
  Protect $cfgDir
  $caTarget = Join-Path $cfgDir 'ca.pem'
  Copy-Item -LiteralPath $CA -Destination $caTarget -Force
  Protect $caTarget
  $cfg = Get-Content -LiteralPath $ConfigTemplate -Raw | ConvertFrom-Json
  $cfg.ca_certificate_file = $caTarget
  $cfg.state_directory = (Join-Path $Root 'state')
  Utf8NoBom $cfgFile ($cfg | ConvertTo-Json)
  Protect $cfgFile
  $out = (& $Exe prepare --config $cfgFile | Out-String)
  if ($LASTEXITCODE -ne 0) { Fail 'prepare failed' }
  if ($out -match 'PRIVATE KEY') { Fail 'prepare printed key material' }
  $prepareFile = Join-Path $Root 'prepare.json'
  Utf8NoBom $prepareFile $out
  Write-Host "prepare OK. Copy this file to the center host as <OUT>/prepare.json:"
  Write-Host "  $prepareFile"
  Write-Host "Then wait for grant.json on the center host (the script there prints 'GRANT issued'), copy it here and run -Step enroll."
  exit 0
}

if ($Step -eq 'enroll') {
  if (-not (Test-Path -LiteralPath $cfgFile)) { Fail 'run -Step prepare first' }
  if (-not $Grant -or -not (Test-Path -LiteralPath $Grant)) { Fail '-Grant file is required' }
  $grantTarget = Join-Path $cfgDir 'grant.json'
  Copy-Item -LiteralPath $Grant -Destination $grantTarget -Force
  Protect $grantTarget
  & $Exe enroll --config $cfgFile --grant-file $grantTarget
  if ($LASTEXITCODE -ne 0) { Fail "enroll failed (exit $LASTEXITCODE); grant lives 15 minutes, ask for a new prepare/grant if it expired" }
  Remove-Item -LiteralPath $grantTarget -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $errFile -ErrorAction SilentlyContinue
  & $Exe install-service --name $ServiceName --config $cfgFile --error-file $errFile
  if ($LASTEXITCODE -ne 0) { Fail 'install-service failed (already installed? run -Step remove first)' }
  & sc.exe start $ServiceName | Out-Null
  Start-Sleep -Seconds 5
  Write-Host (& sc.exe queryex $ServiceName | Out-String)
  if (Test-Path -LiteralPath $errFile) { Write-Host ('service error text: ' + (Get-Content -LiteralPath $errFile -Raw)) }
  Write-Host 'enroll OK, service started. Watch the center host STATUS lines; the first inventory arrives within ~1-2 minutes.'
  exit 0
}

if ($Step -eq 'status') {
  Write-Host (& sc.exe queryex $ServiceName | Out-String)
  if (Test-Path -LiteralPath $errFile) { Write-Host ('service error text: ' + (Get-Content -LiteralPath $errFile -Raw)) }
  $spool = Join-Path (Join-Path $Root 'state') 'spool'
  if (Test-Path -LiteralPath $spool) { Write-Host ('spool files: ' + (Get-ChildItem -LiteralPath $spool -File | Measure-Object).Count) }
  exit 0
}

if ($Step -eq 'remove') {
  & $Exe uninstall-service --name $ServiceName
  Write-Host "service removed (rc=$LASTEXITCODE); state and identity stay in $Root"
  exit 0
}
