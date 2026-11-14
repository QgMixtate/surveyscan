# SurveyScan: prepare a Windows PC for read-only remote inventory over WinRM (pilot C34, issue #10; C51.03).
# Run in Windows PowerShell 5.1 "as Administrator" on the target PC, or from a GPO immediate task as SYSTEM with -Gpo.
# Idempotent: safe to run again.
# Grants the collection account (or group) ONLY: WinRM logon, remote WMI read on root\cimv2, DCOM remote access.
# It does NOT make the account an administrator and does not change service (SCM) permissions.
#  default: groups, WMI rights, WinRM service, HTTPS listener (domain CA certificate if present, else self-signed),
#           firewall for the collector only, PUBLIC certificate file for the stand/Web form.
#  -Gpo:    groups, service, HTTP listener and firewall come from the GPO (see deploy/OPERATIONS.md, section 11);
#           the script only grants WMI rights and creates the HTTPS listener if a domain CA certificate is present.
param(
  [string]$Account = 'AWM\scanwinrm',   # collection account or domain group (not an admin)
  [string]$Collector = '10.170.108.2',   # only this address may connect to port 5986
  [switch]$Gpo
)
$ErrorActionPreference = 'Stop'
$sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "Account $Account = $sid"

# 1. Local groups by well-known SID (works on any Windows language); with -Gpo the GPO adds them
if (-not $Gpo) {
  foreach ($g in @('S-1-5-32-580', 'S-1-5-32-562')) {   # Remote Management Users, Distributed COM Users
    $group = Get-LocalGroup -SID $g
    try { Add-LocalGroupMember -SID $g -Member $sid; Write-Host "[+] added to $($group.Name)" }
    catch [Microsoft.PowerShell.Commands.MemberExistsException] { Write-Host "[ok] already in $($group.Name)" }
  }
}

# 2. WMI namespace root\cimv2: Enable Account (0x1) + Remote Enable (0x20), inherited by sub-namespaces
$ss = Get-WmiObject -Namespace 'root/cimv2' -Class __SystemSecurity
$sd = $ss.GetSecurityDescriptor().Descriptor
if ($sd.DACL | Where-Object { $_.Trustee.SidString -eq $sid -and ($_.AccessMask -band 0x21) -eq 0x21 }) { Write-Host '[ok] WMI root\cimv2 rights present' }
else {
  $trustee = ([wmiclass]'Win32_Trustee').CreateInstance(); $trustee.SidString = $sid
  $ace = ([wmiclass]'Win32_ACE').CreateInstance(); $ace.AccessMask = 0x21; $ace.AceFlags = 0x2; $ace.AceType = 0; $ace.Trustee = $trustee
  $sd.DACL += $ace.psobject.ImmediateBaseObject
  $r = $ss.SetSecurityDescriptor($sd); if ($r.ReturnValue -ne 0) { throw "WMI SetSecurityDescriptor failed: $($r.ReturnValue)" }
  Write-Host '[+] WMI root\cimv2: Enable Account + Remote Enable'
}

# 3. WinRM service and permission for Remote Management Users
if (-not $Gpo) { Set-Service -Name WinRM -StartupType Automatic; Start-Service -Name WinRM }
$sddl = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
if ($sddl -match ';;;S-1-5-32-580\)' -or $sddl -match ';;;RM\)') { Write-Host '[ok] WinRM RootSDDL allows Remote Management Users' }
else { Set-Item WSMan:\localhost\Service\RootSDDL -Value ($sddl -replace '(D:P?)', '$1(A;;GXGR;;;S-1-5-32-580)') -Force; Write-Host '[+] WinRM RootSDDL: Remote Management Users' }

# 4. HTTPS listener: prefer a certificate issued by the domain CA (autoenrollment) for this PC's DNS name
$fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
$domainCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
  $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) -and $_.Issuer -ne $_.Subject -and
  ($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.1' }) -and
  ($_.DnsNameList | Where-Object { $_.Unicode -eq $fqdn })
} | Sort-Object NotAfter -Descending | Select-Object -First 1
$listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }
$thumb = $null
if ($listener) {
  $thumb = (Get-ChildItem "$($listener.PSPath)" | Where-Object Name -eq 'CertificateThumbprint').Value
  Write-Host "[ok] HTTPS listener exists"
} elseif ($domainCert) {
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $domainCert.Thumbprint -Force | Out-Null
  $thumb = $domainCert.Thumbprint
  Write-Host "[+] HTTPS listener on 5986 for $fqdn (domain CA certificate)"
} elseif ($Gpo) {
  Write-Host '[skip] no domain CA certificate yet: HTTPS listener not created (HTTP 5985 + Kerberos works without it)'
} else {
  $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$fqdn" -and $_.NotAfter -gt (Get-Date).AddDays(30) -and $_.HasPrivateKey } | Select-Object -First 1
  if (-not $cert) { $cert = New-SelfSignedCertificate -DnsName $fqdn, $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(3) -KeyExportPolicy NonExportable }
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
  $thumb = $cert.Thumbprint
  Write-Host "[+] HTTPS listener on 5986 for $fqdn (self-signed)"
}

if ($Gpo) { Write-Host "DONE (GPO mode). Host: $fqdn"; exit 0 }

# 5. Firewall: port 5986 only from the collector address
if (Get-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -ErrorAction SilentlyContinue) { Set-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -RemoteAddress $Collector; Write-Host '[ok] firewall rule updated' }
else { New-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -DisplayName 'SurveyScan WinRM HTTPS (collector only)' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $Collector -Action Allow | Out-Null; Write-Host "[+] firewall: 5986 from $Collector" }

# 6. Public certificate for the stand/Web form, PEM text (no private key). Optional in the Web form: without it the
#    collector remembers the certificate on first connection.
$out = "C:\surveyscan-winrm-$($env:COMPUTERNAME).pem"
$der = (Get-Item "Cert:\LocalMachine\My\$thumb").RawData
$pem = "-----BEGIN CERTIFICATE-----`r`n" + [Convert]::ToBase64String($der, 'InsertLineBreaks') + "`r`n-----END CERTIFICATE-----`r`n"
[System.IO.File]::WriteAllText($out, $pem)
Write-Host ''
Write-Host "DONE. Host: $fqdn"
Write-Host "Certificate thumbprint (compare with the stand): $thumb"
Write-Host "Public certificate for the stand: $out"
