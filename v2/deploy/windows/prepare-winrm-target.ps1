# SurveyScan: prepare a Windows PC for read-only remote inventory over WinRM HTTPS (pilot C34, issue #10).
# Run in Windows PowerShell 5.1 "as Administrator" on the target PC. Idempotent: safe to run again.
# Grants the collection account ONLY: WinRM logon, remote WMI read on root\cimv2, DCOM remote access.
# It does NOT make the account an administrator and does not change service (SCM) permissions.
# Output: thumbprint of the WinRM certificate and a PUBLIC certificate file to copy to the SurveyScan stand.
param(
  [string]$Account = 'AWM\scanwinrm',   # collection account (domain user, not an admin)
  [string]$Collector = '10.170.108.2'    # only this address may connect to port 5986
)
$ErrorActionPreference = 'Stop'
$sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host "Account $Account = $sid"

# 1. Local groups by well-known SID (works on any Windows language)
foreach ($g in @('S-1-5-32-580', 'S-1-5-32-562')) {   # Remote Management Users, Distributed COM Users
  $group = Get-LocalGroup -SID $g
  try { Add-LocalGroupMember -SID $g -Member $sid; Write-Host "[+] added to $($group.Name)" }
  catch [Microsoft.PowerShell.Commands.MemberExistsException] { Write-Host "[ok] already in $($group.Name)" }
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
Set-Service -Name WinRM -StartupType Automatic; Start-Service -Name WinRM
$sddl = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
if ($sddl -match ';;;S-1-5-32-580\)' -or $sddl -match ';;;RM\)') { Write-Host '[ok] WinRM RootSDDL allows Remote Management Users' }
else { Set-Item WSMan:\localhost\Service\RootSDDL -Value ($sddl -replace '(D:P?)', '$1(A;;GXGR;;;S-1-5-32-580)') -Force; Write-Host '[+] WinRM RootSDDL: Remote Management Users' }

# 4. HTTPS listener with a certificate for this PC's DNS name
$fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
$listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }
if ($listener) {
  $thumb = (Get-ChildItem "$($listener.PSPath)" | Where-Object Name -eq 'CertificateThumbprint').Value
  Write-Host "[ok] HTTPS listener exists"
} else {
  $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$fqdn" -and $_.NotAfter -gt (Get-Date).AddDays(30) -and $_.HasPrivateKey } | Select-Object -First 1
  if (-not $cert) { $cert = New-SelfSignedCertificate -DnsName $fqdn, $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(3) -KeyExportPolicy NonExportable }
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
  $thumb = $cert.Thumbprint
  Write-Host "[+] HTTPS listener on 5986 for $fqdn"
}

# 5. Firewall: port 5986 only from the collector address
if (Get-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -ErrorAction SilentlyContinue) { Set-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -RemoteAddress $Collector; Write-Host '[ok] firewall rule updated' }
else { New-NetFirewallRule -Name 'SurveyScan-WinRM-HTTPS' -DisplayName 'SurveyScan WinRM HTTPS (collector only)' -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress $Collector -Action Allow | Out-Null; Write-Host "[+] firewall: 5986 from $Collector" }

# 6. Public certificate for the stand (no private key)
$out = "C:\surveyscan-winrm-$($env:COMPUTERNAME).cer"
Export-Certificate -Cert "Cert:\LocalMachine\My\$thumb" -FilePath $out -Type CERT | Out-Null
Write-Host ''
Write-Host "DONE. Host: $fqdn"
Write-Host "Certificate thumbprint (compare with the stand): $thumb"
Write-Host "Public certificate for the stand: $out"
