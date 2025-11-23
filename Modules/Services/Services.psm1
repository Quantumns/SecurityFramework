<#
  Services.psm1 - SecurityFramework
  Implements Thesis Section 3.2.2: Services and Protocols
  - Disables SMBv1 (Ransomware vector)
  - Disables Telnet (Insecure protocol)
  - Disables Remote Registry (Lateral movement risk)
  - Enforces Network Level Authentication (NLA) for RDP
#>

function Invoke-Services {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'Services'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('4.8')
    msMappings   = @('WindowsBaseline:Services')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $cfg = $Config.services
  if (-not $cfg) {
    $result.outcome = 'Failed'
    $result.details.Add("Error: 'services' section missing in Config.json")
    return $result
  }

  try {
    # 1. SMBv1 Protocol (The "WannaCry" vector)
    if ($cfg.disableSmb1) {
      # Check Windows Feature (Server/Protocol)
      $smbFeature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
      
      # Check Service (Client Driver)
      $smbClient  = Get-Service -Name "mrxsmb10" -ErrorAction SilentlyContinue
      $clientRunning = ($smbClient -and $smbClient.StartType -ne 'Disabled')

      if (($smbFeature -and $smbFeature.State -eq 'Enabled') -or $clientRunning) {
        if ($Mode -eq 'Enforce') {
          if ($smbFeature.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -WarningAction SilentlyContinue | Out-Null
            $result.details.Add("Disabled SMBv1 Protocol Feature.")
          }
          if ($clientRunning) {
            Set-Service -Name "mrxsmb10" -StartupType Disabled
            $result.details.Add("Disabled SMBv1 Client Driver (mrxsmb10).")
          }
        } else {
          $result.details.Add("Audit: SMBv1 is ENABLED (High Risk).")
        }
      } else {
        $result.details.Add("SMBv1 is already disabled.")
      }
    }

    # 2. Telnet Client
    if ($cfg.disableTelnet) {
      $telnet = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue
      if ($telnet -and $telnet.State -eq 'Enabled') {
        if ($Mode -eq 'Enforce') {
          Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -WarningAction SilentlyContinue | Out-Null
          $result.details.Add("Disabled Telnet Client.")
        } else {
          $result.details.Add("Audit: Telnet Client is ENABLED.")
        }
      } else {
        $result.details.Add("Telnet Client already disabled.")
      }
    }

    # 3. Remote Registry (Lateral Movement)
    if ($cfg.disableRemoteRegistry) {
      $rr = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
      if ($rr -and ($rr.Status -ne 'Stopped' -or $rr.StartType -ne 'Disabled')) {
        if ($Mode -eq 'Enforce') {
          Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
          Set-Service -Name "RemoteRegistry" -StartupType Disabled
          $result.details.Add("Disabled Remote Registry service.")
        } else {
          $result.details.Add("Audit: Remote Registry is ENABLED/Running.")
        }
      } else {
        $result.details.Add("Remote Registry already disabled.")
      }
    }

    # 4. RDP Network Level Authentication (NLA)
    if ($cfg.enforceRdpNla) {
      $rdpKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
      if (Test-Path $rdpKey) {
        $nlaVal = (Get-ItemProperty -Path $rdpKey -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        if ($nlaVal -ne 1) {
          if ($Mode -eq 'Enforce') {
            Set-ItemProperty -Path $rdpKey -Name "UserAuthentication" -Value 1 -Force
            $result.details.Add("Enforced RDP Network Level Authentication (NLA).")
          } else {
            $result.details.Add("Audit: RDP NLA is DISABLED (Risk).")
          }
        } else {
          $result.details.Add("RDP NLA already enforced.")
        }
      }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Disabled|Enforced" }).Count -gt 0

    if ($Mode -eq 'Audit') {
      if ($anyIssues) { $result.outcome = 'Non-Compliant' } else { $result.outcome = 'Compliant' }
    } else {
      if ($anyFixes) { $result.outcome = 'Applied' } else { $result.outcome = 'Already Compliant' }
    }

  } catch {
    $result.outcome = 'Failed'
    $result.details.Add("Error: $($_.Exception.Message)")
  }

  return $result
}

Export-ModuleMember -Function Invoke-Services