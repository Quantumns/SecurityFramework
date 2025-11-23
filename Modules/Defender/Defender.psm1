<#
  Defender.psm1 - SecurityFramework
  Implements Thesis Section 3.2.3: Defender and Security Protections
  - Enables Real-Time Monitoring & Cloud Protection (MAPS)
  - Enables PUA (Potentially Unwanted Application) Protection
  - Enables Network Protection (SmartScreen for non-browser apps)
  - Enables LSA Protection (Credential Guard) to prevent password theft
#>

function Invoke-Defender {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'Defender'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('10.1', '10.2', '10.4')
    msMappings   = @('WindowsBaseline:Defender')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $cfg = $Config.defender
  if (-not $cfg) {
    $result.outcome = 'Failed'
    $result.details.Add("Error: 'defender' section missing in Config.json")
    return $result
  }

  try {
    # 1. Real-Time & Cloud Protection
    # Get current status
    $mpStatus = Get-MpComputerStatus
    $mpPref   = Get-MpPreference

    if ($cfg.enableRealTimeMonitoring) {
      if ($mpStatus.RealTimeProtectionEnabled -eq $false) {
        if ($Mode -eq 'Enforce') {
          Set-MpPreference -DisableRealtimeMonitoring $false
          $result.details.Add("Enabled Defender Real-Time Monitoring.")
        } else {
          $result.details.Add("Audit: Real-Time Monitoring is DISABLED (Critical Risk).")
        }
      } else {
        $result.details.Add("Real-Time Monitoring is active.")
      }
    }

    if ($cfg.enableCloudProtection) {
      # MAPS Reporting: 2 = Advanced
      if ($mpPref.MAPSReporting -ne 2) {
        if ($Mode -eq 'Enforce') {
          Set-MpPreference -MAPSReporting Advanced
          Set-MpPreference -SubmitSamplesConsent SendSafeSamples
          $result.details.Add("Enabled Cloud Protection (MAPS Advanced).")
        } else {
          $result.details.Add("Audit: Cloud Protection (MAPS) is not set to Advanced.")
        }
      } else {
        $result.details.Add("Cloud Protection (MAPS) is active.")
      }
    }

    # 2. PUA Protection (Potentially Unwanted Applications)
    if ($cfg.enablePuaProtection) {
      if ($mpPref.PUAProtection -ne 1) {
        if ($Mode -eq 'Enforce') {
          Set-MpPreference -PUAProtection Enabled
          $result.details.Add("Enabled PUA Protection.")
        } else {
          $result.details.Add("Audit: PUA Protection is DISABLED.")
        }
      } else {
        $result.details.Add("PUA Protection is active.")
      }
    }

    # 3. Network Protection (Block malicious IPs system-wide)
    if ($cfg.enableNetworkProtection) {
      if ($mpPref.EnableNetworkProtection -ne 1) {
        if ($Mode -eq 'Enforce') {
          Set-MpPreference -EnableNetworkProtection Enabled
          $result.details.Add("Enabled Network Protection.")
        } else {
          $result.details.Add("Audit: Network Protection is DISABLED.")
        }
      } else {
        $result.details.Add("Network Protection is active.")
      }
    }

    # 4. LSA Protection (Credential Guard) - Registry Key
    # HKLM\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL = 1
    if ($cfg.enableLsaProtection) {
      $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
      $ppl     = (Get-ItemProperty -Path $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
      
      if ($ppl -ne 1) {
        if ($Mode -eq 'Enforce') {
          New-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force | Out-Null
          $result.details.Add("Enabled LSA Protection (RunAsPPL). Reboot required to take full effect.")
        } else {
          $result.details.Add("Audit: LSA Protection (RunAsPPL) is DISABLED.")
        }
      } else {
        $result.details.Add("LSA Protection (RunAsPPL) is configured.")
      }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Enabled" }).Count -gt 0

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

Export-ModuleMember -Function Invoke-Defender