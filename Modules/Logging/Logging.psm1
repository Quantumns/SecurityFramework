<#
  Logging.psm1 - SecurityFramework
  Implements Thesis Section 3.2.6: Logging and Auditing
  - Enforces Advanced Audit Policies (Logon, System, Privilege Use, etc.)
  - Enables PowerShell Script Block & Module Logging (Detects fileless malware)
  - Increases Event Log Sizes to prevent overwriting evidence
#>

function Invoke-Logging {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'Logging'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('8.2', '8.5')
    msMappings   = @('WindowsBaseline:Auditing')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $cfg = $Config.logging
  if (-not $cfg) {
    $result.outcome = 'Failed'
    $result.details.Add("Error: 'logging' section missing in Config.json")
    return $result
  }

  try {
    # 1. Advanced Audit Policies (using auditpol.exe)
    if ($cfg.enableAdvancedAuditing) {
      # Categories to enforce (Success & Failure)
      # These align with CIS Control 8.2
      $targetCategories = @(
        "Account Logon",
        "Logon/Logoff",
        "Privilege Use",
        "Detailed Tracking", 
        "Policy Change",
        "System",
        "Object Access"
      )

      # NOTE: We blindly enforce in 'Enforce' mode because reading auditpol reliably across languages is hard.
      # In 'Audit' mode, we do a basic check.
      
      if ($Mode -eq 'Enforce') {
        foreach ($cat in $targetCategories) {
          # /success:enable /failure:enable
          $args = "/set /category:`"$cat`" /success:enable /failure:enable"
          Start-Process "auditpol.exe" -ArgumentList $args -NoNewWindow -Wait
        }
        $result.details.Add("Applied Advanced Audit Policies (Success+Failure) for critical categories.")
      } else {
         # Simple check: just see if auditpol runs and reports settings
         $auditDump = auditpol /get /category:* 2>&1
         if ($auditDump -match "No Auditing") {
             $result.details.Add("Audit: Potential gaps found in Audit Policies (Saw 'No Auditing' entries).")
         } else {
             $result.details.Add("Audit: Audit Policies appear active (Detailed check skipped for performance).")
         }
      }
    }

    # 2. PowerShell Logging (Script Block & Module)
    # This detects "fileless" attacks (malware running in memory)
    if ($cfg.enablePowerShellLogging) {
      $psKeyBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
      $sbKey     = Join-Path $psKeyBase "ScriptBlockLogging"
      $modKey    = Join-Path $psKeyBase "ModuleLogging"
      
      $sbEnabled = (Get-ItemProperty -Path $sbKey -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
      $modEnabled = (Get-ItemProperty -Path $modKey -Name "EnableModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging

      if ($sbEnabled -ne 1 -or $modEnabled -ne 1) {
        if ($Mode -eq 'Enforce') {
          # Script Block Logging
          if (-not (Test-Path $sbKey)) { New-Item -Path $sbKey -Force | Out-Null }
          Set-ItemProperty -Path $sbKey -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
          
          # Module Logging
          if (-not (Test-Path $modKey)) { New-Item -Path $modKey -Force | Out-Null }
          Set-ItemProperty -Path $modKey -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
          
          # We also need to specify * which modules to log (Wildcard)
          $modListKey = Join-Path $modKey "ModuleNames"
          if (-not (Test-Path $modListKey)) { New-Item -Path $modListKey -Force | Out-Null }
          Set-ItemProperty -Path $modListKey -Name "*" -Value "*" -Type String -Force

          $result.details.Add("Enabled PowerShell ScriptBlock & Module Logging.")
        } else {
          $result.details.Add("Audit: PowerShell Logging is DISABLED (Blind spot for fileless malware).")
        }
      } else {
        $result.details.Add("PowerShell Logging is active.")
      }
    }

    # 3. Log Sizes (Retention)
    # Preventing "log rolling" where evidence is overwritten too fast
    if ($cfg.securityLogSizeKB -gt 0) {
      # Security Log
      $secLog = Get-WinEvent -ListLog Security
      # Compare Bytes vs KB
      $currentKB = $secLog.MaximumSizeInBytes / 1024
      
      if ($currentKB -lt $cfg.securityLogSizeKB) {
        if ($Mode -eq 'Enforce') {
           # wevtutil sl Security /ms:<bytes> (Config is in KB)
           $bytes = $cfg.securityLogSizeKB * 1024
           & wevtutil sl Security /ms:$bytes
           $result.details.Add("Increased Security Log size to $($cfg.securityLogSizeKB) KB.")
        } else {
           $result.details.Add("Audit: Security Log size ($currentKB KB) is smaller than target ($($cfg.securityLogSizeKB) KB).")
        }
      } else {
         $result.details.Add("Security Log size is compliant.")
      }
    }

    # PowerShell Log Size
    if ($cfg.powershellLogSizeKB -gt 0) {
      # "Windows PowerShell" log
      $psLog = Get-WinEvent -ListLog "Windows PowerShell" -ErrorAction SilentlyContinue
      if ($psLog) {
          $currentKB = $psLog.MaximumSizeInBytes / 1024
          if ($currentKB -lt $cfg.powershellLogSizeKB) {
            if ($Mode -eq 'Enforce') {
               $bytes = $cfg.powershellLogSizeKB * 1024
               & wevtutil sl "Windows PowerShell" /ms:$bytes
               $result.details.Add("Increased PowerShell Log size to $($cfg.powershellLogSizeKB) KB.")
            } else {
               $result.details.Add("Audit: PowerShell Log size ($currentKB KB) is too small.")
            }
          } else {
             $result.details.Add("PowerShell Log size is compliant.")
          }
      }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Applied|Enabled|Increased" }).Count -gt 0

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

Export-ModuleMember -Function Invoke-Logging