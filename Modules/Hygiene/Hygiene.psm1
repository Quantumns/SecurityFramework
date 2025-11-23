<#
  Hygiene.psm1 - SecurityFramework
  Implements Thesis Section 3.2.9: System Hygiene and Autorun Controls
  - Removes bloatware (Consumer apps like Xbox, Solitaire)
  - Disables AutoRun/AutoPlay (Prevents USB viruses)
  - Cleans temporary files (Reduces clutter and forensic artifacts)
#>

function Invoke-Hygiene {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'Hygiene'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('4.7', '4.10')
    msMappings   = @('WindowsBaseline:Hygiene')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $cfg = $Config.hygiene
  if (-not $cfg) {
    $result.outcome = 'Failed'
    $result.details.Add("Error: 'hygiene' section missing in Config.json")
    return $result
  }

  try {
    # 1. Disable AutoRun / AutoPlay (USB Security)
    if ($cfg.disableAutorun) {
      # HKLM and HKCU keys for Explorer Policies
      $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
      )
      
      $autoRunCompliant = $true
      foreach ($k in $keys) {
         $val = (Get-ItemProperty -Path $k -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
         if ($val -ne 255) { $autoRunCompliant = $false }
      }

      if (-not $autoRunCompliant) {
        if ($Mode -eq 'Enforce') {
           foreach ($k in $keys) {
             if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
             Set-ItemProperty -Path $k -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force
           }
           $result.details.Add("Disabled AutoRun/AutoPlay for all drives.")
        } else {
           $result.details.Add("Audit: AutoRun is ENABLED (Risk of USB malware).")
        }
      } else {
         $result.details.Add("AutoRun/AutoPlay is disabled.")
      }
    }

    # 2. Remove Bloatware
    if ($cfg.removeBloatware) {
      $foundBloat = @()
      foreach ($app in $cfg.bloatwareList) {
         if (Get-AppxPackage -Name $app -ErrorAction SilentlyContinue) {
            $foundBloat += $app
         }
      }

      if ($foundBloat.Count -gt 0) {
        if ($Mode -eq 'Enforce') {
           foreach ($app in $foundBloat) {
              Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
           }
           $result.details.Add("Removed $($foundBloat.Count) bloatware apps (e.g., $($foundBloat[0])).")
        } else {
           $result.details.Add("Audit: Found $($foundBloat.Count) bloatware apps installed.")
        }
      } else {
         $result.details.Add("No bloatware found.")
      }
    }

    # 3. Cleanup Temp Files
    if ($cfg.cleanupTempFiles) {
       # We check C:\Windows\Temp and %TEMP%
       $sysTemp = "C:\Windows\Temp"
       $userTemp = $env:TEMP
       
       $count = (Get-ChildItem -Path $sysTemp -Force -ErrorAction SilentlyContinue).Count + 
                (Get-ChildItem -Path $userTemp -Force -ErrorAction SilentlyContinue).Count

       if ($count -gt 0) {
         if ($Mode -eq 'Enforce') {
            # Removing recursively, suppressing errors for locked files
            Remove-Item -Path "$sysTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$userTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
            $result.details.Add("Cleaned up temporary files.")
         } else {
            $result.details.Add("Audit: Found $count temporary files.")
         }
       } else {
          $result.details.Add("Temp folders are clean.")
       }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Disabled|Removed|Cleaned" }).Count -gt 0

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

Export-ModuleMember -Function Invoke-Hygiene