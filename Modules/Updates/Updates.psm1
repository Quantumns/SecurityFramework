<#
  Updates.psm1 - SecurityFramework
  Implements Thesis Section 3.2.5: Updates and Patch Management
  - Configures Automatic Updates via Registry (AUOptions)
  - Ensures Windows Update Service (wuauserv) is Automatic/Running
  - Natively scans for pending updates using Microsoft.Update.Session COM Object
#>

function Invoke-Updates {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'Updates'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('7.1', '7.3')
    msMappings   = @('WindowsBaseline:Updates')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $cfg = $Config.updates
  if (-not $cfg) {
    $result.outcome = 'Failed'
    $result.details.Add("Error: 'updates' section missing in Config.json")
    return $result
  }

  try {
    # 1. Configure Auto-Update Settings (Registry)
    # AUOptions: 4 = Auto download and schedule the install
    $auKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    
    if ($cfg.configureAutoUpdate) {
      if (-not (Test-Path $auKey)) { New-Item -Path $auKey -Force | Out-Null }
      
      $currAU = (Get-ItemProperty -Path $auKey -Name "AUOptions" -ErrorAction SilentlyContinue).AUOptions
      $currNoReboot = (Get-ItemProperty -Path $auKey -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers

      # Check if compliant
      $settingsCompliant = ($currAU -eq $cfg.autoUpdateOption) -and ($currNoReboot -eq 1)

      if (-not $settingsCompliant) {
        if ($Mode -eq 'Enforce') {
          Set-ItemProperty -Path $auKey -Name "AUOptions" -Value $cfg.autoUpdateOption -Type DWord -Force
          if ($cfg.noAutoRebootWithUsers) {
             Set-ItemProperty -Path $auKey -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord -Force
          }
          $result.details.Add("Applied Auto-Update Policy (AUOptions=4, NoAutoReboot=1).")
        } else {
          $result.details.Add("Audit: Auto-Update Policy mismatch or missing.")
        }
      } else {
        $result.details.Add("Auto-Update Policy is compliant.")
      }
    }

    # 2. Windows Update Service
    $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($svc.StartType -ne 'Automatic' -or $svc.Status -ne 'Running') {
      if ($Mode -eq 'Enforce') {
        Set-Service -Name "wuauserv" -StartupType Automatic
        Start-Service -Name "wuauserv"
        $result.details.Add("Ensured Windows Update Service is Automatic and Running.")
      } else {
        $result.details.Add("Audit: Windows Update Service is not Automatic/Running.")
      }
    } else {
      $result.details.Add("Windows Update Service is healthy.")
    }

    # 3. Check for Missing Updates (Native COM Object)
    # This aligns with "Vulnerability Management" (CIS 7.1)
    if ($cfg.checkForMissingUpdates) {
      try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        # We search for updates that are NOT installed
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        
        $count = $searchResult.Updates.Count
        if ($count -gt 0) {
          $titleList = @()
          foreach ($u in $searchResult.Updates) { $titleList += $u.Title }
          # Just log the count and first few to avoid flooding logs
          $result.details.Add("Audit: Found $count missing updates (e.g. $($titleList[0])).")
          # In Enforce mode, we don't trigger install here to avoid long hang times, 
          # but the Policy we set above in step 1 ensures Windows will do it automatically.
        } else {
          $result.details.Add("System appears fully patched (0 pending updates).")
        }
      } catch {
        $result.details.Add("Warning: Could not scan for updates (Offline or COM error).")
      }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Applied|Ensured" }).Count -gt 0

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

Export-ModuleMember -Function Invoke-Updates