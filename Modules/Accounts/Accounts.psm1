<#
  Accounts.psm1 - SecurityFramework
  Implements Thesis Section 3.2.1: Accounts and Policies
  - Enforces Password Policies (Length, Age, History)
  - Enforces Lockout Policies (Threshold, Duration)
  - Disables Guest Account
  - Renames Built-in Administrator (Smart SID detection)
#>

function Invoke-Accounts {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'Accounts'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('5.2', '5.3', '5.4')
    msMappings   = @('WindowsBaseline:Accounts')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $cfg = $Config.accounts
  if (-not $cfg) {
    $result.outcome = 'Failed'
    $result.details.Add("Error: 'accounts' section missing in Config.json")
    return $result
  }

  # --- Helper to check domain status ---
  $isDomain = (Get-CimInstance Win32_ComputerSystem).PartofDomain
  
  try {
    # 1. Password Policy (Net Accounts)
    # We use 'net accounts' output parsing for Audit, and direct execution for Enforce
    $netAcc = net accounts
    $currentMinLen = [regex]::Match($netAcc, "Minimum password length\s*:\s*(\d+)").Groups[1].Value
    $currentMaxAge = [regex]::Match($netAcc, "Maximum password age \(days\)\s*:\s*(\d+)").Groups[1].Value
    $currentHistory= [regex]::Match($netAcc, "Length of password history maintained\s*:\s*(\d+)").Groups[1].Value
    
    # Lockout
    $currentLockThresh = [regex]::Match($netAcc, "Lockout threshold\s*:\s*(\d+)").Groups[1].Value
    $currentLockDur    = [regex]::Match($netAcc, "Lockout duration \(minutes\)\s*:\s*(\d+)").Groups[1].Value
    $currentLockWin    = [regex]::Match($netAcc, "Lockout observation window \(minutes\)\s*:\s*(\d+)").Groups[1].Value

    $policyIssues = @()

    if ([int]$currentMinLen -lt $cfg.minPasswordLength) { $policyIssues += "MinLen ($currentMinLen < $($cfg.minPasswordLength))" }
    if ([int]$currentMaxAge -gt $cfg.maxPasswordAgeDays){ $policyIssues += "MaxAge ($currentMaxAge > $($cfg.maxPasswordAgeDays))" }
    if ([int]$currentHistory -lt $cfg.passwordHistoryCount){ $policyIssues += "History ($currentHistory < $($cfg.passwordHistoryCount))" }
    if ([int]$currentLockThresh -eq 0 -or [int]$currentLockThresh -gt $cfg.lockoutThreshold) { $policyIssues += "LockoutThreshold" }

    if ($Mode -eq 'Enforce') {
      if ($policyIssues.Count -gt 0) {
        # Apply Password Policies
        net accounts /minpwlen:$($cfg.minPasswordLength) /maxpwage:$($cfg.maxPasswordAgeDays) /uniquepw:$($cfg.passwordHistoryCount) | Out-Null
        # Apply Lockout Policies
        net accounts /lockoutthreshold:$($cfg.lockoutThreshold) /lockoutduration:$($cfg.lockoutDurationMins) /lockoutwindow:$($cfg.lockoutResetMins) | Out-Null
        $result.details.Add("Applied Password & Lockout Policies.")
      } else {
        $result.details.Add("Password & Lockout Policies already compliant.")
      }
    } else {
      if ($policyIssues.Count -gt 0) { $result.details.Add("Audit: Weak Policy - $($policyIssues -join ', ')") }
      else { $result.details.Add("Audit: Password & Lockout Policies OK.") }
    }

    # 2. Guest Account
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest) {
      if ($guest.Enabled) {
        if ($Mode -eq 'Enforce') {
          Disable-LocalUser -Name "Guest"
          $result.details.Add("Guest account disabled.")
        } else {
          $result.details.Add("Audit: Guest account is ENABLED (Risk).")
        }
      } else {
        $result.details.Add("Guest account already disabled.")
      }
    }

    # 3. Rename Administrator (Smart SID Detection)
    if ($isDomain) {
      $result.details.Add("Skipping Admin Rename: System is Domain Joined.")
    } 
    elseif ($cfg.renameAdminAccount) {
      # Find account with SID ending in -500 (The built-in Admin)
      $adminAccount = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -match "-500$" }
      
      if ($adminAccount) {
        if ($adminAccount.Name -ne $cfg.newAdminName) {
           if ($Mode -eq 'Enforce') {
             # Rename using WMI method
             Invoke-CimMethod -InputObject $adminAccount -MethodName Rename -Arguments @{Name = $cfg.newAdminName} | Out-Null
             $result.details.Add("Renamed Admin '$($adminAccount.Name)' to '$($cfg.newAdminName)'.")
           } else {
             $result.details.Add("Audit: Administrator name is '$($adminAccount.Name)' (Expected: '$($cfg.newAdminName)').")
           }
        } else {
           $result.details.Add("Administrator name already hardened ($($cfg.newAdminName)).")
        }
      }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Applied|disabled|Renamed" }).Count -gt 0

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

Export-ModuleMember -Function Invoke-Accounts