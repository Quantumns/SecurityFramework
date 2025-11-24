<#
  Hardening.psm1 - SecurityFramework
  Implements Thesis Section 3.2.8: Application Hardening
  - Enforces SmartScreen (Edge & System)
  - Blocks Office Macros from Internet
  - Disables Windows Script Host (WSH) to stop .vbs malware
  - Enables Attack Surface Reduction (ASR) Rules
#>

function Invoke-Hardening {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'Hardening'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('9.2', '9.4', '16.7')
    msMappings   = @('WindowsBaseline:AppHardening')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $cfg = $Config.hardening
  if (-not $cfg) {
    $result.outcome = 'Failed'
    $result.details.Add("Error: 'hardening' section missing in Config.json")
    return $result
  }

  try {
    # 1. Microsoft Defender SmartScreen
    if ($cfg.enableSmartScreen) {
      $edgeKey = "HKLM:\SOFTWARE\Policies\Microsoft Edge"
      $sysKey  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
      
      $edgeVal = (Get-ItemProperty -Path $edgeKey -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue).SmartScreenEnabled
      $sysVal  = (Get-ItemProperty -Path $sysKey -Name "EnableSmartScreen" -ErrorAction SilentlyContinue).EnableSmartScreen
      
      if ($edgeVal -ne 1 -or $sysVal -ne 1) {
        if ($Mode -eq 'Enforce') {
          if (-not (Test-Path $edgeKey)) { New-Item -Path $edgeKey -Force | Out-Null }
          Set-ItemProperty -Path $edgeKey -Name "SmartScreenEnabled" -Value 1 -Type DWord -Force

          if (-not (Test-Path $sysKey)) { New-Item -Path $sysKey -Force | Out-Null }
          Set-ItemProperty -Path $sysKey -Name "EnableSmartScreen" -Value 1 -Type DWord -Force
          
          $result.details.Add("Enforced SmartScreen for Edge and System.")
        } else {
          $result.details.Add("Audit: SmartScreen is not fully enforced.")
        }
      } else {
        $result.details.Add("SmartScreen is active.")
      }
    }

    # 2. Block Office Macros from Internet (System-Wide via HKLM)
    if ($cfg.blockOfficeMacros) {
      # Use HKLM to enforce for ALL users on this machine
      $wordKey = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security"
      $valName = "BlockContentExecutionFromInternet"
      
      $currVal = (Get-ItemProperty -Path $wordKey -Name $valName -ErrorAction SilentlyContinue).$valName
      
      if ($currVal -ne 1) {
        if ($Mode -eq 'Enforce') {
           if (-not (Test-Path $wordKey)) { New-Item -Path $wordKey -Force | Out-Null }
           Set-ItemProperty -Path $wordKey -Name $valName -Value 1 -Type DWord -Force
           $result.details.Add("Blocked Office Macros from Internet (System-Wide).")
        } else {
           $result.details.Add("Audit: Office Macros from Internet are NOT blocked system-wide.")
        }
      } else {
         $result.details.Add("Office Macro restrictions are active (System-Wide).")
      }
    }

    # 3. Disable Windows Script Host (WSH)
    # Stops .vbs and .js malware scripts
    if ($cfg.disableWindowsScriptHost) {
      $wshKey = "HKLM:\Software\Microsoft\Windows Script Host Settings"
      $wshVal = (Get-ItemProperty -Path $wshKey -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
      
      if ($wshVal -ne 0) {
        if ($Mode -eq 'Enforce') {
           if (-not (Test-Path $wshKey)) { New-Item -Path $wshKey -Force | Out-Null }
           Set-ItemProperty -Path $wshKey -Name "Enabled" -Value 0 -Type DWord -Force
           $result.details.Add("Disabled Windows Script Host (WSH).")
        } else {
           $result.details.Add("Audit: Windows Script Host is ENABLED.")
        }
      } else {
         $result.details.Add("Windows Script Host is disabled.")
      }
    }

    # 4. Attack Surface Reduction (ASR) Rules
    if ($cfg.enableAsrRules) {
      # The "Cool Thing": Human Readable Names for GUIDs
      $asrRules = @{
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office Child Processes"
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office Executable Content"
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office Code Injection"
        "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office Communication Child Proc"
      }

      # Get current ASR status
      $mpPref = Get-MpPreference
      # Create a hashtable of current rules for easy lookup
      $currentRules = @{}
      for ($i=0; $i -lt $mpPref.AttackSurfaceReductionRules_Ids.Count; $i++) {
         $id  = $mpPref.AttackSurfaceReductionRules_Ids[$i]
         $act = $mpPref.AttackSurfaceReductionRules_Actions[$i] # 0=Off, 1=Block, 2=Audit
         $currentRules[$id] = $act
      }

      $asrChanges = 0
      foreach ($guid in $asrRules.Keys) {
         if ($currentRules[$guid] -ne 1) {
            if ($Mode -eq 'Enforce') {
               Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled
               $asrChanges++
            } else {
               $result.details.Add("Audit: ASR Rule '$($asrRules[$guid])' is NOT enabling blocking.")
            }
         }
      }

      if ($Mode -eq 'Enforce') {
         if ($asrChanges -gt 0) {
            $result.details.Add("Enabled $asrChanges missing ASR Rules.")
         } else {
            $result.details.Add("All targeted ASR Rules are active.")
         }
      }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Enforced|Blocked|Disabled|Enabled" }).Count -gt 0

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

Export-ModuleMember -Function Invoke-Hardening