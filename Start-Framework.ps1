<#  Start-Framework.ps1
    Menu launcher for the SecurityFramework.
    - Detects modules in .\Modules
    - Automatic System Backup (Reg/Firewall) before Enforcement
    - Runs Audit/Enforce for all or a single module
    - Shows last run summary with HK-style score
    - Logs & Reports submenu
    Windows PowerShell 5.1 compatible
#>

$ErrorActionPreference  = "Stop"
$ProgressPreference     = "SilentlyContinue"

# -------- Paths
$Root        = $PSScriptRoot
$Framework   = Join-Path $Root "Framework.ps1"
$ModulesDir  = Join-Path $Root "Modules"
$LogsDir     = Join-Path $Root "Logs"
$BackupDir   = Join-Path $Root "Backups"
$ConfigPath  = Join-Path $Root "Config\config.json"
$FwLogPath   = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

# ---------- Core Functions ----------

function Ensure-Dirs {
    if (-not (Test-Path $LogsDir))   { New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null }
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null }
}

function Invoke-Backup {
    Ensure-Dirs
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $currentBackup = Join-Path $BackupDir $timestamp
    
    try {
        if (-not (Test-Path $currentBackup)) { New-Item -Path $currentBackup -ItemType Directory -Force | Out-Null }
        
        Write-Host "`n[BACKUP] Creating system rollback point..." -ForegroundColor Cyan
        
        # 1. Export Firewall Rules (JSON)
        Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action, Profile | ConvertTo-Json -Depth 2 | Out-File (Join-Path $currentBackup "FirewallRules.json")
        
        # 2. Export Critical Registry Keys (Reg Export)
        $regExports = @(
            @{ Name="AuditPol";  Path="HKLM\SECURITY\Policy\PolAdtEv" },
            @{ Name="Lsa";       Path="HKLM\SYSTEM\CurrentControlSet\Control\Lsa" },
            @{ Name="WinUpdate"; Path="HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" }
        )

        foreach ($reg in $regExports) {
            $outFile = Join-Path $currentBackup "$($reg.Name).reg"
            Start-Process "reg.exe" -ArgumentList "export `"$($reg.Path)`" `"$outFile`" /y" -Wait -WindowStyle Hidden
        }
        
        Write-Host "   [OK] Rollback saved to: Backups\$timestamp" -ForegroundColor Green
        Start-Sleep -Seconds 1
        return $true
    } catch {
        Write-Host "   [ERROR] Backup failed: $($_.Exception.Message)" -ForegroundColor Red
        Pause-UI
        return $false
    }
}

function Check-BackupStatus {
    param([bool]$ReportOnly = $false)
    Ensure-Dirs
    
    # Find newest backup folder
    $lastBackup = Get-ChildItem $BackupDir -Directory | Sort-Object Name -Descending | Select-Object -First 1
    
    if ($ReportOnly) {
        Write-Host "`n=== Backup Status ===" -ForegroundColor Cyan
        if ($lastBackup) {
            try {
                $backupDate = [DateTime]::ParseExact($lastBackup.Name, "yyyyMMdd-HHmmss", $null)
                $daysAgo = ((Get-Date) - $backupDate).Days
                Write-Host "Last Backup: $($lastBackup.Name)"
                Write-Host "Age:         $daysAgo days ago"
                Write-Host "Location:    $($lastBackup.FullName)"
            } catch {
                Write-Host "Last Backup: $($lastBackup.Name) (Invalid Date Format)"
            }
        } else {
            Write-Host "Last Backup: None found." -ForegroundColor Yellow
        }
        Pause-UI
        return
    }

    # --- ENFORCE MODE LOGIC ---
    $shouldCreate = $true
    
    if ($lastBackup) {
        try {
            $backupDate = [DateTime]::ParseExact($lastBackup.Name, "yyyyMMdd-HHmmss", $null)
            $daysAgo = ((Get-Date) - $backupDate).Days
            
            Write-Host "`n[INFO] Last rollback point found: $daysAgo days ago ($($lastBackup.Name))" -ForegroundColor Cyan
            
            if ($daysAgo -lt 1) {
                # Very recent backup (today)
                $ans = Read-Host "Create ANOTHER backup before continuing? (y/N)"
                if ($ans -ne 'y') { $shouldCreate = $false }
            } else {
                # Backup exists but is older than 1 day
                $ans = Read-Host "Create a NEW backup now? (Y/n)"
                if ($ans -eq 'n') { $shouldCreate = $false }
            }
        } catch {
            # Corrupt folder name
            Write-Host "`n[WARN] Last backup folder has invalid name format." -ForegroundColor Yellow
            $ans = Read-Host "Create a fresh backup now? (Y/n)"
            if ($ans -eq 'n') { $shouldCreate = $false }
        }
    } else {
        # No backup at all
        Write-Host "`n[WARN] NO PREVIOUS BACKUPS FOUND." -ForegroundColor Red
        Write-Host "       It is highly recommended to create a rollback point." -ForegroundColor Yellow
        $ans = Read-Host "Create backup now? (Y/n)"
        if ($ans -eq 'n') { $shouldCreate = $false }
    }

    if ($shouldCreate) {
        Invoke-Backup
    }
}

function Pause-UI { [void](Read-Host "Press Enter to continue...") }

function Test-IsAdmin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-ModuleNames {
  $list = @()
  if (-not (Test-Path $ModulesDir)) { return $list }

  foreach ($dir in Get-ChildItem $ModulesDir -Directory -ErrorAction SilentlyContinue) {
    $psm1 = Get-ChildItem -Path $dir.FullName -Filter *.psm1 -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $display = if ($psm1) { [System.IO.Path]::GetFileNameWithoutExtension($psm1.Name) } else { $dir.Name }
    $list += [pscustomobject]@{ FolderName = $dir.Name; DisplayName = $display }
  }
  foreach ($f in Get-ChildItem -Path $ModulesDir -Filter *.psm1 -File -ErrorAction SilentlyContinue) {
    $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
    $list += [pscustomobject]@{ FolderName = $nameNoExt; DisplayName = $nameNoExt }
  }

  $list | Sort-Object DisplayName -Unique
}

function Invoke-Framework {
  param(
    [ValidateSet('Audit','Enforce')] [string]$Mode,
    [string[]]$Modules = @()
  )
  if (-not (Test-Path $Framework)) { Write-Error "Framework.ps1 not found at $Framework"; return }
  if (-not (Test-Path $ConfigPath)) { Write-Error "Config not found at $ConfigPath"; return }

  # 1. Elevation Check
  if ($Mode -eq 'Enforce') {
      if (-not (Test-IsAdmin)) {
        Write-Host "[INFO] Elevation required for Enforcement. Launching new window..." -ForegroundColor Yellow
        
        # We build the command string manually to ensure the pause happens inside the new window
        $cmdString = "-NoProfile -ExecutionPolicy Bypass -Command `& '$Framework' -Mode $Mode -Config '$ConfigPath'"
        if ($Modules.Count -gt 0) { $cmdString += " -Modules " + ($Modules -join ',') }
        
        # APPEND THE PAUSE HERE
        $cmdString += "; Write-Host ''; Read-Host 'Press Enter to close this window...'"

        Start-Process powershell -Verb RunAs -ArgumentList $cmdString -Wait
        return
      }
      
      # 2. Automatic Rollback (Only runs if Admin)
      Invoke-RestorePoint
  }

  # 3. Run Framework (Standard execution)
  $cmd = @(
    "-NoProfile","-ExecutionPolicy","Bypass",
    "-File", $Framework,
    "-Mode", $Mode,
    "-Config", $ConfigPath
  )
  if ($Modules.Count -gt 0) { $cmd += @("-Modules", ($Modules -join ',')) }

  $modLabel = if ($Modules.Count) { '[' + ($Modules -join ',') + ']' } else { '[All Modules]' }
  Write-Host "[RUN] $Mode $modLabel" -ForegroundColor Cyan
  & powershell @cmd
  
  # 4. Keep window open if we just ran an enforcement (for the current window)
  if ($Mode -eq 'Enforce') {
      Write-Host "`n[INFO] Process Complete." -ForegroundColor Green
      Pause-UI
  }
}

function Get-HKStyleScore {
  param([object[]]$mods)

  $considered = @()
  foreach ($m in $mods) { if ($m.outcome -ne 'Skipped') { $considered += $m } }

  $points = 0
  $maxPts = 4 * [Math]::Max(1, $considered.Count)

  foreach ($m in $considered) {
    switch ($m.outcome) {
      'Compliant'          { $points += 4 }
      'Already Compliant'  { $points += 4 }
      'Applied'            { $points += 2 }
      'Partial'            { $points += 1 }
      'Non-Compliant'      { $points += 0 }
      'Failed'             { $points += 0 }
      default              { $points += 0 }
    }
  }

  $score = [Math]::Round((($points / $maxPts) * 5) + 1, 1)

  $ratingCasual, $ratingPro =
    if     ($score -ge 5.5) { "Excellent","Excellent" }
    elseif ($score -ge 4.5) { "Well done","Good" }
    elseif ($score -ge 3.5) { "Sufficient","Sufficient" }
    elseif ($score -ge 2.5) { "You should do better","Insufficient" }
    elseif ($score -ge 1.5) { "Weak","Insufficient" }
    else                    { "Bogus","Insufficient" }

  [pscustomobject]@{
    PointsAchieved      = $points
    MaxPoints           = $maxPts
    Score               = $score
    RatingCasual        = $ratingCasual
    RatingProfessional  = $ratingPro
    ConsideredModules   = $considered.Count
    SkippedModules      = ($mods | Where-Object {$_.outcome -eq 'Skipped'}).Count
  }
}

function Show-LastRunSummary {
  if (-not (Test-Path $LogsDir)) { Write-Host "No logs folder found."; return }
  $last = Get-ChildItem $LogsDir -Filter *.json -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $last) { Write-Host "No run logs yet."; return }

  $json = Get-Content $last.FullName -Raw | ConvertFrom-Json
  Write-Host "Last run: $($json.runId)  Mode: $($json.mode)  Host: $($json.host)" -ForegroundColor DarkCyan

  $mods = $json.modules
  if (-not $mods) { Write-Host "No module results."; return }

  $hk = Get-HKStyleScore -mods $mods

  Write-Host ""
  Write-Host ("Modules: {0} | Considered: {1} | Skipped: {2}" -f $mods.Count, $hk.ConsideredModules, $hk.SkippedModules)
  Write-Host ("Points: {0} / {1}" -f $hk.PointsAchieved, $hk.MaxPoints)
  Write-Host ("Score: {0}  |  Rating (Casual): {1}  |  Rating (Professional): {2}" -f `
              $hk.Score, $hk.RatingCasual, $hk.RatingProfessional) -ForegroundColor Green

  Write-Host ""
  foreach ($m in $mods) {
    $name = $m.module
    $out  = $m.outcome
    $pts  = switch ($out) {
      'Compliant'          { 4 }
      'Already Compliant'  { 4 }
      'Applied'            { 2 }
      'Partial'            { 1 }
      'Non-Compliant'      { 0 }
      'Failed'             { 0 }
      'Skipped'            { '-' }
      default              { 0 }
    }
    $tag  = switch ($out) {
      'Compliant'          {'[OK]'}
      'Already Compliant'  {'[OK]'}
      'Applied'            {'[FIX]'}
      'Partial'            {'[! ]'}
      'Non-Compliant'      {'[X ]'}
      'Skipped'            {'[SKIP]'}
      'Failed'             {'[ERR]'}
      default              {'[   ]'}
    }
    Write-Host ("{0} {1}: {2}  (points: {3})" -f $tag, $name, $out, $pts)
  }

  Write-Host ("`nLog file: {0}" -f $last.FullName) -ForegroundColor DarkGray
}

# ---------- Logs & Reports utilities ----------

function Open-File-Notepad {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path $Path)) { Write-Host "File not found: $Path" -ForegroundColor Yellow; return }
  Start-Process notepad.exe -ArgumentList "`"$Path`""
}

function Try-Open-FirewallLog {
  if (-not (Test-Path $FwLogPath)) {
    Write-Host "Firewall log not found at: $FwLogPath" -ForegroundColor Yellow
    return
  }
  try { Start-Process notepad.exe -ArgumentList "`"$FwLogPath`"" } 
  catch { Write-Host "Failed to open log. Try running as Admin." -ForegroundColor Red }
}

function Show-LogsMenu {
  while ($true) {
    try {
      Clear-Host
      Write-Host "=== Logs & Reports ===" -ForegroundColor Cyan
      Write-Host "Logs folder: $LogsDir"
      Write-Host ""
      Write-Host "1) Open LAST run report"
      Write-Host "2) Open live firewall log"
      Write-Host "3) Check Backup Status"
      Write-Host "4) Back"
      Write-Host ""

      $opt = (Read-Host "Select option (1-4)").Trim()
      switch ($opt) {
        '1' {
          Ensure-Dirs
          $last = Get-ChildItem $LogsDir -Filter "run-*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
          if ($last) { Open-File-Notepad -Path $last.FullName } else { Write-Host "No run logs found." -ForegroundColor Yellow }
          Pause-UI
        }
        '2' { Try-Open-FirewallLog;  Pause-UI }
        '3' { Check-BackupStatus -ReportOnly $true }
        '4' { return }
        default { Write-Host "Invalid option." -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
      }
    } catch {
      Write-Host ("[Warn] Logs menu error: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
      Pause-UI
    }
  }
}

function Show-MainMenu {
  Ensure-Dirs
  while ($true) {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "    SME SECURITY FRAMEWORK (v1.0)         " -ForegroundColor White
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host " 1.  Audit System (Read-Only)"
    Write-Host " 2.  Enforce Security Baseline (Admin)"
    Write-Host " 3.  Run Specific Module"
    Write-Host " 4.  View Last Report & Score"
    Write-Host " 5.  Logs & Reports"
    Write-Host " 6.  Exit"
    Write-Host "==========================================" -ForegroundColor Cyan
    
    $choice = Read-Host " Select Option"
    
    switch ($choice) {
      '1' { Invoke-Framework -Mode Audit;   Pause-UI }
      '2' { Invoke-Framework -Mode Enforce; Pause-UI }
      '3' { 
        $mods = Get-ModuleNames
        Write-Host "`nAvailable Modules:" -ForegroundColor Yellow
        for ($i=0; $i -lt $mods.Count; $i++) { Write-Host "  $($i+1). $($mods[$i].DisplayName)" }
        
        $raw = Read-Host "Select Module Number"
        
        # Input Validation
        if ([string]::IsNullOrWhiteSpace($raw)) { 
            Write-Host "No selection made." -ForegroundColor Yellow
            Pause-UI
            continue 
        }
        
        $sel = 0
        if (-not [int]::TryParse($raw.Trim(), [ref]$sel)) { 
            Write-Host "Invalid selection (not a number)." -ForegroundColor Yellow
            Pause-UI
            continue 
        }
        
        if ($sel -lt 1 -or $sel -gt $mods.Count) { 
            Write-Host "Selection out of range." -ForegroundColor Yellow
            Pause-UI
            continue 
        }
        
        # Ask for Mode
        $chosen = $mods[$sel-1]
        $modeRaw = Read-Host "Run mode for '$($chosen.DisplayName)' (1=Audit, 2=Enforce)"
        
        if ($modeRaw -eq '2' -or $modeRaw -eq 'enforce') {
             Invoke-Framework -Mode Enforce -Modules @($chosen.FolderName)
        } else {
             Invoke-Framework -Mode Audit -Modules @($chosen.FolderName)
        }
        Pause-UI
      }
      '4' { Show-LastRunSummary; Pause-UI }
      '5' { Show-LogsMenu }
      '6' { Exit }
      'Q' { Exit }
      'q' { Exit }
      default { Write-Host "Invalid option." -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
    }
  }
}

# ------- start
Ensure-Dirs
Show-MainMenu