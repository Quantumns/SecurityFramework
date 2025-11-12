<#  Start-Framework.ps1
    Menu launcher for the SecurityFramework.
    - Detects modules in .\Modules\<ModuleName>\*.psm1 (and also .\Modules\*.psm1)
    - Runs Audit/Enforce for all or a single module
    - Shows last run summary with HK-style score (Skips excluded)
    - Logs & Reports submenu: open run logs, open/tail/snapshot firewall log (robust input handling)
    Windows PowerShell 5.1 compatible
#>

$ErrorActionPreference  = "Stop"
$ProgressPreference     = "SilentlyContinue"

# -------- paths (locked to the script location)
$Root        = $PSScriptRoot
$Framework   = Join-Path $Root "Framework.ps1"
$ModulesDir  = Join-Path $Root "Modules"
$LogsDir     = Join-Path $Root "Logs"
$ConfigPath  = Join-Path $Root "Config\config.json"
$FwLogPath   = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

function Pause-UI { [void](Read-Host "Press Enter to continue...") }

function Test-IsAdmin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-LogsDir { if (-not (Test-Path $LogsDir)) { New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null } }

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

  if ($Mode -eq 'Enforce' -and -not (Test-IsAdmin)) {
    Write-Host "[INFO] Relaunching elevated for Enforce..." -ForegroundColor Yellow
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$Framework`" -Mode $Mode -Config `"$ConfigPath`""
    if ($Modules.Count -gt 0) { $args += " -Modules " + ($Modules -join ',') }
    Start-Process powershell -Verb RunAs -ArgumentList $args | Out-Null
    return
  }

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

function Copy-FirewallLogSnapshot {
  param([string]$DestDir = $LogsDir, [string]$LogPath = $FwLogPath)
  try {
    Ensure-LogsDir
    $stamp = (Get-Date -Format "yyyyMMdd-HHmmss")
    $dest  = Join-Path $DestDir ("pfirewall-{0}.log" -f $stamp)
    if (Test-Path $LogPath) { Copy-Item $LogPath $dest -Force; return $dest }
  } catch { }
  return $null
}

function Open-File-Notepad {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path $Path)) { Write-Host "File not found: $Path" -ForegroundColor Yellow; return }
  Start-Process notepad.exe -ArgumentList "`"$Path`""
}

function Open-File-NotepadElevated {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path $Path)) { Write-Host "File not found: $Path" -ForegroundColor Yellow; return }
  Start-Process notepad.exe -Verb RunAs -ArgumentList "`"$Path`""
}

function Tail-File {
  param(
    [Parameter(Mandatory)][string]$Path,
    [int]$Lines = 200
  )
  if (-not (Test-Path $Path)) { Write-Host "File not found: $Path" -ForegroundColor Yellow; return }
  try {
    Get-Content -Path $Path -Tail $Lines
  } catch {
    Write-Host ("Tail failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
  }
}

function Read-IntOrDefault {
  param(
    [string]$Prompt,
    [int]$Default = 200,
    [int]$Min = 1,
    [int]$Max = 1000000
  )
  $raw = Read-Host $Prompt
  if ($null -eq $raw) { return $Default }
  $s = [string]$raw
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  if ($s -match "^\s*`u001A\s*$") { return $Default } # Ctrl+Z
  if ($s -match "^\s*[qQ]\s*$") { return $Default }
  $val = 0
  if (-not [int]::TryParse($s.Trim(), [ref]$val)) { return $Default }
  if ($val -lt $Min) { return $Min }
  if ($val -gt $Max) { return $Max }
  return $val
}

function Show-RunLogsBrowser {
  Ensure-LogsDir
  $files = Get-ChildItem $LogsDir -Filter "run-*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
  if (-not $files -or $files.Count -eq 0) { Write-Host "No run logs found." -ForegroundColor Yellow; return }

  Write-Host "`nAvailable run logs:" -ForegroundColor Cyan
  for ($i=0; $i -lt $files.Count; $i++) {
    Write-Host ("{0}) {1}" -f ($i+1), $files[$i].Name)
  }
  $raw = Read-Host "Pick log number to open (or Enter to cancel)"
  if ([string]::IsNullOrWhiteSpace($raw)) { return }
  $sel = 0
  if (-not [int]::TryParse($raw.Trim(), [ref]$sel)) { Write-Host "Invalid selection." -ForegroundColor Yellow; return }
  if ($sel -lt 1 -or $sel -gt $files.Count) { Write-Host "Out of range." -ForegroundColor Yellow; return }

  Open-File-Notepad -Path $files[$sel-1].FullName
}

function Try-Open-FirewallLog {
  if (-not (Test-Path $FwLogPath)) {
    Write-Host "Firewall log not found at: $FwLogPath" -ForegroundColor Yellow
    return
  }

  $opened = $false
  try { Start-Process notepad.exe -ArgumentList "`"$FwLogPath`""; $opened = $true } catch { $opened = $false }

  if (-not $opened) {
    Write-Host "Access denied or blocked opening the live firewall log." -ForegroundColor Yellow
    Write-Host "1) Open with elevated Notepad (UAC prompt)"
    Write-Host "2) Create a snapshot copy in Logs and open the copy"
    Write-Host "3) Cancel"
    $c = (Read-Host "Choose (1-3)").Trim()
    switch ($c) {
      '1' { try { Open-File-NotepadElevated -Path $FwLogPath } catch { Write-Host "Failed to open elevated: $($_.Exception.Message)" -ForegroundColor Red } }
      '2' {
        $copy = Copy-FirewallLogSnapshot
        if ($copy) { Write-Host ("Snapshot created: {0}" -f $copy) -ForegroundColor DarkGray; Open-File-Notepad -Path $copy }
        else { Write-Host "Snapshot failed." -ForegroundColor Yellow }
      }
      default { }
    }
  }
}

function Show-LogsMenu {
  while ($true) {
    try {
      Clear-Host
      Write-Host "=== Logs & Reports ===" -ForegroundColor Cyan
      Write-Host "Logs folder: $LogsDir"
      Write-Host ""
      Write-Host "1) Open LAST run report"
      Write-Host "2) Browse and open a run report"
      Write-Host "3) Open live firewall log (handles permissions)"
      Write-Host "4) Tail firewall log (view last lines)"
      Write-Host "5) Snapshot firewall log to Logs and open it"
      Write-Host "6) Back"
      Write-Host ""

      $opt = (Read-Host "Select option (1-6)").Trim()
      switch ($opt) {
        '1' {
          Ensure-LogsDir
          $last = Get-ChildItem $LogsDir -Filter "run-*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
          if ($last) { Open-File-Notepad -Path $last.FullName } else { Write-Host "No run logs found." -ForegroundColor Yellow }
          Pause-UI
        }
        '2' { Show-RunLogsBrowser; Pause-UI }
        '3' { Try-Open-FirewallLog;  Pause-UI }
        '4' {
          if (-not (Test-Path $FwLogPath)) { Write-Host "Firewall log not found." -ForegroundColor Yellow; Pause-UI; continue }
          $lines = Read-IntOrDefault -Prompt "Lines to show (default 200, 'q' to cancel)" -Default 200 -Min 1 -Max 100000
          if ($lines -le 0) { Pause-UI; continue }
          Tail-File -Path $FwLogPath -Lines $lines
          Pause-UI
        }
        '5' {
          $copy = Copy-FirewallLogSnapshot
          if ($copy) { Write-Host ("Snapshot created: {0}" -f $copy) -ForegroundColor DarkGray; Open-File-Notepad -Path $copy }
          else { Write-Host "Snapshot failed." -ForegroundColor Yellow }
          Pause-UI
        }
        '6' { return }   # back to main menu
        default { Write-Host "Invalid option." -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
      }
    } catch {
      Write-Host ("[Warn] Logs menu error: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
      Pause-UI
    }
  }
}

function Show-MainMenu {
  while ($true) {
    Clear-Host
    Write-Host "=== Security Framework Menu ===" -ForegroundColor Cyan
    Write-Host "Root: $Root"
    Write-Host "Modules path: $ModulesDir"
    Write-Host ""
    Write-Host "1) Audit ALL modules"
    Write-Host "2) Enforce ALL modules"
    Write-Host "3) Run ONE module"
    Write-Host "4) Show LAST RUN summary"
    Write-Host "5) Logs & Reports"
    Write-Host "6) Exit"
    Write-Host ""

    $choice = (Read-Host "Select option (1-6)").Trim()
    switch ($choice) {
      '1' { Invoke-Framework -Mode Audit;   Pause-UI }
      '2' { Invoke-Framework -Mode Enforce; Pause-UI }
      '3' {
        $mods = @(Get-ModuleNames)
        if ($mods.Count -eq 0) { Write-Host "No modules found under: $ModulesDir"; Pause-UI; continue }

        Write-Host "`nAvailable modules:" -ForegroundColor Cyan
        for ($i=0; $i -lt $mods.Count; $i++) { "{0}) {1}" -f ($i+1), $mods[$i].DisplayName | Write-Host }

        $raw = Read-Host "Pick module number"
        $sel = 0
        if (-not [int]::TryParse(($raw.Trim()), [ref]$sel)) { Write-Host "Invalid selection (not a number)." -ForegroundColor Yellow; Pause-UI; continue }
        if ($sel -lt 1 -or $sel -gt $mods.Count) { Write-Host "Invalid selection (out of range)." -ForegroundColor Yellow; Pause-UI; continue }

        $chosen = $mods[$sel-1]
        $modeRaw = Read-Host ("Run mode for '{0}' (Audit/Enforce)" -f $chosen.DisplayName)
        $mode = ($modeRaw | ForEach-Object { $_.ToString().Trim() }).ToLower()

        switch ($mode) {
          'audit'   { Invoke-Framework -Mode Audit   -Modules @($chosen.FolderName) }
          'enforce' { Invoke-Framework -Mode Enforce -Modules @($chosen.FolderName) }
          default   { Write-Host "Invalid mode. Type Audit or Enforce." -ForegroundColor Yellow }
        }
        Pause-UI
      }
      '4' { Show-LastRunSummary; Pause-UI }
      '5' { Show-LogsMenu }
      '6' {
        $ans = (Read-Host "Exit the script and close this PowerShell session? (Y/N)").Trim()
        if ($ans -match '^(y|Y)') { Exit 0 }
        else { continue }
      }
      default { Write-Host "Invalid option." -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
    }
  }
}

# ------- start
Ensure-LogsDir
Show-MainMenu
