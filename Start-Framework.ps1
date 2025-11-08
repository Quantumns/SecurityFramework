<#  Start-Framework.ps1
    Menu launcher for the SecurityFramework.
    - Detects modules in .\Modules\<ModuleName>\*.psm1 (and also .\Modules\*.psm1)
    - Runs Audit/Enforce for all or a single module
    - Shows last run summary with HK-style score (Skips excluded)
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

function Pause-UI { [void](Read-Host "Press Enter to continue...") }

function Test-IsAdmin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-ModuleNames {
  <#
    Returns objects: @{ FolderName; DisplayName }
    DisplayName prefers the .psm1 filename (without extension). Falls back to folder name.
    Supports:
      - .\Modules\<ModuleName>\*.psm1
      - .\Modules\*.psm1
  #>
  $list = @()
  if (-not (Test-Path $ModulesDir)) { return $list }

  # Case 1: subfolder modules
  foreach ($dir in Get-ChildItem $ModulesDir -Directory -ErrorAction SilentlyContinue) {
    $psm1 = Get-ChildItem -Path $dir.FullName -Filter *.psm1 -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $display = if ($psm1) { [System.IO.Path]::GetFileNameWithoutExtension($psm1.Name) } else { $dir.Name }
    $list += [pscustomobject]@{
      FolderName  = $dir.Name
      DisplayName = $display
    }
  }

  # Case 2: psm1 directly under Modules
  foreach ($f in Get-ChildItem -Path $ModulesDir -Filter *.psm1 -File -ErrorAction SilentlyContinue) {
    $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
    # FolderName assumed to be the same as filename if no subfolder
    $list += [pscustomobject]@{
      FolderName  = $nameNoExt
      DisplayName = $nameNoExt
    }
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

  # Enforce needs admin; re-launch elevated if necessary
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

  Write-Host "[RUN] $Mode $(if($Modules.Count){'['+$Modules -join ','+']'}else{'[All Modules]'})" -ForegroundColor Cyan
  & powershell @cmd
}

function Get-HKStyleScore {
  <#
    Excludes Skipped from scoring.
    Points:
      Compliant/Already Compliant = 4
      Applied = 2
      Partial = 1
      Non-Compliant/Failed = 0
    Score = (Points / MaxPoints) * 5 + 1
  #>
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

  # Plain-text ratings (no emojis)
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

  Write-Host "`nLog file: $($last.FullName)" -ForegroundColor DarkGray
}

function Show-Menu {
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
    Write-Host "5) Exit"
    Write-Host ""

    $choice = Read-Host "Select option (1-5)"
    switch ($choice) {
      '1' { Invoke-Framework -Mode Audit;  Pause-UI; }
      '2' { Invoke-Framework -Mode Enforce; Pause-UI; }
      '3' {
        $mods = @(Get-ModuleNames)
        if ($mods.Count -eq 0) { Write-Host "No modules found under: $ModulesDir"; Pause-UI; break }

        Write-Host "`nAvailable modules:" -ForegroundColor Cyan
        for ($i=0; $i -lt $mods.Count; $i++) {
          "{0}) {1}" -f ($i+1), $mods[$i].DisplayName | Write-Host
        }

        # Read, trim, and validate selection
        $raw = Read-Host "Pick module number"
        $sel = 0
        if (-not [int]::TryParse(($raw.Trim()), [ref]$sel)) {
          Write-Host "Invalid selection (not a number)." -ForegroundColor Yellow; Pause-UI; break
        }
        if ($sel -lt 1 -or $sel -gt $mods.Count) {
          Write-Host "Invalid selection (out of range)." -ForegroundColor Yellow; Pause-UI; break
        }

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
      '5' { break }
      default { Write-Host "Invalid option." -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
    }
  }
}

# ------- start
Show-Menu
