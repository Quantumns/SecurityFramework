param(
  [ValidateSet("Audit","Enforce")]
  [string]$Mode = "Audit",
  [string]$Config = ".\Config\config.json",
  [string[]]$Modules = @()  # empty = run all found modules
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Helper: timestamp + host + runId
$HostName = $env:COMPUTERNAME
$RunId    = (Get-Date -Format "yyyyMMdd-HHmmss") + "_$HostName"
$logDir   = Join-Path $PSScriptRoot "Logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Write-Info($msg)  { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn($msg)  { Write-Warning $msg }
function Write-Err ($msg)  { Write-Error $msg }

# Load config
if (-not (Test-Path $Config)) { Write-Err "Config not found: $Config"; exit 2 }
$configObj = Get-Content $Config -Raw | ConvertFrom-Json

# Discover modules
$modulesRoot = Join-Path $PSScriptRoot "Modules"
$allModulePaths = Get-ChildItem $modulesRoot -Directory | Select-Object -ExpandProperty FullName

if ($Modules.Count -gt 0) {
  $selected = foreach ($m in $Modules) {
    $match = $allModulePaths | Where-Object { $_ -match [regex]::Escape($m) }
    if ($null -eq $match) { Write-Warn "Module not found: $m" } else { $match }
  }
  $modulePaths = $selected | Sort-Object -Unique
} else {
  $modulePaths = $allModulePaths | Sort-Object
}

# Results accumulator
$results = [System.Collections.Generic.List[object]]::new()

foreach ($mp in $modulePaths) {
  $moduleName = Split-Path $mp -Leaf
  $psm1 = Join-Path $mp "$moduleName.psm1"

  if (-not (Test-Path $psm1)) {
    Write-Warn "Skipping ${moduleName}: no ${moduleName}.psm1"
    continue
  }

  Write-Info "Loading module: $moduleName"
  Import-Module $psm1 -Force

  # Each module exposes: Invoke-<ModuleName> -Mode <Audit|Enforce> -Config <object>
  $invokeName = "Invoke-$moduleName"
  if (-not (Get-Command $invokeName -ErrorAction SilentlyContinue)) {
    Write-Warn "Skipping ${moduleName}: no function ${invokeName}"
    continue
  }

  try {
    Write-Info "Running $moduleName in $Mode mode"
    $moduleResult = & $invokeName -Mode $Mode -Config $configObj  # returns object
    $results.Add($moduleResult)
  }
  catch {
    $err = $_.Exception.Message
    Write-Err "Module $moduleName failed: $err"
    $results.Add([pscustomobject]@{
      module       = $moduleName
      outcome      = "Failed"
      error        = $err
      timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    })
  }
}

$runSummary = [pscustomobject]@{
  runId        = $RunId
  host         = $HostName
  mode         = $Mode
  scriptVersion= "0.1.0"
  modules      = $results
  timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
}

$logPath = Join-Path $logDir "run-$RunId.json"
$runSummary | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $logPath
Write-Info "Run log written: $logPath"
