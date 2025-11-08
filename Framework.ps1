param(
  [ValidateSet("Audit","Enforce")]
  [string]$Mode = "Audit",
  [string]$Config = ".\Config\config.json",
  [string[]]$Modules = @()  # empty = run all found modules
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

# ------------------------
# Preflight checks
# ------------------------
# PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Error "PowerShell 5.1+ required. Detected: $($PSVersionTable.PSVersion)"
  exit 1
}

# Admin hint for Enforce (the menu re-launches elevated, but direct runs may not)
function Test-IsAdmin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ($Mode -eq "Enforce" -and -not (Test-IsAdmin)) {
  Write-Warning "Enforce mode works best with Administrator rights (some changes may fail without elevation)."
}

# ------------------------
# Paths and folders
# ------------------------
$HostName = $env:COMPUTERNAME
$RunId    = (Get-Date -Format "yyyyMMdd-HHmmss") + "_$HostName"
$rootDir  = $PSScriptRoot

# Ensure Logs directory
$logDir   = Join-Path $rootDir "Logs"
if (-not (Test-Path $logDir)) {
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
}

# Ensure Config directory + default config if missing
$configDir = Split-Path -Parent (Resolve-Path -LiteralPath $Config -ErrorAction SilentlyContinue)
if (-not $configDir) {
  $configDir = Join-Path $rootDir "Config"
}
if (-not (Test-Path $configDir)) {
  New-Item -ItemType Directory -Force -Path $configDir | Out-Null
}

if (-not (Test-Path $Config)) {
  # Create a safe default config if none exists
  $defaultCfg = @{
    firewall = @{
      defaultInbound  = "Block"
      defaultOutbound = "Allow"
    }
    # Future modules can read their sections here, e.g.:
    # updates = @{ autoInstall = $true; activeHoursStart = 8; activeHoursEnd = 18 }
  } | ConvertTo-Json -Depth 6
  $Config = Join-Path $configDir "config.json"
  $defaultCfg | Out-File -FilePath $Config -Encoding utf8
  Write-Warning "No config found. Created default: $Config"
}

function Write-Info($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Warning $msg }
function Write-Err ($msg) { Write-Error $msg }

# ------------------------
# Load config
# ------------------------
try {
  $configRaw = Get-Content $Config -Raw -ErrorAction Stop
  $configObj = $configRaw | ConvertFrom-Json -ErrorAction Stop
} catch {
  Write-Err "Failed to read/parse config at '$Config': $($_.Exception.Message)"
  exit 2
}

# ------------------------
# Discover modules
# ------------------------
$modulesRoot = Join-Path $rootDir "Modules"
if (-not (Test-Path $modulesRoot)) {
  New-Item -ItemType Directory -Force -Path $modulesRoot | Out-Null
  Write-Warn "Modules folder not found. Created empty folder at: $modulesRoot"
}

$allModuleDirs = Get-ChildItem $modulesRoot -Directory -ErrorAction SilentlyContinue

if (-not $allModuleDirs -or $allModuleDirs.Count -eq 0) {
  Write-Warn "No modules found under: $modulesRoot"
}

# If specific modules requested, match by folder name (case-insensitive, exact)
if ($Modules.Count -gt 0) {
  $wanted = @()
  foreach ($m in $Modules) {
    $match = $allModuleDirs | Where-Object { $_.Name -ieq $m }
    if ($null -eq $match -or $match.Count -eq 0) {
      Write-Warn "Module not found: $m"
    } else {
      $wanted += $match
    }
  }
  $moduleDirs = $wanted | Sort-Object -Unique
} else {
  $moduleDirs = $allModuleDirs | Sort-Object Name
}

# ------------------------
# Execute modules
# ------------------------
$results = [System.Collections.Generic.List[object]]::new()

foreach ($dir in $moduleDirs) {
  $moduleName = $dir.Name
  $psm1       = Join-Path $dir.FullName "$moduleName.psm1"

  if (-not (Test-Path $psm1)) {
    Write-Warn ("Skipping {0}: no {0}.psm1" -f $moduleName)
    continue
  }

  Write-Info ("Loading module: {0}" -f $moduleName)
  try {
    Import-Module $psm1 -Force -ErrorAction Stop
  } catch {
    $err = $_.Exception.Message
    Write-Err ("Import failed for module {0}: {1}" -f $moduleName, $err)
    $results.Add([pscustomobject]@{
      module       = $moduleName
      outcome      = "Failed"
      error        = "Import failed: $err"
      timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    })
    continue
  }

  $invokeName = "Invoke-$moduleName"
  if (-not (Get-Command $invokeName -ErrorAction SilentlyContinue)) {
    Write-Warn ("Skipping {0}: no function {1}" -f $moduleName, $invokeName)
    continue
  }

  try {
    Write-Info ("Running {0} in {1} mode" -f $moduleName, $Mode)
    $moduleResult = & $invokeName -Mode $Mode -Config $configObj
    # Basic shape guard
    if (-not $moduleResult) {
      $moduleResult = [pscustomobject]@{
        module       = $moduleName
        outcome      = "Failed"
        error        = "Module returned no result."
        timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
      }
    }
    $results.Add($moduleResult)
  }
  catch {
    $err = $_.Exception.Message
    Write-Err ("Module {0} failed: {1}" -f $moduleName, $err)
    $results.Add([pscustomobject]@{
      module       = $moduleName
      outcome      = "Failed"
      error        = $err
      timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    })
  }
}

# ------------------------
# Write run summary
# ------------------------
$runSummary = [pscustomobject]@{
  runId         = $RunId
  host          = $HostName
  mode          = $Mode
  scriptVersion = "0.1.0"
  modules       = $results
  timestampUtc  = (Get-Date).ToUniversalTime().ToString("o")
}

$logPath = Join-Path $logDir "run-$RunId.json"
$runSummary | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $logPath
Write-Info "Run log written: $logPath"
