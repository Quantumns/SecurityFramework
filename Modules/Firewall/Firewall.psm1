<#
  Firewall.psm1 - SecurityFramework (Windows PowerShell 5.1)

  - Policy-aware defaults for Domain/Private/Public
  - Default inbound/outbound from config with safe fallbacks
  - Logging enablement (LogBlocked=True, LogAllowed=False) with enum handling + netsh fallback
  - Explicit high-risk block rules (SMB TCP/445, Telnet TCP/23)
  - Optional TeamViewer allow (inbound 5938) if detected and enabled in config
  - Config-driven additional rules (idempotent upsert)
  - Clear Audit/Enforce outcomes with evidence in details
  - Pure ASCII; PS 5.1 compatible
#>

function Write-Info([string]$msg) { Write-Host ("[INFO] {0}" -f $msg) -ForegroundColor Cyan }
function Write-Warn([string]$msg) { Write-Warning $msg }
function Write-Err ([string]$msg) { Write-Error $msg }

function Test-HasProp {
  param(
    [Parameter(Mandatory)]$Object,
    [Parameter(Mandatory)][string]$Name
  )
  if ($null -eq $Object) { return $false }
  if ($Object -is [hashtable]) { return $Object.ContainsKey($Name) }
  try { return ($Object.PSObject.Properties.Name -contains $Name) } catch { return $false }
}

function Test-ProfilePolicyControlled {
  param(
    [Parameter(Mandatory)]
    [ValidateSet('Domain','Private','Public')]
    [string]$Profile
  )
  $base = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
  $sub  = switch ($Profile) {
    'Domain'  { 'DomainProfile' }
    'Private' { 'PrivateProfile' }
    'Public'  { 'PublicProfile' }
  }
  $keyPath = Join-Path $base $sub
  try {
    if (Test-Path $keyPath) {
      $props = Get-ItemProperty -Path $keyPath -ErrorAction Stop
      if ($null -ne $props.EnableFirewall)        { return $true }
      if ($null -ne $props.DefaultInboundAction)  { return $true }
      if ($null -ne $props.DefaultOutboundAction) { return $true }
    }
  } catch { }
  return $false
}

function Ensure-MpsSvc {
  $svc = Get-Service -Name 'mpssvc' -ErrorAction SilentlyContinue
  if (-not $svc) { throw "Firewall service 'mpssvc' not found." }
  $changed = $false
  if ($svc.StartType -ne 'Automatic') { Set-Service -Name 'mpssvc' -StartupType Automatic; $changed = $true }
  if ($svc.Status -ne 'Running')      { Start-Service -Name 'mpssvc'; $changed = $true }
  return $changed
}

function Convert-ToGpoBoolean {
  param([bool]$Value)
  try {
    $t = [type]'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean'
    if ($Value) { return $t::True } else { return $t::False }
  } catch { return $Value }
}

function Resolve-GpoBool {
  param($Value)
  try {
    $s = $Value.ToString()
    if ($s -eq 'True')  { return $true }
    if ($s -eq 'False') { return $false }
    return $false
  } catch { return [bool]$Value }
}

function Ensure-FirewallLogging {
  param(
    [Parameter(Mandatory)]
    [ValidateSet('Domain','Private','Public')]
    [string]$ProfileName,
    [string]$LogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log",
    [int]$MaxKB = 16384,
    [bool]$LogDropped = $true,
    [bool]$LogAllowed = $false
  )
  $changed = $false
  try {
    $p = Get-NetFirewallProfile -Profile $ProfileName
    if ($p.LogFileName -ne $LogPath)       { Set-NetFirewallProfile -Profile $ProfileName -LogFileName $LogPath | Out-Null; $changed = $true }
    if ($p.LogMaxSizeKilobytes -ne $MaxKB) { Set-NetFirewallProfile -Profile $ProfileName -LogMaxSizeKilobytes $MaxKB | Out-Null; $changed = $true }

    $dropVal  = Convert-ToGpoBoolean -Value:$LogDropped
    $allowVal = Convert-ToGpoBoolean -Value:$LogAllowed

    if ((Resolve-GpoBool $p.LogBlocked) -ne $LogDropped) { Set-NetFirewallProfile -Profile $ProfileName -LogBlocked  $dropVal  | Out-Null; $changed = $true }
    if ((Resolve-GpoBool $p.LogAllowed) -ne $LogAllowed) { Set-NetFirewallProfile -Profile $ProfileName -LogAllowed  $allowVal | Out-Null; $changed = $true }
    return $changed
  } catch {
    $token = switch ($ProfileName) { 'Domain'{'domainprofile'} 'Private'{'privateprofile'} 'Public'{'publicprofile'} }
    try {
      if ($LogPath) { & netsh advfirewall set $token logging logfilename "$LogPath" | Out-Null; $changed = $true }
      if ($MaxKB)   { & netsh advfirewall set $token logging maxfilesize $MaxKB     | Out-Null; $changed = $true }
      & netsh advfirewall set $token logging droppedconnections  $(if($LogDropped){'enable'} else {'disable'}) | Out-Null; $changed = $true
      & netsh advfirewall set $token logging allowedconnections $(if($LogAllowed){'enable'} else {'disable'}) | Out-Null; $changed = $true
      return $changed
    } catch {
      throw ("Logging configuration failed for {0} via NetSecurity and netsh: {1}" -f $ProfileName, $_.Exception.Message)
    }
  }
}

# Create/update rules without -Enabled to avoid enum cast issues; toggle state after.
function Ensure-FirewallRule {
  param(
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][ValidateSet('Inbound','Outbound')]$Direction,
    [Parameter(Mandatory)][ValidateSet('TCP','UDP','Any')]$Protocol,
    [string]$LocalPort = '',
    [ValidateSet('Allow','Block')][string]$Action = 'Block',
    [ValidateSet('Domain','Private','Public','Any')][string]$Profile = 'Any',
    [string]$Program = '',
    [string]$RemoteAddress = 'Any',
    [bool]$Enabled = $true
  )

  $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
  if (-not $existing) {
    $params = @{
      DisplayName = $DisplayName
      Direction   = $Direction
      Action      = $Action
      Profile     = $Profile
    }
    if ($Program) { $params.Program = $Program }
    if ($RemoteAddress -and $RemoteAddress -ne 'Any') { $params.RemoteAddress = $RemoteAddress }
    if ($Protocol -and $Protocol -ne 'Any') { $params.Protocol = $Protocol }
    if ($LocalPort) { $params.LocalPort = $LocalPort }

    New-NetFirewallRule @params | Out-Null

    if ($Enabled) { Enable-NetFirewallRule -DisplayName $DisplayName | Out-Null }
    else          { Disable-NetFirewallRule -DisplayName $DisplayName | Out-Null }

    return 'Created'
  }

  $changed = $false

  if ($existing.Action -ne $Action)               { Set-NetFirewallRule -DisplayName $DisplayName -Action $Action       | Out-Null; $changed = $true }
  if ($existing.Direction -ne $Direction)         { Set-NetFirewallRule -DisplayName $DisplayName -Direction $Direction | Out-Null; $changed = $true }
  if ($existing.Profile.ToString() -ne $Profile)  { Set-NetFirewallRule -DisplayName $DisplayName -Profile $Profile     | Out-Null; $changed = $true }
  if ($Program -and $existing.Program -ne $Program) { Set-NetFirewallRule -DisplayName $DisplayName -Program $Program   | Out-Null; $changed = $true }

  if ($RemoteAddress -and $RemoteAddress -ne 'Any') {
    $fa = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $existing
    if ($fa.RemoteAddress -ne $RemoteAddress) {
      Set-NetFirewallRule -DisplayName $DisplayName -RemoteAddress $RemoteAddress | Out-Null
      $changed = $true
    }
  }

  $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existing
  $curProto = if ($pf.Protocol -eq 256) { 'Any' } else { $pf.Protocol }
  if ($Protocol -and $Protocol -ne $curProto) {
    Set-NetFirewallRule -DisplayName $DisplayName -Protocol $Protocol | Out-Null
    $changed = $true
  }
  if ($LocalPort) {
    if ($pf.LocalPort -ne $LocalPort) {
      Set-NetFirewallRule -DisplayName $DisplayName -LocalPort $LocalPort | Out-Null
      $changed = $true
    }
  }

  $isEnabled = ($existing.Enabled -eq 'True' -or $existing.Enabled -eq $true)
  if ($Enabled -and -not $isEnabled) { Enable-NetFirewallRule -DisplayName $DisplayName | Out-Null; $changed = $true }
  if (-not $Enabled -and $isEnabled) { Disable-NetFirewallRule -DisplayName $DisplayName | Out-Null; $changed = $true }

  if ($changed) { return 'Updated' } else { return 'Unchanged' }
}

function Test-TeamViewerPresent {
  try {
    $paths = @(
      "$env:ProgramFiles\TeamViewer\TeamViewer.exe",
      "$env:ProgramFiles(x86)\TeamViewer\TeamViewer.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
  } catch { }
  return $null
}

function Invoke-Firewall {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'Firewall'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('4.4','4.7')
    msMappings   = @('WindowsBaseline:Firewall')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $fwCfg = $Config.firewall
  if (-not $fwCfg) { $fwCfg = @{} }

  if (Test-HasProp $fwCfg 'defaultInbound')  { $desiredInbound  = $fwCfg.defaultInbound }  else { $desiredInbound  = 'Block' }
  if (Test-HasProp $fwCfg 'defaultOutbound') { $desiredOutbound = $fwCfg.defaultOutbound } else { $desiredOutbound = 'Allow' }

  $allowTVInbound = $false
  if (Test-HasProp $fwCfg 'allowTeamViewerInbound') { $allowTVInbound = [bool]$fwCfg.allowTeamViewerInbound }

  $profiles = @('Domain','Private','Public')

  $policyControlled = @{}
  foreach ($p in $profiles) {
    $policyControlled[$p] = Test-ProfilePolicyControlled -Profile $p
    if ($Mode -eq 'Enforce' -and $policyControlled[$p]) {
      $result.details.Add( ("Policy-controlled profile detected: {0}" -f $p) )
    }
  }

  if ($Mode -eq 'Enforce') {
    try {
      $serviceChanged = $false
      if (Ensure-MpsSvc) { $serviceChanged = $true; $result.details.Add('Firewall service ensured as Automatic and Running.') }

      $profileChanges = @{}
      $loggingChanged = @()
      $ruleChanges    = @()

      foreach ($p in $profiles) {
        if ($policyControlled[$p]) { continue }

        $before = Get-NetFirewallProfile -Profile $p
        Set-NetFirewallProfile -Profile $p -Enabled True -DefaultInboundAction $desiredInbound -DefaultOutboundAction $desiredOutbound | Out-Null
        $after = Get-NetFirewallProfile -Profile $p

        $changed = ($before.Enabled -ne $after.Enabled) -or
                   ($before.DefaultInboundAction -ne $after.DefaultInboundAction) -or
                   ($before.DefaultOutboundAction -ne $after.DefaultOutboundAction)
        $profileChanges[$p] = $changed
        if ($changed) { $result.details.Add( ("Applied baseline to {0}: Enabled=True, Inbound={1}, Outbound={2}." -f $p, $desiredInbound, $desiredOutbound) ) }
        else          { $result.details.Add( ("No baseline change needed for {0}." -f $p) ) }

        $logChanged = Ensure-FirewallLogging -ProfileName $p -LogDropped:$true -LogAllowed:$false -MaxKB 16384
        if ($logChanged) { $loggingChanged += $p; $result.details.Add( ("Logging set for {0}: LogBlocked=True, LogAllowed=False, Max=16384KB." -f $p) ) }
        else             { $result.details.Add( ("Logging already compliant for {0}." -f $p) ) }
      }

      foreach ($spec in @(
        @{ name='SF-Block-SMB-445';   dir='Inbound'; proto='TCP'; port='445'; action='Block'; profile='Any' },
        @{ name='SF-Block-Telnet-23'; dir='Inbound'; proto='TCP'; port='23';  action='Block'; profile='Any' }
      )) {
        $state = Ensure-FirewallRule -DisplayName $spec.name -Direction $spec.dir -Protocol $spec.proto -LocalPort $spec.port -Action $spec.action -Profile $spec.profile -Enabled:$true
        if     ($state -eq 'Created') { $result.details.Add(("Rule created: {0}." -f $spec.name)) }
        elseif ($state -eq 'Updated') { $result.details.Add(("Rule updated: {0}." -f $spec.name)) }
        else                          { $result.details.Add(("Rule unchanged: {0}." -f $spec.name)) }
        $ruleChanges += $state
      }

      $tvExe = Test-TeamViewerPresent
      if ($tvExe) {
        if ($allowTVInbound) {
          $state = Ensure-FirewallRule -DisplayName 'SF-Allow-TeamViewer-5938' -Direction Inbound -Protocol TCP -LocalPort '5938' -Action Allow -Profile 'Any' -Program $tvExe -Enabled:$true
          if     ($state -eq 'Created') { $result.details.Add('Rule created: SF-Allow-TeamViewer-5938 (Inbound TCP 5938, TeamViewer).') }
          elseif ($state -eq 'Updated') { $result.details.Add('Rule updated: SF-Allow-TeamViewer-5938.') }
          else                          { $result.details.Add('Rule unchanged: SF-Allow-TeamViewer-5938.') }
          $ruleChanges += $state
        } else {
          $result.details.Add( ("TeamViewer detected at {0} but inbound allow is disabled in config." -f $tvExe) )
        }
      } else {
        $result.details.Add('TeamViewer not detected.')
      }

      # Config-driven rules (split the condition to avoid '-and' misparse)
      if (Test-HasProp $fwCfg 'rules') {
        if ($fwCfg.rules) {
          foreach ($r in $fwCfg.rules) {
            $nm = $r.name; $dir = $r.direction; $pro = $r.protocol
            $prt = ''; if ($r.localPort) { $prt = $r.localPort.ToString() }
            $act = $r.action
            $prof = 'Any'; if ($r.profile) { $prof = $r.profile }
            $prog = ''; if ($r.program) { $prog = $r.program }
            $rad = 'Any'; if ($r.remoteAddress) { $rad = $r.remoteAddress }
            $ena = $true; if ($r.enabled -ne $null) { $ena = [bool]$r.enabled }

            $state = Ensure-FirewallRule -DisplayName $nm -Direction $dir -Protocol $pro -LocalPort $prt -Action $act -Profile $prof -Program $prog -RemoteAddress $rad -Enabled:$ena
            if     ($state -eq 'Created') { $result.details.Add(("Rule created: {0}." -f $nm)) }
            elseif ($state -eq 'Updated') { $result.details.Add(("Rule updated: {0}." -f $nm)) }
            else                          { $result.details.Add(("Rule unchanged: {0}." -f $nm)) }
            $ruleChanges += $state
          }
        }
      }

      $anyProfileChanged = $false
      foreach ($k in $profileChanges.Keys) { if ($profileChanges[$k]) { $anyProfileChanged = $true; break } }
      $anyLoggingChanged = ($loggingChanged.Count -gt 0)
      $anyRuleApplied    = (($ruleChanges | Where-Object { $_ -eq 'Created' -or $_ -eq 'Updated' }).Count -gt 0)

      if ($anyProfileChanged -or $anyLoggingChanged -or $anyRuleApplied -or $serviceChanged) { $result.outcome = 'Applied' }
      else { $result.outcome = 'Already Compliant' }
    }
    catch {
      $result.outcome = 'Failed'
      $result.details.Add( ("Enforce failed: {0}" -f $_.Exception.Message) )
    }
  }
  else {
    try {
      $nonCompliant = $false
      foreach ($p in $profiles) {
        $prof = Get-NetFirewallProfile -Profile $p
        if ($policyControlled[$p]) { $result.details.Add(("Audit: {0} is policy-controlled; baseline not enforced by tool." -f $p)); continue }

        $enabledOk = ($prof.Enabled -eq $true)
        $inOk  = ($prof.DefaultInboundAction  -eq $desiredInbound)
        $outOk = ($prof.DefaultOutboundAction -eq $desiredOutbound)

        if ($enabledOk -and $inOk -and $outOk) {
          $result.details.Add(("Audit: {0} baseline OK (Enabled=True, Inbound={1}, Outbound={2})." -f $p, $desiredInbound, $desiredOutbound))
        } else {
          $nonCompliant = $true
          $result.details.Add(("Audit: {0} baseline mismatch (Enabled={1}, Inbound={2}, Outbound={3}; expected True/{4}/{5})." -f $p, $prof.Enabled, $prof.DefaultInboundAction, $prof.DefaultOutboundAction, $desiredInbound, $desiredOutbound))
        }

        if (-not (Resolve-GpoBool $prof.LogBlocked)) {
          $nonCompliant = $true
          $result.details.Add(("Audit: {0} LogBlocked disabled (expected True)." -f $p))
        }
      }

      foreach ($rn in @('SF-Block-SMB-445','SF-Block-Telnet-23')) {
        if (-not (Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue)) {
          $nonCompliant = $true
          $result.details.Add(("Audit: missing expected rule '{0}'." -f $rn))
        }
      }

      # Config-driven rules (split the condition)
      if (Test-HasProp $fwCfg 'rules') {
        if ($fwCfg.rules) {
          foreach ($r in $fwCfg.rules) {
            if (-not (Get-NetFirewallRule -DisplayName $r.name -ErrorAction SilentlyContinue)) {
              $nonCompliant = $true
              $result.details.Add(("Audit: missing config-defined rule '{0}'." -f $r.name))
            }
          }
        }
      }

      if ($nonCompliant) { $result.outcome = 'Non-Compliant' } else { $result.outcome = 'Compliant' }
    }
    catch {
      $result.outcome = 'Failed'
      $result.details.Add(("Audit failed: {0}" -f $_.Exception.Message))
    }
  }

  $result.timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  return $result
}

Export-ModuleMember -Function Invoke-Firewall
