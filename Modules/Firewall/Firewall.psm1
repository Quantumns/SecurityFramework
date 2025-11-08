# Modules/Firewall/Firewall.psm1

function Test-FirewallPolicyControlled {
  param([string]$ProfileKeyName) # "DomainProfile","PrivateProfile","PublicProfile"
  $keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$ProfileKeyName"
  if (Test-Path $keyPath) {
    $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
    if ($props) {
      $hasPolicy = ($props.PSObject.Properties.Name -match 'Default(Inbound|Outbound)Action|EnableFirewall').Count -gt 0
      return $hasPolicy
    }
  }
  return $false
}

function Get-PolicyOwner {
  # Returns "Domain GPO", "Local Group Policy", or "None"
  param(
    [bool]$PartOfDomain,
    [bool]$IsControlled
  )
  if (-not $IsControlled) { return "None" }
  if ($PartOfDomain) { return "Domain GPO" }
  return "Local Group Policy"
}

function Ensure-FirewallService {
  try {
    $svc = Get-Service -Name mpssvc -ErrorAction Stop
    if ($svc.StartType -ne 'Automatic') { Set-Service mpssvc -StartupType Automatic }
    if ($svc.Status -ne 'Running')      { Start-Service mpssvc }
    return $true
  } catch { return $false }
}

function Get-ProfileState {
  $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
  $map = @{}
  foreach ($p in $profiles) { $map[$p.Name] = $p }
  return $map
}

function Set-ProfileBaseline {
  param(
    [string]$ProfileName,            # Domain | Private | Public
    [string]$InboundDesired = 'Block',
    [string]$OutboundDesired = 'Allow'
  )
  Set-NetFirewallProfile -Profile $ProfileName `
                         -Enabled True `
                         -DefaultInboundAction $InboundDesired `
                         -DefaultOutboundAction $OutboundDesired `
                         -NotifyOnListen True | Out-Null
}

function Invoke-Firewall {
  [CmdletBinding()]
  param(
    [ValidateSet("Audit","Enforce")]
    [string]$Mode,
    [Parameter(Mandatory)]
    [object]$Config
  )

  $result = [ordered]@{
    module       = "Firewall"
    outcome      = "Unknown"
    details      = [System.Collections.Generic.List[string]]::new()
    cisMappings  = @("4.4","4.5")
    msMappings   = @("WindowsBaseline:Firewall")
    timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
  }

  try {
    $desiredInbound  = if ($Config.firewall.defaultInbound)  { [string]$Config.firewall.defaultInbound }  else { "Block" }
    $desiredOutbound = if ($Config.firewall.defaultOutbound) { [string]$Config.firewall.defaultOutbound } else { "Allow" }

    if (-not (Ensure-FirewallService)) {
      $result.details.Add("Firewall service (mpssvc) could not be started.")
      $result.outcome = "Failed"
      return [pscustomobject]$result
    }

    # Domain membership
    $domainMember = $false
    try {
      $domainMember = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    } catch { $domainMember = $false }

    # Per-profile policy control detection
    $policyControlled = @{
      Domain  = (Test-FirewallPolicyControlled -ProfileKeyName 'DomainProfile')
      Private = (Test-FirewallPolicyControlled -ProfileKeyName 'PrivateProfile')
      Public  = (Test-FirewallPolicyControlled -ProfileKeyName 'PublicProfile')
    }
    $policyOwner = @{
      Domain  = (Get-PolicyOwner -PartOfDomain:$domainMember -IsControlled:$policyControlled.Domain)
      Private = (Get-PolicyOwner -PartOfDomain:$domainMember -IsControlled:$policyControlled.Private)
      Public  = (Get-PolicyOwner -PartOfDomain:$domainMember -IsControlled:$policyControlled.Public)
    }

    $before = Get-ProfileState
    $changes = 0

    if ($Mode -eq "Enforce") {
      foreach ($name in @('Domain','Private','Public')) {
        if ($policyControlled[$name]) {
          $result.details.Add(("Skipped {0}: policy-controlled ({1})." -f $name, $policyOwner[$name]))
          continue
        }

        $p = $before[$name]
        $needsChange = ($p.Enabled -ne 'True' -or
                        $p.DefaultInboundAction  -ne $desiredInbound  -or
                        $p.DefaultOutboundAction -ne $desiredOutbound)

        if ($needsChange) {
          Set-ProfileBaseline -ProfileName $name -InboundDesired $desiredInbound -OutboundDesired $desiredOutbound
          $result.details.Add(("Applied baseline to {0}: Enabled=True, Inbound={1}, Outbound={2}." -f $name, $desiredInbound, $desiredOutbound))
          $changes++
        } else {
          $result.details.Add(("{0} already compliant." -f $name))
        }
      }
    }

    $after = Get-ProfileState

    # Build non-compliance list (only for profiles we are allowed to manage)
    $nonCompliant = @()
    foreach ($name in @('Domain','Private','Public')) {
      if ($policyControlled[$name]) { continue }
      $p = $after[$name]
      if ($p.Enabled -ne 'True' -or
          $p.DefaultInboundAction  -ne $desiredInbound  -or
          $p.DefaultOutboundAction -ne $desiredOutbound) {
        $nonCompliant += $name
      }
    }

    # Outcome logic
    if ($Mode -eq "Audit") {
      $allThreeControlled = ($policyControlled.Domain -and $policyControlled.Private -and $policyControlled.Public)
      if ($allThreeControlled) {
        # Clarify exact owner type
        if ($domainMember) {
          $result.details.Add("All profiles are policy-controlled by Domain GPO.")
        } else {
          $result.details.Add("All profiles are policy-controlled by Local Group Policy.")
        }
        $result.outcome = "Skipped"
      } else {
        if ($nonCompliant.Count -eq 0) {
          $result.outcome = "Compliant"
        } else {
          $result.outcome = "Non-Compliant"
          foreach ($n in $nonCompliant) {
            $p = $after[$n]
            $result.details.Add(("{0}: Enabled={1}, Inbound={2}, Outbound={3} (expected Enabled=True, Inbound={4}, Outbound={5})." -f `
              $n, $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction, $desiredInbound, $desiredOutbound))
          }
          # Also list policy-controlled profiles for clarity
          foreach ($n in @('Domain','Private','Public')) {
            if ($policyControlled[$n]) {
              $result.details.Add(("{0} is policy-controlled ({1})." -f $n, $policyOwner[$n]))
            }
          }
        }
      }
    } else {
      # Enforce mode: distinguish "Already Compliant" vs "Applied" vs "Partial"
      if ($nonCompliant.Count -eq 0) {
        if ($changes -gt 0) {
          $result.outcome = "Applied"
        } else {
          $result.outcome = "Already Compliant"
        }
      } else {
        $result.outcome = "Partial"
        foreach ($n in $nonCompliant) {
          $p = $after[$n]
          $result.details.Add(("Post-enforce still not compliant: {0} (Enabled={1}, Inbound={2}, Outbound={3})." -f `
            $n, $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction))
        }
      }

      # Always annotate policy-controlled profiles in Enforce results
      foreach ($n in @('Domain','Private','Public')) {
        if ($policyControlled[$n]) {
          $result.details.Add(("{0} is policy-controlled ({1}); local script did not modify." -f $n, $policyOwner[$n]))
        }
      }
    }

    return [pscustomobject]$result
  }
  catch {
    return [pscustomobject]@{
      module       = "Firewall"
      outcome      = "Failed"
      error        = $_.Exception.Message
      timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    }
  }
}

Export-ModuleMember -Function Invoke-Firewall
