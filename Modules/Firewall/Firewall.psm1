# Modules/Firewall/Firewall.psm1

function Invoke-Firewall {
  [CmdletBinding()]
  param(
    [ValidateSet("Audit","Enforce")]
    [string]$Mode,
    [Parameter(Mandatory)]
    [object]$Config
  )

  $outcome = "Unknown"
  $details = @()

  try {
    # Example: read default policy from config (with safe defaults)
    $desiredInbound  = $Config.firewall.defaultInbound  | ForEach-Object { $_ } ; if (-not $desiredInbound)  { $desiredInbound  = "Block" }
    $desiredOutbound = $Config.firewall.defaultOutbound | ForEach-Object { $_ } ; if (-not $desiredOutbound) { $desiredOutbound = "Allow" }

    if ($Mode -eq "Enforce") {
      Set-NetFirewallProfile -Profile Domain,Private,Public `
        -Enabled True `
        -DefaultInboundAction  $desiredInbound `
        -DefaultOutboundAction $desiredOutbound `
        -NotifyOnListen True | Out-Null
      $details += "Set profiles=On, Inbound=$desiredInbound, Outbound=$desiredOutbound"
    }

    # Audit state (works in both modes)
    $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    $allOn = -not ($profiles | Where-Object { $_.Enabled -eq 'False' })
    $allInboundBlock = -not ($profiles | Where-Object { $_.DefaultInboundAction -ne 'Block' })

    if ($Mode -eq "Audit") {
      if ($allOn -and $allInboundBlock) { $outcome = "Compliant" } else { $outcome = "Non-Compliant" }
    } else {
      # Enforce path: re-check after applying
      if ($allOn -and $allInboundBlock) { $outcome = "Applied" } else { $outcome = "Partial" }
    }

    [pscustomobject]@{
      module       = "Firewall"
      outcome      = $outcome
      details      = $details
      cisMappings  = @("4.4","4.5")    # keep mappings ready for reporting
      msMappings   = @("WindowsBaseline:Firewall")
      timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    }
  }
  catch {
    [pscustomobject]@{
      module       = "Firewall"
      outcome      = "Failed"
      error        = $_.Exception.Message
      timestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    }
  }
}
Export-ModuleMember -Function Invoke-Firewall
