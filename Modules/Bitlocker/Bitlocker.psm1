<#
  BitLocker.psm1 - SecurityFramework
#>

function Invoke-BitLocker {
  param(
    [Parameter(Mandatory)][ValidateSet('Audit','Enforce')] [string]$Mode,
    [Parameter(Mandatory)] [object]$Config
  )

  $result = [pscustomobject]@{
    module       = 'BitLocker'
    outcome      = $null
    details      = New-Object System.Collections.Generic.List[string]
    cisMappings  = @('3.6', '3.11')
    msMappings   = @('WindowsBaseline:BitLocker')
    timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  }

  $cfg = $Config.bitlocker
  if (-not $cfg) {
    $result.outcome = 'Failed'; $result.details.Add("Config missing"); return $result
  }

  try {
    # 1. Check BitLocker Status on C: FIRST
    $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    
    if (-not $vol) {
        # If we can't read status (e.g. not Admin), we can't determine compliance
        $result.outcome = 'Failed'
        $result.details.Add("Error: Access denied or C: drive not found. (Run as Admin)")
        return $result
    }

    # Check Encryption Status (ProtectionStatus: 1 = On)
    if ($vol.ProtectionStatus -eq 1) {
        $result.details.Add("BitLocker is active and compliant ($($vol.EncryptionMethod)).")
        $result.outcome = 'Compliant' # Explicitly set success here
    } 
    else {
        # 2. Only check TPM if we need to ENABLE BitLocker
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        $tpmReady = ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady)

        if (-not $tpmReady) {
            $result.outcome = 'Skipped'
            $result.details.Add("Audit: BitLocker is OFF. Skipped enforcement because TPM is missing/not ready.")
            return $result
        }

        # BitLocker is OFF, TPM is ON -> We can Enforce
        if ($Mode -eq 'Enforce' -and $cfg.enableBitLocker) {
            if (-not (Test-Path $cfg.backupPath)) { New-Item -ItemType Directory -Force -Path $cfg.backupPath | Out-Null }

            Enable-BitLocker -MountPoint "C:" -EncryptionMethod $cfg.encryptionMethod -UsedSpaceOnly -TpmProtector -ErrorAction Stop

            # Backup Key
            $keyId = (Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | Select-Object -ExpandProperty KeyProtectorId
            if ($keyId) {
               Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $keyId -Path $cfg.backupPath
               $result.details.Add("Enabled BitLocker. Key saved to $($cfg.backupPath).")
            } else {
               Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
               $result.details.Add("Enabled BitLocker (New Recovery Protector added).")
            }
        } else {
            $result.details.Add("Audit: BitLocker is DISABLED (Critical Risk).")
        }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Enabled" }).Count -gt 0

    if ($Mode -eq 'Audit') {
      if ($anyIssues) { $result.outcome = 'Non-Compliant' } elseif (-not $result.outcome) { $result.outcome = 'Compliant' }
    } else {
      if ($anyFixes) { $result.outcome = 'Applied' } elseif (-not $result.outcome) { $result.outcome = 'Already Compliant' }
    }

  } catch {
    $result.outcome = 'Failed'
    $result.details.Add("Error: $($_.Exception.Message)")
  }

  return $result
}

Export-ModuleMember -Function Invoke-BitLocker