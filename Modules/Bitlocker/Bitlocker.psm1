<#
  BitLocker.psm1 - SecurityFramework
  Implements Thesis Section 3.2.7: Data Protection (BitLocker)
  - Checks for TPM availability
  - Enables BitLocker on C: Drive (XTS-AES 256)
  - Backs up Recovery Key to a local secure folder
  - Handles unsupported hardware gracefully
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
    $result.outcome = 'Failed'
    $result.details.Add("Error: 'bitlocker' section missing in Config.json")
    return $result
  }

  try {
    # 1. Check Hardware Support (TPM)
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    $tpmReady = ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady)
    
    if (-not $tpmReady) {
        $result.outcome = 'Skipped'
        $result.details.Add("Skipped: TPM chip not found or not ready. BitLocker cannot be automated safely.")
        return $result
    }

    # 2. Check BitLocker Status on C:
    $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    if (-not $vol) {
        $result.outcome = 'Failed'
        $result.details.Add("Error: Could not retrieve BitLocker status for C: drive.")
        return $result
    }

    # Check Encryption Status
    # ProtectionStatus: 0 = Off, 1 = On
    if ($vol.ProtectionStatus -eq 1) {
        # Verify Encryption Method
        if ($vol.EncryptionMethod -eq $cfg.encryptionMethod) {
             $result.details.Add("BitLocker is active and compliant ($($vol.EncryptionMethod)).")
        } else {
             $result.details.Add("Audit: BitLocker is active but uses $($vol.EncryptionMethod) (Expected $($cfg.encryptionMethod)).")
             # Note: We do not auto-change encryption method as it requires decrypt/re-encrypt (dangerous for script)
        }
    } else {
        # BitLocker is OFF
        if ($Mode -eq 'Enforce' -and $cfg.enableBitLocker) {
            # Ensure Backup Directory Exists
            if (-not (Test-Path $cfg.backupPath)) {
                New-Item -ItemType Directory -Force -Path $cfg.backupPath | Out-Null
            }

            # Enable BitLocker
            # -UsedSpaceOnly is faster for new deployments
            # -SkipHardwareTest prevents hanging on reboot check (optional, but good for automation)
            Enable-BitLocker -MountPoint "C:" `
               -EncryptionMethod $cfg.encryptionMethod `
               -UsedSpaceOnly `
               -TpmProtector `
               -ErrorAction Stop

            # Backup Key
            $keyId = (Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | Select-Object -ExpandProperty KeyProtectorId
            if ($keyId) {
               Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $keyId -Path $cfg.backupPath
               $result.details.Add("Enabled BitLocker. Recovery Key backed up to $($cfg.backupPath).")
            } else {
               # Try to add a recovery password if one doesn't exist
               Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
               $result.details.Add("Enabled BitLocker (Added new Recovery Protector).")
            }

        } else {
            $result.details.Add("Audit: BitLocker is DISABLED (Critical Risk).")
        }
    }

    # Determine Outcome
    $anyIssues = ($result.details | Where-Object { $_ -match "Audit: " }).Count -gt 0
    $anyFixes  = ($result.details | Where-Object { $_ -match "Enabled" }).Count -gt 0

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

Export-ModuleMember -Function Invoke-BitLocker