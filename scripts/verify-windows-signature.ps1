# Checks the Authenticode signature of Windows programs and installers, on
# Windows.
#
#   pwsh scripts/verify-windows-signature.ps1 -Mode <mode> [-Subject <text>] FILE...
#
# -Mode follows WINDOWS_SIGNING:
#   off               every file must be unsigned, so an unsigned build is
#                     never taken for a signed one, or the other way round.
#   artifact-signing  every file must carry a signature Windows trusts, by the
#                     signer -Subject names (the certificate's subject must
#                     contain that text), with a timestamp, and not from a
#                     test profile, whose signatures end with the certificate.
#   test              every file must carry a signature by the throwaway
#                     certificate, with a timestamp. Windows does not trust
#                     that certificate, which is expected.
# It prints one line per file and ends with an error if any file fails.
param(
    [Parameter(Mandatory = $true)][ValidateSet('off', 'artifact-signing', 'test')][string]$Mode,
    [string]$Subject = '',
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Files
)
$ErrorActionPreference = 'Stop'
$lifetimeSigning = '1.3.6.1.4.1.311.10.3.13'
$testSubject = 'CN=Kontext test signing (not for release)'
if ($Mode -eq 'artifact-signing' -and -not $Subject) { Write-Error 'artifact-signing needs -Subject, the signer the files must name'; exit 1 }

$failed = 0
foreach ($file in $Files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { "FAIL  $file`: not a file"; $failed++; continue }
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    $signer = $signature.SignerCertificate
    $problems = @()
    switch ($Mode) {
        'off' {
            if ($signer) { $problems += "is signed by '$($signer.Subject)', but signing is off" }
        }
        default {
            if (-not $signer) { $problems += 'is not signed' }
            else {
                if (-not $signature.TimeStamperCertificate) { $problems += 'has no timestamp' }
                $usages = @($signer.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
                if ($Mode -eq 'artifact-signing') {
                    if ($signature.Status -ne 'Valid') { $problems += "status is $($signature.Status): $($signature.StatusMessage)" }
                    if (-not $signer.Subject.Contains($Subject)) { $problems += "signer is '$($signer.Subject)', expected one naming '$Subject'" }
                    if ($usages -contains $lifetimeSigning) { $problems += 'is signed with a test profile (lifetime signing), which ends with its certificate' }
                } else {
                    if ($signer.Subject -ne $testSubject) { $problems += "signer is '$($signer.Subject)', expected the throwaway certificate" }
                    if ($signature.Status -eq 'HashMismatch') { $problems += 'the file does not match its signature' }
                }
            }
        }
    }
    if ($problems.Count) { $failed++; "FAIL  $file`: $($problems -join '; ')" }
    elseif ($Mode -eq 'off') { "ok    $file`: unsigned, as signing is off" }
    else { "ok    $file`: signed by '$($signer.Subject)', timestamp by '$($signature.TimeStamperCertificate.Subject)', status $($signature.Status)" }
}
if ($failed) { Write-Error "$failed of $($Files.Count) files failed the signature check ($Mode)"; exit 1 }
