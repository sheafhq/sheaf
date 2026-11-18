<#
.SYNOPSIS
  Deploy the Sheaf Worker using the DPAPI-stored Cloudflare token
  (cf-token.ps1). For trusted local agents and humans.

.DESCRIPTION
  Decrypts the token in memory, passes it into WSL as CLOUDFLARE_API_TOKEN
  (WSLENV) and runs deploy.sh in the given WSL checkout. The token is never
  printed or written in plain text. Windows ARM64 can't run wrangler, which
  is why the deploy runs inside WSL.

.EXAMPLE
  deploy.ps1 -Mode check                               # who am I deploying as?
  deploy.ps1 -Mode dry-run                             # build only
  deploy.ps1 -Mode deploy -WslRepo ~/deploy-staging/sheaf
#>
param(
  [ValidateSet('check', 'dry-run', 'deploy', 'd1-list', 'd1-apply')][string]$Mode = 'check',
  [string]$WslRepo = '~/deploy-staging/sheaf'
)
$ErrorActionPreference = 'Stop'
$blob = Join-Path $env:APPDATA 'sheaf\cloudflare-api-token.dpapi'
if (-not (Test-Path $blob)) { Write-Output 'NO_STORED_TOKEN: run scripts\deploy\cf-token.ps1 -Save (pops up a dialog) first.'; exit 5 }

$secure = (Get-Content $blob -Raw).Trim() | ConvertTo-SecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
  $env:CLOUDFLARE_API_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  $env:WSLENV = 'CLOUDFLARE_API_TOKEN'
  # Single-quoted bash with no embedded double quotes (PowerShell 5.1 quoting).
  & wsl.exe -e bash -lc "bash $WslRepo/scripts/deploy/deploy.sh $Mode"
  $code = $LASTEXITCODE
}
finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  Remove-Item Env:\CLOUDFLARE_API_TOKEN -ErrorAction SilentlyContinue
}
if ($code -eq 4) { Write-Output 'The stored Cloudflare token was rejected. Run cf-token.ps1 -Save with a valid one.' }
exit $code
