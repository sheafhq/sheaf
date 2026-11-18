<#
.SYNOPSIS
  Push to github.com/sheafhq/sheaf with the DPAPI-stored token from
  gh-token.ps1. For trusted local agents and humans. Fast-forward only.

.DESCRIPTION
  Decrypts the token in memory and hands it to git through GIT_ASKPASS
  (gh-askpass.sh reads it from an environment variable). The token is never
  printed, never put on a command line, and never written in plain text.
  Credential helpers are disabled for the push so nothing caches it.

.EXAMPLE
  gh-push.ps1                                  # push main -> main
  gh-push.ps1 -Refspec main:main -DryRun
#>
param(
  [string]$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$Refspec = 'main:main',
  [switch]$DryRun,
  # Push with git inside WSL instead of Git for Windows. Use when Windows git
  # cannot reach GitHub (seen 2026-11-18: "getaddrinfo() thread failed to
  # start" from Git for Windows' curl while the system curl worked). The token
  # is passed in memory via WSLENV, as deploy.ps1 does.
  [switch]$ViaWsl
)
$ErrorActionPreference = 'Stop'
$blob = Join-Path $env:APPDATA 'sheaf\github-token.dpapi'
$meta = Join-Path $env:APPDATA 'sheaf\github-token.meta.json'
if (-not (Test-Path $blob)) { Write-Output 'NO_STORED_TOKEN: run scripts\deploy\gh-token.ps1 -Save (pops up a dialog) first.'; exit 5 }
if (Test-Path $meta) {
  $e = (Get-Content $meta -Raw | ConvertFrom-Json).expires_at
  if ($e -and ([datetime]$e) -lt (Get-Date)) { Write-Output "TOKEN_EXPIRED on ${e}: create a new token and run gh-token.ps1 -Save."; exit 2 }
}

$secure = (Get-Content $blob -Raw).Trim() | ConvertTo-SecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
  $env:SHEAF_GH_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  $env:GIT_ASKPASS = (Join-Path $PSScriptRoot 'gh-askpass.sh') -replace '\\', '/'
  $env:GIT_TERMINAL_PROMPT = '0'
  $ErrorActionPreference = 'Continue'   # git writes progress to stderr
  if ($ViaWsl) {
    $wslRepo = ((& wsl.exe -e wslpath -a ($Repo -replace '\\', '/')) | Select-Object -First 1).Trim()
    $wslAskpass = ((& wsl.exe -e wslpath -a ((Join-Path $PSScriptRoot 'gh-askpass.sh') -replace '\\', '/')) | Select-Object -First 1).Trim()
    $env:WSLENV = 'SHEAF_GH_TOKEN'
    $wslArgs = @('-e', 'git', '-C', $wslRepo, '-c', 'credential.helper=', '-c', "core.askPass=$wslAskpass", 'push')
    if ($DryRun) { $wslArgs += '--dry-run' }
    $wslArgs += @('origin', $Refspec)
    $out = (& wsl.exe @wslArgs 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
  } else {
    $gitArgs = @('-C', $Repo, '-c', 'credential.helper=', 'push')
    if ($DryRun) { $gitArgs += '--dry-run' }
    $gitArgs += @('origin', $Refspec)
    $out = (& git @gitArgs 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
  }
  $code = $LASTEXITCODE
  Write-Output ($out -replace [regex]::Escape($env:SHEAF_GH_TOKEN), '<redacted>')
}
finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  Remove-Item Env:\SHEAF_GH_TOKEN, Env:\GIT_ASKPASS, Env:\WSLENV -ErrorAction SilentlyContinue
}
if ($code -ne 0 -and $out -match 'Invalid username or token|Authentication failed|denied') {
  Write-Output 'The stored GitHub token was rejected. Run gh-token.ps1 -Save with a valid one.'
}
exit $code
