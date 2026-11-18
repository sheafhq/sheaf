<#
.SYNOPSIS
  Agent Economy in a Box: run the Sheaf end-to-end simulation from Windows.

.DESCRIPTION
  Thin launcher around run-sim.ts (the real orchestrator, cross-platform).

  Execution mode is picked automatically:
    * WSL    when the repo lives on the WSL filesystem (\\wsl$ / \\wsl.localhost),
             or on Windows ARM64, where workerd (wrangler dev's runtime) has
             no native build.
    * Native on Windows x64, using node + anvil.exe from PATH.
  Force one with -Wsl or -Native.

  Works on Windows PowerShell 5.1 and PowerShell 7+.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File \\wsl.localhost\Ubuntu\home\you\sheaf\simulation\run-sim.ps1

.EXAMPLE
  .\simulation\run-sim.ps1 -Agent mock -KeepState
#>
[CmdletBinding()]
param(
  [ValidateSet('auto', 'mock', 'ollama')]
  [string]$Agent = 'auto',
  [int]$AnvilPort = 18545,
  [int]$WranglerPort = 18787,
  [switch]$KeepState,
  [switch]$Wsl,
  [switch]$Native,
  [string]$Distro = ''
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$SimDir = $PSScriptRoot
$simArgs = @('--agent', $Agent, '--anvil-port', "$AnvilPort", '--wrangler-port', "$WranglerPort")
if ($KeepState) { $simArgs += '--keep-state' }

# --- choose mode -------------------------------------------------------------
$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
$onWslFs = $SimDir -match '^(\\\\|//)(wsl\$|wsl\.localhost)[\\/]'

if ($Wsl -and $Native) { throw 'Use either -Wsl or -Native, not both.' }
if ($Wsl) { $mode = 'wsl' }
elseif ($Native) { $mode = 'native' }
elseif ($onWslFs) { $mode = 'wsl' }
elseif ($arch -eq 'ARM64') { $mode = 'wsl' }
else { $mode = 'native' }

Write-Host "Agent Economy in a Box: launching in $mode mode (arch $arch)" -ForegroundColor Cyan

# --- WSL ---------------------------------------------------------------------
if ($mode -eq 'wsl') {
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'wsl.exe not found. Install WSL (wsl --install) or run with -Native on Windows x64.'
  }
  $wslBase = @()
  if ($Distro) { $wslBase = @('-d', $Distro) }

  # Translate this script's directory into a Linux path.
  $linuxDir = (& wsl.exe @wslBase -e wslpath -a ($SimDir -replace '\\', '/')) | Select-Object -First 1
  if ($LASTEXITCODE -ne 0 -or -not $linuxDir) { throw "wslpath could not translate $SimDir" }
  $linuxDir = $linuxDir.Trim()
  if ($linuxDir -like '/mnt/*') {
    Write-Warning 'Repo is on the Windows filesystem; node_modules must be installed from inside WSL (linux workerd).'
  }

  # NOTE: no double quotes inside this script. Windows PowerShell 5.1 does
  # not escape embedded " when passing arguments to native executables.
  # Inside WSL the POSIX launcher does the rest (deps check, workspace
  # install, run). ~/.local/node/bin covers a user-local Node install.
  $argStr = ($simArgs | ForEach-Object { "'$_'" }) -join ' '
  $bash = @(
    'export PATH=$HOME/.local/node22/bin:$HOME/.local/node/bin:$PATH',
    "exec bash '$linuxDir/run-sim.sh' $argStr"
  ) -join '; '

  & wsl.exe @wslBase -e bash -lc $bash
  exit $LASTEXITCODE
}

# --- native Windows (x64) ------------------------------------------------------
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw 'node not found on PATH. Install Node.js 22.12+.'
}
if (-not (Get-Command anvil -ErrorAction SilentlyContinue) -and -not $env:ANVIL_BIN) {
  throw 'anvil not found on PATH. Install Foundry for Windows (https://book.getfoundry.sh) or set $env:ANVIL_BIN.'
}

$RepoRoot = Split-Path -Parent $SimDir
Push-Location $RepoRoot
try {
  # The repo root provides wrangler; the simulation has its own dependencies
  # (the published @sheafhq/mcp-recorder@0.3.0 firewall, @sheafhq/verify, tsx).
  if (-not (Test-Path (Join-Path $RepoRoot 'node_modules\wrangler'))) {
    Write-Host 'installing repo dependencies (npm install)...'
    npm install --no-fund --no-audit
    if ($LASTEXITCODE -ne 0) { throw 'npm install (repo root) failed' }
  }
  $need = @('simulation\node_modules\@sheafhq\mcp-recorder', 'simulation\node_modules\tsx') |
    Where-Object { -not (Test-Path (Join-Path $RepoRoot $_)) }
  if ($need) {
    Write-Host 'installing simulation dependencies (npm install --prefix simulation)...'
    npm install --prefix simulation --no-fund --no-audit
    if ($LASTEXITCODE -ne 0) { throw 'npm install (simulation) failed' }
  }
  Push-Location (Join-Path $RepoRoot 'simulation')
  try { & node --import tsx run-sim.ts @simArgs; $code = $LASTEXITCODE } finally { Pop-Location }
}
finally {
  Pop-Location
}
exit $code
