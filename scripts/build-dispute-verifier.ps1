# Build the single-file browser verifier on Windows.
# esbuild's JS API spawns a service process; this direct CLI invocation avoids
# that and is the path used for the committed artifact in this environment.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "win32-arm64" } else { "win32-x64" }
$esbuild = Join-Path $root "node_modules\@esbuild\$arch\esbuild.exe"
if (-not (Test-Path $esbuild)) {
  throw "esbuild binary not found at $esbuild"
}
New-Item -ItemType Directory -Force -Path (Join-Path $root ".test-dist") | Out-Null
& $esbuild scripts/dispute-verifier-entry.ts `
  --bundle `
  --format=iife `
  --platform=browser `
  --target=es2022 `
  --minify `
  --legal-comments=none `
  --outfile=.test-dist/dispute-verifier.js
if ($LASTEXITCODE -ne 0) { throw "esbuild failed with $LASTEXITCODE" }
node scripts/inline-dispute-verifier.mjs
