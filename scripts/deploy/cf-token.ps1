<#
.SYNOPSIS
  Manage the Cloudflare API token used to deploy the Sheaf Worker, stored
  encrypted with Windows DPAPI (CurrentUser scope). Never printed.

    cf-token.ps1 -Save     pop up a masked dialog and store the token
    cf-token.ps1 -Status   is a token stored?
    cf-token.ps1 -Clear    delete it (do this when you roll/revoke the token)

  Store: %APPDATA%\sheaf\cloudflare-api-token.dpapi (+ .meta.json, no secret)
  Used only by scripts\deploy\deploy.ps1.
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Save')][switch]$Save,
  [Parameter(ParameterSetName = 'Status')][switch]$Status,
  [Parameter(ParameterSetName = 'Clear')][switch]$Clear
)
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:APPDATA 'sheaf'
$blob = Join-Path $dir 'cloudflare-api-token.dpapi'
$meta = Join-Path $dir 'cloudflare-api-token.meta.json'

if ($Clear) { Remove-Item $blob, $meta -ErrorAction SilentlyContinue; Write-Output 'cleared: no Cloudflare token stored'; exit 0 }

if ($Save) {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'Cloudflare API token: deploy Sheaf Worker'
  $form.Size = New-Object System.Drawing.Size(480, 200)
  $form.StartPosition = 'CenterScreen'; $form.TopMost = $true
  $form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; $form.MinimizeBox = $false
  $label = New-Object System.Windows.Forms.Label
  $label.Text = 'Paste the Cloudflare API token (Edit Cloudflare Workers, sheafhq.io). It will be stored encrypted (Windows DPAPI, your account only).'
  $label.Location = New-Object System.Drawing.Point(12, 12); $label.Size = New-Object System.Drawing.Size(450, 50)
  $form.Controls.Add($label)
  $box = New-Object System.Windows.Forms.TextBox
  $box.Location = New-Object System.Drawing.Point(12, 68); $box.Size = New-Object System.Drawing.Size(440, 24)
  $box.UseSystemPasswordChar = $true
  $form.Controls.Add($box)
  $ok = New-Object System.Windows.Forms.Button
  $ok.Text = 'Save'; $ok.Location = New-Object System.Drawing.Point(296, 112)
  $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.AcceptButton = $ok; $form.Controls.Add($ok)
  $cancel = New-Object System.Windows.Forms.Button
  $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(377, 112)
  $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $form.CancelButton = $cancel; $form.Controls.Add($cancel)
  $form.Add_Shown({ $form.Activate(); $box.Focus() })
  $result = $form.ShowDialog(); $token = $box.Text.Trim(); $form.Dispose()
  if ($result -ne [System.Windows.Forms.DialogResult]::OK -or -not $token) { Write-Output 'cancelled: nothing stored'; exit 1 }
  New-Item -ItemType Directory -Force $dir | Out-Null
  (ConvertTo-SecureString $token -AsPlainText -Force | ConvertFrom-SecureString) | Set-Content -Path $blob -Encoding ascii
  $token = $null
  @{ purpose = 'wrangler deploy of sheaf-recorder (api.sheafhq.io, sheafhq.io)'; saved_at = (Get-Date).ToUniversalTime().ToString('o') } |
    ConvertTo-Json | Set-Content -Path $meta -Encoding utf8
  Write-Output "stored: encrypted Cloudflare token at $blob"
  exit 0
}

if (Test-Path $blob) { Write-Output 'status: Cloudflare token stored'; exit 0 }
Write-Output 'status: no Cloudflare token stored (run cf-token.ps1 -Save)'; exit 1
