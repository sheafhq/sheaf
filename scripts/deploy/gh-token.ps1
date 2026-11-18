<#
.SYNOPSIS
  Manage the GitHub token used to push to github.com/sheafhq/sheaf, stored
  encrypted with Windows DPAPI (CurrentUser scope). Never printed.

    gh-token.ps1 -Save     pop up a masked dialog and store the token
    gh-token.ps1 -Status   is a token stored, and when does it expire?
    gh-token.ps1 -Clear    delete it (do this when you roll/revoke the token)

  Store: %APPDATA%\sheaf\github-token.dpapi (+ .meta.json, no secret)
  Used by scripts\deploy\gh-push.ps1. Needs Contents: write on sheafhq/sheaf.
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Save')][switch]$Save,
  [Parameter(ParameterSetName = 'Status')][switch]$Status,
  [Parameter(ParameterSetName = 'Clear')][switch]$Clear
)
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:APPDATA 'sheaf'
$blob = Join-Path $dir 'github-token.dpapi'
$meta = Join-Path $dir 'github-token.meta.json'

if ($Clear) { Remove-Item $blob, $meta -ErrorAction SilentlyContinue; Write-Output 'cleared: no GitHub token stored'; exit 0 }

if ($Save) {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'GitHub token: push to sheafhq/sheaf'
  $form.Size = New-Object System.Drawing.Size(480, 250)
  $form.StartPosition = 'CenterScreen'; $form.TopMost = $true
  $form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; $form.MinimizeBox = $false
  $label = New-Object System.Windows.Forms.Label
  $label.Text = 'Paste a GitHub token with Contents: write on sheafhq/sheaf. It will be stored encrypted (Windows DPAPI, your account only).'
  $label.Location = New-Object System.Drawing.Point(12, 12); $label.Size = New-Object System.Drawing.Size(450, 40)
  $form.Controls.Add($label)
  $box = New-Object System.Windows.Forms.TextBox
  $box.Location = New-Object System.Drawing.Point(12, 58); $box.Size = New-Object System.Drawing.Size(440, 24)
  $box.UseSystemPasswordChar = $true
  $form.Controls.Add($box)
  $l2 = New-Object System.Windows.Forms.Label
  $l2.Text = 'Expires on (YYYY-MM-DD, optional):'
  $l2.Location = New-Object System.Drawing.Point(12, 96); $l2.Size = New-Object System.Drawing.Size(220, 20)
  $form.Controls.Add($l2)
  $exp = New-Object System.Windows.Forms.TextBox
  $exp.Location = New-Object System.Drawing.Point(236, 93); $exp.Size = New-Object System.Drawing.Size(120, 24)
  $form.Controls.Add($exp)
  $ok = New-Object System.Windows.Forms.Button
  $ok.Text = 'Save'; $ok.Location = New-Object System.Drawing.Point(296, 160)
  $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.AcceptButton = $ok; $form.Controls.Add($ok)
  $cancel = New-Object System.Windows.Forms.Button
  $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(377, 160)
  $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $form.CancelButton = $cancel; $form.Controls.Add($cancel)
  $form.Add_Shown({ $form.Activate(); $box.Focus() })
  $result = $form.ShowDialog(); $token = $box.Text.Trim(); $expires = $exp.Text.Trim(); $form.Dispose()
  if ($result -ne [System.Windows.Forms.DialogResult]::OK -or -not $token) { Write-Output 'cancelled: nothing stored'; exit 1 }
  New-Item -ItemType Directory -Force $dir | Out-Null
  (ConvertTo-SecureString $token -AsPlainText -Force | ConvertFrom-SecureString) | Set-Content -Path $blob -Encoding ascii
  $token = $null
  $m = @{ purpose = 'git push to github.com/sheafhq/sheaf (scripts\deploy\gh-push.ps1)'; saved_at = (Get-Date).ToUniversalTime().ToString('o') }
  if ($expires -match '^\d{4}-\d{2}-\d{2}$') { $m.expires_at = $expires }
  $m | ConvertTo-Json | Set-Content -Path $meta -Encoding utf8
  Write-Output "stored: encrypted GitHub token at $blob$(if ($m.expires_at) { " (expires $($m.expires_at))" })"
  exit 0
}

if (Test-Path $blob) {
  $e = if (Test-Path $meta) { (Get-Content $meta -Raw | ConvertFrom-Json).expires_at } else { $null }
  Write-Output "status: GitHub token stored$(if ($e) { ", expires $e" })"; exit 0
}
Write-Output 'status: no GitHub token stored (run gh-token.ps1 -Save)'; exit 1
