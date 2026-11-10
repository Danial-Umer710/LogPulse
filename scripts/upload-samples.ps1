<#
.SYNOPSIS
  Upload the sample logs to the raw-logs container, like a CI pipeline would.
  Each upload fires the Event Grid blob trigger; reports appear on the
  dashboard a few seconds later.
#>
param([string]$ResourceGroup = "rg-logpulse")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$outputs = az deployment group show --resource-group $ResourceGroup --name logpulse --query properties.outputs -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Run ./scripts/deploy.ps1 first." }
$storage = $outputs.storageAccountName.value

# samples/<platform>/<pipeline>/<build>/<file>.log  ->  raw-logs/<pipeline>/<build>/<file>.log
Get-ChildItem -Path (Join-Path $root "samples") -Recurse -File | ForEach-Object {
    $parts = $_.FullName.Substring((Join-Path $root "samples").Length + 1) -split '[\\/]'
    $blob = ($parts[1..($parts.Length - 1)]) -join '/'
    Write-Host "uploading $blob"
    az storage blob upload --auth-mode login --account-name $storage --container-name raw-logs `
        --name $blob --file $_.FullName --overwrite -o none
    if ($LASTEXITCODE -ne 0) {
        throw "Upload failed. If this is a permissions error, wait 2-5 minutes after deploying (role assignments take time to apply) and try again."
    }
}
Write-Host "`nUploaded. Open the dashboard: $($outputs.functionAppUrl.value)/api/dashboard" -ForegroundColor Green
