<#
.SYNOPSIS
  Deploy LogPulse to Azure: infrastructure, code and the Event Grid subscription.

.EXAMPLE
  ./scripts/deploy.ps1                                  # defaults: rg-logpulse in swedencentral
  ./scripts/deploy.ps1 -Location northeurope
  ./scripts/deploy.ps1 -SkipInfra                       # redeploy code only

  Run `az login` first. Safe to run again: every step is idempotent.
#>
param(
    [string]$ResourceGroup = "rg-logpulse",
    [string]$Location = "swedencentral",
    [switch]$SkipInfra
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Invoke-AzCli {
    # Run az and stop the script on failure (PowerShell 5.1 ignores native exit codes).
    $out = & az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed (exit $LASTEXITCODE)" }
    return $out
}
function Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }

Step "Checking Azure login"
$account = Invoke-AzCli account show -o json | ConvertFrom-Json
Write-Host "Subscription: $($account.name) ($($account.id))"

if (-not $SkipInfra) {
    Step "Registering resource providers (first time only, can take a minute)"
    foreach ($ns in "Microsoft.Web", "Microsoft.Storage", "Microsoft.DocumentDB", "Microsoft.EventGrid",
                    "Microsoft.Insights", "Microsoft.OperationalInsights", "Microsoft.ManagedIdentity") {
        Invoke-AzCli provider register --namespace $ns --wait | Out-Null
        Write-Host "  $ns registered"
    }

    Step "Creating resource group $ResourceGroup in $Location"
    Invoke-AzCli group create --name $ResourceGroup --location $Location -o none

    $me = (& az ad signed-in-user show --query id -o tsv 2>$null)
    if (-not $me) { Write-Warning "Could not read your user id; you will not get data access to Storage/Cosmos (uploads via portal still work)."; $me = "" }

    Step "Deploying infrastructure (Bicep). Takes 3-6 minutes, mostly Cosmos DB"
    $outputs = Invoke-AzCli deployment group create --resource-group $ResourceGroup --name logpulse `
        --template-file infra/main.bicep --parameters location=$Location principalId=$me `
        --query properties.outputs -o json | ConvertFrom-Json
} else {
    $outputs = Invoke-AzCli deployment group show --resource-group $ResourceGroup --name logpulse --query properties.outputs -o json | ConvertFrom-Json
}

$app = $outputs.functionAppName.value
$appUrl = $outputs.functionAppUrl.value
$storage = $outputs.storageAccountName.value
$topic = $outputs.systemTopicName.value

Step "Packaging code"
python scripts/package.py
if ($LASTEXITCODE -ne 0) { throw "packaging failed" }

Step "Deploying code to $app (Azure installs requirements.txt, 1-3 minutes)"
Invoke-AzCli functionapp deployment source config-zip --resource-group $ResourceGroup --name $app `
    --src dist/logpulse.zip --build-remote true --timeout 600 -o none

Step "Waiting for the function host to start"
$key = ""
for ($i = 0; $i -lt 30 -and -not $key; $i++) {
    try { Invoke-WebRequest "$appUrl/api/health" -UseBasicParsing -TimeoutSec 30 | Out-Null } catch { }
    $key = (& az functionapp keys list --resource-group $ResourceGroup --name $app --query "systemKeys.blobs_extension" -o tsv 2>$null)
    if (-not $key) { Start-Sleep -Seconds 10 }
}
if (-not $key) { throw "The blobs_extension key did not appear. Check the Function App's logs in the portal, then re-run with -SkipInfra." }

Step "Connecting Blob Storage events to the function (Event Grid subscription)"
# The webhook URL contains "&code=<key>". On Windows, az is a .cmd file and
# cmd.exe treats "&" as a command separator, which would cut the URL off. So
# send the request body as a JSON file through `az rest`: the URL never
# reaches the command line.
$endpoint = "$appUrl/runtime/webhooks/blobs?functionName=Host.Functions.ingest_log&code=$key"
$body = @{
    properties = @{
        destination = @{ endpointType = "WebHook"; properties = @{ endpointUrl = $endpoint; maxEventsPerBatch = 1 } }
        filter = @{
            includedEventTypes = @("Microsoft.Storage.BlobCreated")
            subjectBeginsWith = "/blobServices/default/containers/raw-logs/"
        }
        eventDeliverySchema = "EventGridSchema"
    }
} | ConvertTo-Json -Depth 6
$bodyFile = Join-Path $env:TEMP "logpulse-eventsub.json"
[System.IO.File]::WriteAllText($bodyFile, $body)  # UTF-8 without BOM
$subUri = "https://management.azure.com/subscriptions/$($account.id)/resourceGroups/$ResourceGroup/providers/Microsoft.EventGrid/systemTopics/$topic/eventSubscriptions/raw-logs-to-logpulse?api-version=2022-06-15"
try {
    Invoke-AzCli rest --method put --uri $subUri --body "@$bodyFile" -o none
} finally {
    Remove-Item $bodyFile -ErrorAction SilentlyContinue  # contains the function's system key
}
for ($i = 0; $i -lt 12; $i++) {
    $state = (& az rest --method get --uri $subUri --query properties.provisioningState -o tsv 2>$null)
    if ($state -in "Succeeded", "Failed") { break }
    Start-Sleep -Seconds 5
}
if ($state -ne "Succeeded") { throw "Event Grid subscription state: $state. Re-run with -SkipInfra." }
Write-Host "  Event Grid subscription: $state"

Step "Done"
Write-Host ""
Write-Host "Dashboard:   $appUrl/api/dashboard" -ForegroundColor Green
Write-Host "Health:      $appUrl/api/health"
Write-Host "Storage:     $storage  (container: raw-logs)"
Write-Host "Cosmos DB:   $($outputs.cosmosAccountName.value)  (database logpulse / container reports)"
Write-Host ""
Write-Host "Next: ./scripts/upload-samples.ps1 to upload the sample logs and watch them get processed."
