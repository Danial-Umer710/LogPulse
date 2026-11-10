<#
.SYNOPSIS
  Delete every LogPulse Azure resource (the whole resource group) so it costs nothing.
#>
param([string]$ResourceGroup = "rg-logpulse")

$answer = Read-Host "Delete resource group '$ResourceGroup' and EVERYTHING in it? Type the name to confirm"
if ($answer -ne $ResourceGroup) { Write-Host "Cancelled."; exit 1 }
az group delete --name $ResourceGroup --yes --no-wait
Write-Host "Deletion started. It finishes in the background in a few minutes."
