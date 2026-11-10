# Deploying LogPulse to Azure

Total time: about 30–45 minutes, most of it waiting. Cost: a few cents (well within free student credit).

## What gets created

| Resource | Purpose | Pricing |
|---|---|---|
| Storage account + `raw-logs` container | CI pipelines upload raw logs here | pennies |
| Event Grid system topic + subscription | Pushes "blob created" events to the function | first 100k events/month free |
| Function App (Flex Consumption, Python 3.12) | Parses logs, serves the API and dashboard | free grant covers a demo |
| Cosmos DB (serverless) `logpulse/reports` | Stores structured reports | pay per request, cents |
| Application Insights + Log Analytics | Function logs, failures, metrics | free tier covers a demo |
| User-assigned managed identity | Lets the function reach Storage and Cosmos **without any keys or passwords** | free |

All of it lives in one resource group (`rg-logpulse`), so deleting that group removes everything.

---

## Step 1: Create the Azure account (you do this)

1. Go to **https://azure.microsoft.com/free/students** and click **Start free**.
2. Sign in with your **university email** and verify your student status. You get **$100 credit, no credit card required**, valid for 12 months.
   - If your university isn't eligible, use the normal free account at https://azure.microsoft.com/free instead. That one needs a card for identity checks; you get $200 credit for 30 days and aren't charged unless you upgrade.
3. When it's done, you should see the **Azure for Students** subscription at https://portal.azure.com → *Subscriptions*.

## Step 2: Install the Azure CLI (one time)

In PowerShell:

```powershell
winget install -e --id Microsoft.AzureCLI
```

**Close and reopen** the terminal, then check it works:

```powershell
az version
```

You do **not** need Azure Functions Core Tools or Azurite. The deploy script uses the CLI only.

## Step 3: Log in

```powershell
az login
```

A browser window opens; sign in with the same account as in Step 1. If you have more than one subscription:

```powershell
az account list -o table
az account set --subscription "Azure for Students"
```

## Step 4: Pick a region

Student subscriptions sometimes only allow certain regions, and the Flex Consumption plan isn't available everywhere. List the regions that support it:

```powershell
az functionapp list-flexconsumption-locations -o table
```

Pick one near you that's on the list. `swedencentral`, `northeurope` and `westeurope` are good choices in Europe.

## Step 5: Deploy everything (one command)

From the project folder:

```powershell
cd D:\Projects\LogPulse
.\scripts\deploy.ps1 -Location swedencentral
```

> If PowerShell says *"running scripts is disabled on this system"*, run this once and try again:
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

The script will:
1. register the Azure services your subscription needs (first time only),
2. create the resource group and every resource from `infra/main.bicep` (3–6 min),
3. package the code and deploy it to the Function App (1–3 min),
4. wait for the function to start, then connect Blob Storage → Event Grid → function.

At the end it prints your **dashboard URL**.

## Step 6: Test it end to end

**Wait 2–5 minutes after deploying first.** The script gives you permission to upload blobs, and Azure takes a few minutes to apply it. Then:

```powershell
.\scripts\upload-samples.ps1
```

This uploads the 6 sample logs to `raw-logs/<pipeline>/<build>/<file>.log`, the same way a CI pipeline would. Each upload triggers the function. Open the dashboard URL and the reports appear within seconds.

You can also upload by hand in the portal: *Storage account → Containers → raw-logs → Upload*. Under *Advanced*, set the upload folder to something like `web-app/2001`.

## Step 7: Collect evidence for your submission

Take these screenshots:

- [ ] **Resource group** overview showing every resource
- [ ] **Storage → raw-logs** container with the uploaded logs
- [ ] **Event Grid system topic → Event subscriptions** showing `raw-logs-to-logpulse`, plus its *Metrics* tab (delivered events)
- [ ] **Function App → ingest_log → Invocations** (or *Monitor*) showing successful runs and the log line `Stored report … status=failed`
- [ ] **Cosmos DB → Data Explorer → logpulse → reports → Items**: open a report document
- [ ] **Cosmos DB Data Explorer query**, e.g.
      `SELECT c.pipeline, c.build_id, c.status, c.tests FROM c WHERE c.status = 'failed'`
- [ ] **Dashboard**: builds list, a report detail, search results for `CVE`
- [ ] **Application Insights → Transaction search / Logs** showing function executions
- [ ] Optional: a 2–3 minute screen recording: upload a log, then show it on the dashboard

## Step 8: When you're finished (after grading)

```powershell
.\scripts\teardown.ps1
```

This deletes the whole resource group so nothing keeps using your credit.

---

## Redeploying after code changes

```powershell
.\scripts\deploy.ps1 -SkipInfra
```

## Calling the protected `/api/analyze` endpoint

It needs a function key:

```powershell
az functionapp keys list -g rg-logpulse -n <function-app-name> --query functionKeys.default -o tsv
```

Paste it into the **Function key** box in the dashboard's *Upload log* dialog, or add `?code=<key>` to the URL.

## Troubleshooting

| Problem | Fix |
|---|---|
| `RequestDisallowedByPolicy` / `RequestDisallowedByAzure` / "location is not allowed" | Your student subscription restricts regions. Delete the group (`az group delete -n rg-logpulse --yes`) and re-run with another `-Location`. |
| Cosmos DB: "high demand in this region" / `ServiceUnavailable` | Same fix: try another region. |
| Upload says `AuthorizationPermissionMismatch` | The permission hasn't applied yet. Wait 5 minutes and retry. |
| Dashboard loads but shows no builds | Check *Function App → Log stream* while uploading. If nothing appears, re-run `.\scripts\deploy.ps1 -SkipInfra` to recreate the Event Grid subscription. |
| `The blobs_extension key did not appear` | Open *Function App → Overview* and confirm it's running and shows 3 functions, then re-run with `-SkipInfra`. |
| Errors mentioning `Cosmos` / `403` in the function logs | The Cosmos permission for the managed identity can take a few minutes to apply. Upload the log again after 5 minutes. |
