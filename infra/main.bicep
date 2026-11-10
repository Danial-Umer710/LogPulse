// LogPulse: all Azure resources, deployed into one resource group.
//
//   Storage account ── BlobCreated ──► Event Grid ──► Function App (Flex Consumption, Python)
//        raw-logs/                                        │  managed identity (no keys in config)
//                                                         ▼
//                                              Cosmos DB (serverless) logpulse/reports
//                                                         │
//                                              Application Insights (logs + metrics)
//
// The Event Grid *subscription* is created by scripts/deploy.ps1 after the code
// is deployed. It needs the function's blob-extension key, which only exists
// once the code is running.

targetScope = 'resourceGroup'

@description('Azure region for every resource.')
param location string = resourceGroup().location

@description('Short prefix for resource names.')
@maxLength(10)
param appName string = 'logpulse'

@description('Object id of the person deploying. They get data access to the log container and Cosmos DB, for uploads and Data Explorer.')
param principalId string = ''

@description('Python version for the Function App.')
@allowed(['3.11', '3.12'])
param pythonVersion string = '3.12'

var suffix = uniqueString(resourceGroup().id)
var storageName = take('st${appName}${suffix}', 24)
var functionAppName = 'func-${appName}-${suffix}'
var cosmosName = 'cosmos-${appName}-${suffix}'
var logContainerName = 'raw-logs'
var deploymentContainerName = 'app-package'
var tags = { project: 'LogPulse' }

// Built-in role definition ids
var roles = {
  storageBlobDataOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  storageBlobDataContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  storageQueueDataContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  storageTableDataContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  monitoringMetricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
}
var cosmosDataContributorRole = '00000000-0000-0000-0000-000000000002'

// ---------------------------------------------------------------------------
// Identity used by the Function App for Storage, Cosmos DB and App Insights
// ---------------------------------------------------------------------------
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${appName}-${suffix}'
  location: location
  tags: tags
}

// ---------------------------------------------------------------------------
// Storage: raw log uploads + Functions host state + deployment package
// ---------------------------------------------------------------------------
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource logContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: logContainerName
}

resource deploymentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: deploymentContainerName
}

resource appStorageRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for role in [roles.storageBlobDataOwner, roles.storageQueueDataContributor, roles.storageTableDataContributor]: {
    name: guid(storage.id, identity.id, role)
    scope: storage
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', role)
      principalId: identity.properties.principalId
      principalType: 'ServicePrincipal'
    }
  }
]

resource userStorageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(principalId)) {
  name: guid(storage.id, principalId, roles.storageBlobDataContributor)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.storageBlobDataContributor)
    principalId: principalId
    principalType: 'User'
  }
}

// ---------------------------------------------------------------------------
// Monitoring
// ---------------------------------------------------------------------------
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${appName}-${suffix}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${appName}-${suffix}'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

resource appInsightsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appInsights.id, identity.id, roles.monitoringMetricsPublisher)
  scope: appInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.monitoringMetricsPublisher)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Cosmos DB (serverless): pay per request, cents for a demo
// ---------------------------------------------------------------------------
resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: cosmosName
  location: location
  tags: tags
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    consistencyPolicy: { defaultConsistencyLevel: 'Session' }
    locations: [ { locationName: location, failoverPriority: 0, isZoneRedundant: false } ]
    capabilities: [ { name: 'EnableServerless' } ]
    minimalTlsVersion: 'Tls12'
  }
}

resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmos
  name: 'logpulse'
  properties: { resource: { id: 'logpulse' } }
}

resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: cosmosDb
  name: 'reports'
  properties: {
    resource: {
      id: 'reports'
      partitionKey: { paths: [ '/pipeline' ], kind: 'Hash' }
      indexingPolicy: {
        indexingMode: 'consistent'
        includedPaths: [ { path: '/*' } ]
        excludedPaths: [
          { path: '/findings/[]/context/*' } // large text we never filter on
          { path: '/"_etag"/?' }
        ]
      }
    }
  }
}

resource cosmosAppRole 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-05-15' = {
  parent: cosmos
  name: guid(cosmos.id, identity.id, cosmosDataContributorRole)
  properties: {
    roleDefinitionId: '${cosmos.id}/sqlRoleDefinitions/${cosmosDataContributorRole}'
    principalId: identity.properties.principalId
    scope: cosmos.id
  }
}

resource cosmosUserRole 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-05-15' = if (!empty(principalId)) {
  parent: cosmos
  name: guid(cosmos.id, principalId, cosmosDataContributorRole)
  properties: {
    roleDefinitionId: '${cosmos.id}/sqlRoleDefinitions/${cosmosDataContributorRole}'
    principalId: principalId
    scope: cosmos.id
  }
}

// ---------------------------------------------------------------------------
// Function App: Flex Consumption plan (serverless, scales to zero)
// ---------------------------------------------------------------------------
resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: 'plan-${appName}-${suffix}'
  location: location
  tags: tags
  kind: 'functionapp'
  sku: { name: 'FC1', tier: 'FlexConsumption' }
  properties: { reserved: true }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deploymentContainerName}'
          authentication: { type: 'UserAssignedIdentity', userAssignedIdentityResourceId: identity.id }
        }
      }
      scaleAndConcurrency: { maximumInstanceCount: 40, instanceMemoryMB: 2048 }
      runtime: { name: 'python', version: pythonVersion }
    }
    siteConfig: {
      minTlsVersion: '1.2'
      appSettings: [
        // Functions host storage, via managed identity (no connection string)
        { name: 'AzureWebJobsStorage__accountName', value: storage.name }
        { name: 'AzureWebJobsStorage__credential', value: 'managedidentity' }
        { name: 'AzureWebJobsStorage__clientId', value: identity.properties.clientId }
        // Monitoring
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
        { name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING', value: 'ClientId=${identity.properties.clientId};Authorization=AAD' }
        // LogPulse settings (read by logpulse/store.py)
        { name: 'LOGPULSE_STORE', value: 'cosmos' }
        { name: 'COSMOS_ENDPOINT', value: cosmos.properties.documentEndpoint }
        { name: 'COSMOS_DATABASE', value: cosmosDb.name }
        { name: 'COSMOS_CONTAINER', value: cosmosContainer.name }
        { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId } // DefaultAzureCredential picks the user-assigned identity
      ]
    }
  }
  dependsOn: [ appStorageRoles, deploymentContainer ]
}

// Event Grid topic that publishes this storage account's blob events.
// deploy.ps1 subscribes the function to it.
resource systemTopic 'Microsoft.EventGrid/systemTopics@2022-06-15' = {
  name: 'evgt-${appName}-${suffix}'
  location: location
  tags: tags
  properties: {
    source: storage.id
    topicType: 'Microsoft.Storage.StorageAccounts'
  }
}

output functionAppName string = functionApp.name
output functionAppUrl string = 'https://${functionApp.properties.defaultHostName}'
output storageAccountName string = storage.name
output logContainerName string = logContainerName
output cosmosAccountName string = cosmos.name
output cosmosEndpoint string = cosmos.properties.documentEndpoint
output systemTopicName string = systemTopic.name
output appInsightsName string = appInsights.name
