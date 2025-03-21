# 👺 MS Sentinel

<details>

<summary>Security Event Log Cleared </summary>

```kusto
// MITRE T1070 Indicator Removal on the host

let timeframe =1d;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 1102 and EventSourceName == "Microsoft-Windows-Eventlog"
| sumarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), EventCount = count() by computer, Account, EventID, Activity
```

</details>

<details>

<summary>Mass Deletion from Azure </summary>

```kusto
// MITRE : T1485

let starttym = 10d;
let endtym = 1d;
let tymframe = 1h;
let TotalEventsThreshold = 20;
let TimeSeriesData = 
AzureActivity
| where TimeGenerated between (startofday(ago(starttime)) .. startofday(ago(endtime)))
| where OperationNameValue endswith "delete"
```

</details>

<details>

<summary>Password Reset Successful SSPR </summary>

```kusto
// Some code

set query_now = datetime(2025-03-21T03:37:32.566);
AuditLogs
| where operationName contains "self-service password reset flow activity" and ResultDescription contains "user successfully reset password"
| project InitiatedBy.user.ipAddress
```

</details>

<details>

<summary>Account Exempt from Conditional Access </summary>

```kusto
// Some code

SigninLogs
| where ConditionalAccessStatus != "success"
| where AppDisplayName contains "azure" 
     and AuthenticationContextClassReferences  !contains "previouslySatisfied"
     and isontempty(AlternatesSignInName)
     and crossTenantAccessType != "b2bcollaboration" and CrossTenantAccessType != "passthrough"
     
| project AlternatesSignInName
| where status !contains "50140" and AuthenticationDetails contains "success"
| distinct AlternateSignInName, userType, crossTenantAccessType, AppDisplayName
  

```

</details>

<details>

<summary>Login to Break The Glass Rule </summary>

```kusto
// Some code

SigninLogs
| where userPrincipalName contains "az-ind-breakglass-gp-1" or userPrincipalName contains "az-in-breakglass-gp-2"
| project Identity, userDisplayName, Location, LocationDetails, IPAddress, ClientAppUsed, ConditionalAccessStatus, DeviceDetail, RiskState
```

</details>

<details>

<summary>App Gateway WebApplication Firewall Path Traversal Attack </summary>

```kusto
// Some code

let Threshold = 1; 
AzureDiagnostics 
| where ResourceProvider == "Microsoft.Network" and Category == "ApplicationGatewayFirewallLog"
| where Message has "Path Traversal Attack"
| project 
   transactionId_g,
   hostname_s,
   requesUrl_s,
   TimeGenerated,
   clientIp_s,
   Message,
   details_message_s,
   details_data_s
| join kind = inner(
   AzureDiagnostics
   | where ResourceProvider == "Microsoft.Network" and Category == "ApplicationGatewayFirewallLog"
   | where action_s == "Allowed")
   on transactionId_g
| extend uri = strcat(hostname_s, requesturi_s)
| summarize
  StartTime = min(TimeGenerated),
  EndTime = max(TimeGenerated),
  TransactionID = make_set(trabsactionId_g, 100),
  Message = make_set(Message, 100),
  Detail_Message = make_set(details_message_s,100),
  Detail_Data = make_set(details_data_s, 100),
  Total_TransactionId = dcount(transactionId_g)
  by clientIp_s, uri, action_s
| where Total_TransactionId >= Threshold
| join kind=leftanti _getWatchlist("Whitelist_IP") on $left.clientIp_s == $right.IP
```

</details>

