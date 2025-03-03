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

