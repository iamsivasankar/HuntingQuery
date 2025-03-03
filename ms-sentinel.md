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

