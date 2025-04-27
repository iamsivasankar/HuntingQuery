---
icon: windows
---

# M365 Advanced Hunting Query

<details>

<summary>Find Active Directory user accounts that have been inactive for more than 30 days.</summary>

<pre class="language-kusto"><code class="lang-kusto">// KQL

<strong>IdentityLogonEvents 
</strong>| project Timestamp, AccountName, 
DeviceName, LogonType
| summarize LastLogon = max(Timestamp) 
by AccountName, LogonType, DeviceName
| where LastLogon &#x3C; ago(30d)
</code></pre>

</details>

<details>

<summary>Identifies applications which leverage a command line pattern which matches the<br>7zip and WinRAR command line executables to create or update an archive when a<br>password is specified</summary>

```kusto
// KQL

DeviceProcessEvents
| where ProcessCommandLine matches regex @"\s[aukfAUKF]\s.*\s-p" // Basic 
filter to look for launch string
| extend SplitLaunchString = split(ProcessCommandLine, ' ') // Split on the 
space
| where array_length(SplitLaunchString) >= 5 and SplitLaunchString[1] in~ 
('a','u','k','f') // look for calls to archive or update an archive specifically 
as the first argument
| mv-expand SplitLaunchString // cross apply the array
| where SplitLaunchString startswith "-p" // -p is the password switch and is 
immediately followed by a password without a space
| extend ArchivePassword = substring(SplitLaunchString, 2, 
strlen(SplitLaunchString))
| project-reorder ProcessCommandLine, ArchivePassword // Promote these fields to 
the left


```

</details>

<details>

<summary>Identify strings in process command lines which match Base64 encoding format,<br>extract the string to a column called Base64,a nd decode it in a column called<br>DecodedString.</summary>

```kusto
// KQL

DeviceProcessEvents
| extend SplitLaunchString = split(ProcessCommandLine, " ")
| mvexpand SplitLaunchString
| where SplitLaunchString matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend Base64 = tostring(SplitLaunchString)
| extend DecodedString = base64_decodestring(Base64)
| where isnotempty(DecodedString)
```

</details>

<details>

<summary>Identify which files within the last 24 hours had more then 10 data access, download or deletion activities on MCAS-protected applications.</summary>

```kusto
// KQL

AppFileEvents
| where Timestamp > ago(1d)
| summarize count() by FolderPath, 
FileName, ActionType, 
AccountDisplayName
| where count_ > 10
```

</details>
