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

<summary>Identify strings in process command lines which match Base64 encoding format,<br>extract the string to a column called Base64, and decode it in a column called<br>Decoded String.</summary>

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

<details>

<summary>Pull SHA256 out of text file and look for Email attachments that matches the SHA256</summary>

```kusto
// KQL

let abuse_sha256 = 
(externaldata(sha256_hash: string )
[@"https://bazaar.abuse.ch/export/txt/sha2
56/recent/"]
with (format="txt"))
| where sha256_hash !startswith "#"
| project sha256_hash;
abuse_sha256
| join (EmailAttachmentInfo 
| where Timestamp > ago(1d) 
) on $left.sha256_hash == $right.SHA256
| project Timestamp,SenderFromAddress 
,RecipientEmailAddress,FileName,FileType,S
HA256, 
MalwareFilterVerdict,MalwareDetectionMethod
```

</details>

<details>

<summary>Finds PowerShell execution events that could involve a download</summary>

```kusto
// KQL 

union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any("WebClient",
"DownloadFile",
"DownloadData",
"DownloadString",
"WebRequest",
"Shellcode",
"http",
"https")
| project Timestamp, DeviceName, InitiatingProcessFileName, 
InitiatingProcessCommandLine, 
FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType
| top 100 by Timestamp 
```

</details>

<details>

<summary>Identity + Endpoint: Lookup processes that performed LDAP auth. with clear text passwords</summary>

```kusto
// KQL

IdentityLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "LDAP cleartext" and 
isnotempty(AccountName)
| project LogonTime = Timestamp, 
DeviceName, AccountName, Application, 
LogonType
| join kind=inner (
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| extend DeviceName = 
toupper(trim(@"\..*$",DeviceName))
| where RemotePort == "389"
| project NetworkConnectionTime = 
Timestamp, DeviceName, AccountName = 
InitiatingProcessAccountName, 
InitiatingProcessFileName, 
InitiatingProcessCommandLine 
) on DeviceName, AccountName
| where LogonTime - NetworkConnectionTime 
between (-2m .. 2m)
| project Application, LogonType, 
LogonTime, DeviceName, AccountName, 
InitiatingProcessFileName, 
InitiatingProcessCommandLine
```

</details>

<details>

<summary>Lookup for emails coming into the organization from an external source that was targeted to more than 50 distinct corporate users</summary>

```kusto
// KQL

EmailEvents
| where SenderFromDomain != 
"corporatedomain.com"
| summarize dcount(RecipientEmailAddress) 
by SenderFromAddress, NetworkMessageId, 
AttachmentCount, SendTime = Timestamp
| where dcount_RecipientEmailAddress > 50


```

</details>

<details>

<summary>Lookup for all emails within last 7 days where the malware verdict was Malware</summary>

```kusto
// KQL 

EmailEvents
| where Timestamp > ago(7d)
| where MalwareFilterVerdict == "Malware"
| project Timestamp, 
SenderMailFromAddress, 
RecipientEmailAddress, 
MalwareDetectionMethod, DeliveryAction 
```

</details>

