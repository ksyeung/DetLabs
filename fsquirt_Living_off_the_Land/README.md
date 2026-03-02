# How do I use this?
Go to https://dataexplorer.azure.com, then create a free ADX cluster account and a new database. Copy the [init.kql](https://github.com/ksyeung/DetLabs/blob/main/fsquirt_Living_off_the_Land/init.kql) data in this folder and paste it into the ADX web UI query window. This will create the required tables, ASIM parsers, helper functions, and start ingestion of the telemetry (WindowsEvent[...].parquet, etc).

# fsquirt.exe Living off the Land

The telemetry was collected during execution of `fsquirt.exe`, which runs the GUI for the Bluetooth File Transfer Wizard. I used mhaskar's proof of concept located [here](https://github.com/mhaskar/FsquirtCPLPoC). See similar Windows Living off the Land techniques [here](https://lolbas-project.github.io).

The attacker transfers `fsquirt.exe` and `bthprops.cpl` to the machine over RDP, then executes `fsquirt.exe bthprops.cpl` to sideload the malicious CPL. Bringing `fsquirt.exe` is not strictly required: running `fsquirt bthprops.cpl` causes the system's `C:\Windows\System32\fsquirt.exe` to load `bthprops.cpl` directly.

Here is a detection for this technique:

```kql
// Potential Bthprops.Cpl Sideloading
// Sigma ID: 81909c5c-7cc6-4e0b-aea7-e1d4ab7abf0f
// MITRE: T1574.002 (DLL Side-Loading)
// Ref: https://github.com/mhaskar/FsquirtCPLPoC
// Ref: https://securelist.com/sidewinder-apt/114089/
// Credit: https://github.com/swachchhanda000/sigma/blob/137271f9aa1e846aca84076f17c8525e6f4edf20/rules/windows/image_load/image_load_side_load_bthprops_cpl.yml
DeviceImageLoadEvents
| where FileName endswith "bthprops.cpl"
    and not (FolderPath startswith "C:\\Windows\\System32\\"
          or FolderPath startswith "C:\\Windows\\SysWOW64\\"
          or FolderPath startswith "C:\\Windows\\WinSxS\\")
| project
    Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

Output:

| Timestamp | DeviceName | FileName | FolderPath | SHA256 | InitiatingProcessFileName | InitiatingProcessFolderPath | InitiatingProcessCommandLine | InitiatingProcessAccountName |
|---|---|---|---|---|---|---|---|---|
| 2026-02-05T23:36:34.250Z | jd-win11-22h2-1.ludus.domain | bthprops.cpl | C:\Users\domainuser\Pictures\bthprops.cpl | dbd8c27bc7b0390c2c676179cd516b554ef7101dff698762e1fd66d258c93439 | fsquirt.exe | c:\users\domainuser\pictures\fsquirt.exe | "fsquirt.exe" | domainuser |

<br>

Or more generally, `.cpl` file staging outside system dirs as a precursor to sideloading:
```kql
// .cpl files dropped outside system directories — potential sideloading payload staging
DeviceFileEvents
| where FileName endswith ".cpl"
    and ActionType == "FileCreated"
    and not (FolderPath startswith "C:\\Windows"
          or FolderPath startswith "C:\\Program Files\\"
          or FolderPath startswith "C:\\Program Files (x86)\\")
| project
    Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

Output:

| Timestamp | DeviceName | ProcessCommandLine | FolderPath | InitiatingProcessFileName | InitiatingProcessCommandLine | AccountName |
|---|---|---|---|---|---|---|
| 2026-02-05T23:36:34.748Z | jd-win11-22h2-1.ludus.domain | fsquirt.exe | C:\Users\domainuser\Pictures\fsquirt.exe | explorer.exe | Explorer.EXE | domainuser |
