# How do I use this?
Go to https://dataexplorer.azure.com, then create a free ADX cluster account and a new database. Copy the [init.kql](https://github.com/ksyeung/DetLabs/blob/main/fsquirt_Living_off_the_Land/init.kql) data in this folder and paste it into the ADX web UI query window. This will create the required tables, ASIM parsers, helper functions, and start ingestion of the telemetry (WindowsEvent[...].parquet, etc).

# fsquirt.exe Living off the Land

The telemetry was collected during execution of `fsquirt.exe`, which runs the GUI for the Bluetooth File Transfer Wizard. I used mhaskar's proof of concept located [here](https://github.com/mhaskar/FsquirtCPLPoC). See similar Windows Living off the Land techniques [here](https://lolbas-project.github.io).

In this telemetry, the attacker brings their own `fsquirt.exe` with `bthprops.cpl`. However, this is not strictly necessary: they can set the permanent working dir to the location of `bthprops.cpl`, then launch `C:\Windows\System32\fsquirt.exe` to effectively sideload it.

Here is a detection for this technique:

```
// Potential Bthprops.Cpl Sideloading
// Sigma ID: 81909c5c-7cc6-4e0b-aea7-e1d4ab7abf0f
// MITRE: T1574.002 (DLL Side-Loading)
// Ref: https://github.com/mhaskar/FsquirtCPLPoC
// Ref: https://securelist.com/sidewinder-apt/114089/
// Credit: https://github.com/swachchhanda000/sigma/blob/137271f9aa1e846aca84076f17c8525e6f4edf20/rules/windows/image_load/image_load_side_load_bthprops_cpl.yml
DeviceImageLoadEvents
| where FileName endswith "bthprops.cpl"
    // Exclude legitimate system paths
    and not (FolderPath startswith @"C:\Windows\System32\"
             or FolderPath startswith @"C:\Windows\SysWOW64\"
             or FolderPath startswith @"C:\Windows\WinSxS\")
| project
    Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

Output:

| Timestamp | DeviceName | FileName | FolderPath | SHA256 | InitiatingProcessFileName | InitiatingProcessFolderPath | InitiatingProcessCommandLine | InitiatingProcessAccountName |
|---|---|---|---|---|---|---|---|---|
| 2026-02-06T23:50:26.491Z | jd-win11-22h2-1.ludus.domain | bthprops.cpl | C:\Users\domainuser\Downloads\bthprops.cpl | dbd8c27bc7b0390c2c676179cd516b554ef7101dff698762e1fd66d258c93439 | fsquirt.exe | c:\users\domainuser\downloads\fsquirt.exe | "fsquirt.exe" | domainuser |
