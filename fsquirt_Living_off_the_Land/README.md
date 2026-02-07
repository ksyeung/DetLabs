# How do I use this?
Go to https://dataexplorer.azure.com, then create a free ADX cluster account and a new database. Copy the [init.kql](https://github.com/ksyeung/DetLabs/blob/main/fsquirt_Living_off_the_Land/init.kql) data in this folder and paste it into the ADX web UI query window. This will create the required tables, ASIM parsers, helper functions, and start ingestion of the telemetry (WindowsEvent[...].parquet, etc).

# fsquirt.exe Living off the Land

The telemetry was collected during execution of `fsquirt.exe`, which runs the GUI for the Bluetooth File Transfer Wizard. I used mhaskar's proof of concept located [here](https://github.com/mhaskar/FsquirtCPLPoC). See similar Windows Living off the Land techniques [here](https://lolbas-project.github.io).

Here are some detections for this technique.


Using MDE tables:
```
// CPL Sideloading Detection
let droppedPairs =
  DeviceFileEvents
  | where ActionType == "FileCreated"                                                 
  | extend Ext = tolower(tostring(split(FileName, ".")[-1]))
  | where Ext in ("exe", "cpl")
  | extend Dir = tolower(substring(FolderPath, 0, string_size(FolderPath) - string_size(FileName) - 1))
  | summarize
	  Exes = make_set_if(tolower(FolderPath), Ext == "exe"),
	  Cpls = make_set_if(tolower(FolderPath), Ext == "cpl")
	  by Dir, DeviceName, bin(Timestamp, 5m)
  | where array_length(Exes) > 0 and array_length(Cpls) > 0;
DeviceImageLoadEvents
| where tolower(tostring(split(FileName, ".")[-1])) == "cpl"
| join kind=inner droppedPairs on DeviceName
| where set_has_element(Cpls, tolower(FolderPath))
  and set_has_element(Exes, tolower(InitiatingProcessFolderPath))
| project
  Timestamp, DeviceName, ExecutedExe = InitiatingProcessFolderPath, LoadedCpl = FolderPath,
  SHA1, SHA256, MD5, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```


Using an ASIM parser (uses Sysmon and an MDE table) and Sysmon Event ID 7 (no MDE):
```
// Find EXE + CPL created in same folder within 1 minute
let fileCreations =                                                                                
    imFileEvent                                                                         
    | where EventType == "FileCreated"
    | extend Ext = tolower(tostring(split(TargetFileName, ".")[-1]))
    | where Ext in ("exe", "cpl")
    | extend Folder = tostring(parse_path(TargetFilePath).DirectoryPath)
    | summarize
        ExeFiles = make_set_if(TargetFilePath, Ext == "exe", 100),
        CplFiles = make_set_if(TargetFilePath, Ext == "cpl", 100),
        ExtCount = dcount(Ext)
        by Folder, DvcHostname, bin(TimeGenerated, 1m)
    | where ExtCount == 2
    | mv-expand ExeFile = ExeFiles to typeof(string);
// Check if the created EXE was executed
let executions =
    imProcessCreate
    | join kind=inner fileCreations
        on $left.TargetProcessName == $right.ExeFile,
            $left.DvcHostname == $right.DvcHostname
    | mv-expand CplFile = CplFiles to typeof(string)
    | project TimeGenerated, DvcHostname, ActorUsername,
        TargetProcessName, TargetProcessId, TargetProcessGuid,
        ParentProcessName, ParentProcessCommandLine, CplFile;
// Verify the CPL was loaded by that process
WindowsEvent
| where EventID == 7
| extend
    Image = tostring(EventData.Image),
    ImageLoaded = tostring(EventData.ImageLoaded),
    ProcessGuid = tostring(EventData.ProcessGuid),
    Hashes = tostring(EventData.Hashes)
| join kind=inner executions
    on $left.Image == $right.TargetProcessName,
        $left.ProcessGuid == $right.TargetProcessGuid,
        $left.ImageLoaded == $right.CplFile,
        $left.Computer == $right.DvcHostname
| project
    TimeGenerated, DvcHostname, ActorUsername, ExecutedExe = TargetProcessName,
    LoadedCpl = ImageLoaded, CplHashes = Hashes, ParentProcess = ParentProcessName,
    ParentCommandLine = ParentProcessCommandLine
```
