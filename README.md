# TryHackMe_Boogeyman_2

> Focus: Windows memory forensics, phishing investigation, malware execution, C2 identification, and scheduled-task persistence  
> Tools: Volatility 3, `strings`, `grep`  
> Evidence: `WKSTN-2961.raw`

## Executive Summary

This investigation reconstructed a multi-stage phishing compromise affecting the user **maxine.beck**. The attacker delivered a malicious Microsoft Word document through email, which was opened from Outlook’s local attachment cache. The document’s macro downloaded and executed a JavaScript payload, which then downloaded and launched a malicious binary named `updater.exe`.

The malicious binary established repeated C2 connections to `128.199.95.189:8080`. After establishing C2, the attacker created a scheduled task named `Updater` to execute hidden PowerShell daily. The task decoded and executed a Base64-encoded payload stored in the current user’s registry, providing fileless persistence.

## Investigation Flow

```text
Phishing email attachment
        |
        v
WINWORD.EXE opens malicious .doc file
        |
        v
Macro downloads disguised stage-2 payload
        |
        v
wscript.exe executes update.js
        |
        v
update.js downloads and runs updater.exe
        |
        v
updater.exe establishes C2 communication
        |
        v
Scheduled task creates persistent hidden PowerShell execution
```

## Initial Access

The malicious attachment was opened by `WINWORD.EXE` from Outlook’s attachment cache.

```bash
vol -f WKSTN-2961.raw windows.cmdline | grep -i 'Resume_WesleyTaylor'
```

### Evidence

```text
PID: 1124
Process: WINWORD.EXE
Command line:
"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n
"C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc"
```

### Malicious Attachment Path

```text
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```

The `Content.Outlook` path is significant because Outlook commonly creates a temporary local copy of an attachment when a user opens it directly from an email. This supports phishing email delivery as the initial-access vector.

## Process Execution Chain

The malicious document led to execution of a JavaScript payload through Windows Script Host, followed by a malicious executable.

```text
WINWORD.EXE (PID 1124)
└── wscript.exe (PID 4260)
    └── updater.exe (PID 6216)
```

The following command was used to inspect process command-line arguments:

```bash
vol -f WKSTN-2961.raw windows.cmdline
```

The JavaScript payload was executed through `wscript.exe`, and the malicious binary was launched as:

```text
C:\Windows\Tasks\updater.exe
```

## Payload Delivery

The malicious stage-2 payload was recovered as a cached file object through memory analysis.

```bash
vol -f WKSTN-2961.raw windows.filescan | grep -i 'update'
```

### Relevant File Artefacts

```text
\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\IE\GEX3PLZ6\update[1].png
\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\IE\FMJK14EZ\update[1].exe
\Windows\Tasks\updater.exe
\Windows\System32\Tasks\Updater
```

The attacker used a misleading `.png` extension for the stage-2 payload. The payload was treated as JavaScript and executed through `wscript.exe`. It then downloaded the malicious executable payload.

### Malicious Binary Download URL

```text
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe
```

## Command and Control

The malicious process responsible for C2 was identified as:

```text
Process: updater.exe
PID: 6216
Path: C:\Windows\Tasks\updater.exe
```

The following command was used to identify network connections associated with the malicious process:

```bash
vol -f WKSTN-2961.raw windows.netscan | grep '6216\|updater.exe'
```

### Network Evidence

```text
Protocol: TCPv4
Local Address: 10.10.49.181
Local Port: 63299
Foreign Address: 128.199.95.189
Foreign Port: 8080
State: CLOSED
PID: 6216
Process: updater.exe
```

Multiple connections from `updater.exe` used different local ephemeral ports but communicated with the same remote endpoint.

### C2 Endpoint

```text
128.199.95.189:8080
```

The repeated connections to the same remote IP address and port, all owned by PID 6216, indicate recurring C2 communication.

## Persistence

The attacker established persistence immediately after the C2 callback by creating a scheduled task named `Updater`.

A Unicode string search of the memory image recovered the task-creation command:

```bash
strings -a -el -n 8 WKSTN-2961.raw | grep -i 'schtasks'
```

### Persistence Command

```text
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
```

### Command Breakdown

| Component | Meaning |
|---|---|
| `schtasks /Create` | Creates a scheduled task |
| `/F` | Forces creation or overwrites an existing task |
| `/SC DAILY` | Runs the task daily |
| `/ST 09:00` | Runs at 09:00 |
| `/TN Updater` | Names the task `Updater` |
| `/TR` | Defines the command executed by the task |
| `powershell.exe` | Launches PowerShell |
| `-NonI` | Runs without user interaction |
| `-W hidden` | Hides the PowerShell window |
| `gp HKCU:\... debug` | Reads the `debug` registry value |
| `FromBase64String` | Decodes Base64-encoded content |
| `UNICODE.GetString` | Converts decoded bytes to readable PowerShell |
| `IEX` | Executes the decoded PowerShell command |

This is fileless persistence because the scheduled task retrieves malicious code from a registry value instead of directly launching a visible payload file.

## Indicators of Compromise

| Type | Indicator |
|---|---|
| Malicious attachment | `Resume_WesleyTaylor (002).doc` |
| Attachment path | `C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc` |
| Stage-2 payload | `update[1].png` |
| Downloaded binary | `update[1].exe` |
| Executed malware | `C:\Windows\Tasks\updater.exe` |
| Malicious process | `updater.exe` |
| Malicious PID | `6216` |
| C2 endpoint | `128.199.95.189:8080` |
| Payload URL | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe` |
| Scheduled task | `Updater` |
| Registry payload location | `HKCU:\Software\Microsoft\Windows\CurrentVersion\debug` |

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | Malicious Word document opened from `Content.Outlook` |
| Execution | User Execution: Malicious File | User opened the malicious resume document |
| Execution | Command and Scripting Interpreter: Windows Command Shell / PowerShell | `wscript.exe` and hidden PowerShell execution |
| Command and Control | Application Layer Protocol | TCP communication with `128.199.95.189:8080` |
| Persistence | Scheduled Task/Job | Daily task named `Updater` |
| Defense Evasion | Obfuscated/Compressed Files and Information | Base64-encoded registry payload |
| Defense Evasion | Hide Artifacts | Hidden PowerShell window |
| Persistence | Modify Registry | Payload stored in the `debug` registry value |

## Key Takeaways

- An Outlook cache path can strongly support email attachment delivery, but it should still be correlated with process execution, file artefacts, and user activity.
- Process lineage was essential for reconstructing the execution chain from `WINWORD.EXE` to `wscript.exe` and finally `updater.exe`.
- `netscan` allowed network artefacts to be attributed directly to PID 6216, confirming the C2 process and remote endpoint.
- Scheduled tasks that launch hidden PowerShell, decode Base64 content, read from the registry, and invoke `IEX` are high-confidence persistence indicators.
- Effective SOC investigation requires correlating process, file, registry, command-line, and network evidence into a single defensible timeline.
