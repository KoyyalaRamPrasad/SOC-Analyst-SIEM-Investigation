# Windows Log Investigation – SharePoInt.exe

## 1. Investigation Overview

**Project:** SOC-Analyst-SIEM-Investigation 
**Platform:** TryHackMe  
**SIEM:** Splunk  
**Room:** Log Analysis with SIEM  
**Task:** Windows Logs  
**Investigation Type:** Windows process and network activity analysis  
**Environment:** Simulated lab environment

### Objective

Investigate suspicious Windows activity by analyzing Sysmon logs in Splunk. Identify the process responsible for network communication, retrieve its MD5 hash, and determine whether a scheduled task was created to execute the suspicious program.

---

## 2. Initial Network Activity

The investigation started with a Sysmon network connection event.

**Event details:**

| Field | Observed value |
|---|---|
| Event ID | 3 |
| Host | WIN-105 |
| Username | WIN-105\Ben Foster |
| Process | SharePoInt.exe |
| Process ID | 1460 |
| Executable path | C:\Windows\Temp\SharePoInt.exe |
| Protocol | TCP |
| Source IP | 10.10.61.100 |
| Source port | 49798 |
| Destination IP | 10.10.114.80 |
| Destination port | 5678 |
| Connection initiated | True |
| Process GUID | {c5d2b969-c41e-689d-dc02-000000002101} |
| Event time (UTC) | 2025-08-14 11:10:21.430 |

### Analysis

Sysmon Event ID 3 records network connections initiated by processes.

The executable `SharePoInt.exe` was running from the Windows Temp directory and initiated a TCP connection to an internal IP address on port 5678.

Running an executable from a temporary directory and making an unexpected network connection are indicators worth investigating. However, these observations alone do not prove malicious activity.

---

## 3. Process Investigation and Hash Identification

To investigate the process further, I used its Process GUID to correlate related Sysmon events.

**Splunk search:**

```spl
index=task4 "{c5d2b969-c41e-689d-dc02-000000002101}"
```

The results included process creation telemetry.

**Relevant process details:**

| Field | Observed value |
|---|---|
| Event ID | 1 |
| Process | SharePoInt.exe |
| Process ID | 1460 |
| Executable path | C:\Windows\Temp\SharePoInt.exe |
| MD5 | 770D14FFA142F09730B415506249E7D1 |
| SHA256 | 096AC8A80A730BD354334278700991EB762EBC8CB2E7D5CAED8702EC0EF2A912 |

### Analysis

Sysmon Event ID 1 records process creation activity.

The Process GUID helped identify the specific process instance associated with the earlier network connection.

The MD5 hash was extracted from the `Hashes` field of the process creation event. A file hash can be used as an identifier when performing further threat intelligence or malware analysis.

**Important:** A hash by itself does not establish whether a file is malicious.

---

## 4. Scheduled Task Investigation

During the investigation, another process creation event showed the execution of Windows Task Scheduler's command-line utility.

**Executable:** `C:\Windows\System32\schtasks.exe`

**Observed command line:**

```cmd
schtasks /create /sc once /st 15:30 /tn "Office365 Install" /tr "C:\Windows\Temp\SharePoInt.exe"
```

### Command analysis

| Parameter | Meaning |
|---|---|
| schtasks | Windows Scheduled Task utility |
| /create | Creates a scheduled task |
| /sc once | Configures a one-time schedule |
| /st 15:30 | Sets the scheduled start time |
| /tn | Specifies the task name |
| /tr | Specifies the program to execute |

**Identified scheduled task name:** `Office365 Install`

**Configured executable:** `C:\Windows\Temp\SharePoInt.exe`

### Analysis

The command creates a scheduled task named `Office365 Install` and configures it to execute `SharePoInt.exe`.

Scheduled tasks can be used for legitimate automation, but attackers may also abuse them to maintain persistence or execute programs at a scheduled time.

The task name appears legitimate, but its configured executable and surrounding activity require further investigation.

Note: This finding was identified from Sysmon process creation telemetry showing the `schtasks.exe` command. A separate Windows Security Event ID 4698 record was not independently verified.

---

## 5. Investigation Timeline

| Time (UTC) | Activity |
|---|---|
| 11:10:21 | SharePoInt.exe initiated a TCP connection to 10.10.114.80:5678 |
| 11:15:09 | A process creation event recorded execution of schtasks.exe to create the scheduled task |

The timeline shows related suspicious activity on WIN-105. Further telemetry would be needed to establish the complete execution sequence and determine whether the scheduled task actually ran.

---

## 6. Indicators of Interest

| Indicator | Value |
|---|---|
| Host | WIN-105 |
| User | Ben Foster |
| Executable | SharePoInt.exe |
| File path | C:\Windows\Temp\SharePoInt.exe |
| MD5 | 770D14FFA142F09730B415506249E7D1 |
| Destination IP | 10.10.114.80 |
| Destination port | 5678 |
| Scheduled task | Office365 Install |
| Scheduled utility | schtasks.exe |

These are investigation indicators, not independently confirmed indicators of compromise.

---

## 7. Security Assessment

The following observations require attention:

1. An executable was running from the Windows Temp directory.
2. The executable initiated an outbound TCP connection to another internal host.
3. The Windows Task Scheduler utility was executed.
4. A scheduled task was configured to execute the same executable.

### Potential security concern

The scheduled task could represent an attempt to establish persistence.

However, the available events do not independently confirm malware execution, successful persistence, or compromise of the destination host.

---

## 8. Recommended Investigation and Response

If this activity were observed in a real SOC environment, the following steps would be appropriate:

- Validate the executable's hash using approved threat intelligence sources.
- Investigate the destination IP and port to identify the remote service.
- Review the parent and child process relationships.
- Examine the scheduled task's configuration and execution history.
- Check whether the task executed successfully.
- Review additional authentication and network logs for related activity.
- Escalate to the incident response team if malicious activity is confirmed.
- Follow organizational procedures before isolating a host or removing a scheduled task.

---

## 9. Conclusion

The investigation used Splunk to correlate Sysmon process creation and network connection events.

The analysis identified `SharePoInt.exe`, extracted its MD5 hash, and discovered a scheduled task named `Office365 Install` configured to execute the executable.

The combination of process execution from a temporary directory, network communication, and scheduled task creation represents suspicious behavior that warrants further investigation.

This exercise provided practical experience in Windows event analysis, Sysmon Event IDs, process correlation using Process GUIDs, hash identification, and scheduled task investigation.

---

## 10. Skills Practiced

- SIEM log analysis using Splunk
- Searching and filtering Windows events
- Understanding Sysmon Event ID 1 and Event ID 3
- Correlating events using Process GUID and Process ID
- Extracting file hashes
- Analyzing Windows command-line activity
- Identifying potential persistence mechanisms
- Documenting investigation findings

**Lab classification:** Simulated TryHackMe investigation. No real enterprise incident was investigated.