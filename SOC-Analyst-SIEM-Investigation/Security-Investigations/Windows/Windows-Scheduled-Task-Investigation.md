# Windows Scheduled Task Persistence Investigation

## 1. Investigation Overview

- **Alert Name:** Potential Task Scheduler Persistence Identified
- **Date:** 30 August 2025
- **Alert Time:** 10:06:07 AM
- **Host:** WIN-H015
- **User:** oliver.thompson
- **SIEM:** Splunk
- **Index:** win-alert
- **Event ID:** 4698 – Scheduled Task Created

## 2. Alert Description

A Windows scheduled task named `AssessmentTaskOne` was created on the host WIN-H015.

The task was configured to execute daily and run a PowerShell command that downloads an executable using `certutil.exe` and launches it.

Downloaded file:
`DataCollector.exe`

## 3. Investigation Findings

### Finding 1 – Process Identification

- Process ID: `5816`
- Parent Process ID: `4128`
- Parent process name: `cmd.exe`

### Finding 2 – Local Group Enumeration

The investigation identified the command:

`net localgroup Administrators`

This command was used to enumerate members of the local Administrators group.

### Finding 3 – Source Workstation

A Windows Security Event ID 4624 was identified.

- Account: `oliver.thompson`
- Target host: `WIN-H015`
- Workstation Name: `DEV-QA-SERVER`
- Source IP: `10.10.157.155`
- Logon Type: 3 – Network logon
- Event time: 30 August 2025, 09:50:32 AM

### Finding 4 – Scheduled Task Creation

- Task name: `AssessmentTaskOne`
- Event ID: `4698`
- Task execution frequency: Daily
- Download utility: `certutil.exe`
- Downloaded executable: `DataCollector.exe`

The task configuration and executable download-and-launch behavior indicate suspicious persistence activity.

## 4. SPL Queries Used

### Search scheduled task creation

```spl
index="win-alert" host="WIN-H015" EventCode=4698
```

### Identify the parent process

```spl
index="win-alert" host="WIN-H015" EventCode=1
| search ProcessId=4128
| table _time Image ProcessId ParentProcessId CommandLine ParentImage
```

### Identify local group enumeration

```spl
index="win-alert" host="WIN-H015" EventCode=1
| search "group" OR "net.exe" OR "net1.exe" OR "Get-LocalGroup"
| table _time Image ProcessId ParentProcessId CommandLine
| sort + _time
```

### Identify the source workstation

```spl
index=win-alert "DEV-QA-SERVER"
```

## 5. Alert Assessment

**Classification:** True Positive (as classified by the TryHackMe lab).

**Reason:** The scheduled task was configured to download and execute an executable, and the investigation identified suspicious account and group discovery activity.

**Recommended Action:** Escalate to L2 SOC / Incident Response for further investigation, including validation of the downloaded executable, review of persistence, and assessment of potential compromise.

## 6. Conclusion

The investigation identified suspicious scheduled task creation, executable download and execution behavior, local Administrators group enumeration, and a source workstation associated with the account activity.

This exercise provided practical experience in Windows event analysis, process investigation, persistence detection, and alert triage using Splunk.

**Dataset:** Simulated TryHackMe training environment.