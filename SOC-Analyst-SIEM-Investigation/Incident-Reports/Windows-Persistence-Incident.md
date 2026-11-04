# Incident Report – Windows Scheduled Task Persistence

## 1. Incident Overview

| Field | Details |
|---|---|
| Alert Name | Potential Task Scheduler Persistence Identified |
| Target Host | WIN-H015 |
| Affected User | oliver.thompson |
| Scheduled Task | AssessmentTaskOne |
| Event ID | 4698 |
| SIEM Tool | Splunk |
| Log Source | Windows Security Logs |
| Classification | True Positive (Lab Classification) |
| Severity | High – Analyst Assessment |

## 2. Incident Summary

A suspicious scheduled task creation event was identified on a Windows host. Investigation of the scheduled task XML revealed a daily execution schedule and a PowerShell-related command sequence using `certutil.exe` to download an executable named `DataCollector.exe`, followed by execution of that file.

## 3. Key Findings

- Identified scheduled task creation through Windows Security Event ID 4698.
- Task name: `AssessmentTaskOne`.
- Identified `certutil.exe` being used to download `DataCollector.exe`.
- The downloaded executable was placed in a temporary user directory.
- Identified the task's daily execution schedule.
- Investigated process information and identified `cmd.exe` as the parent process.
- Observed enumeration of the local Administrators group.
- Identified `DEV-QA-SERVER` as the source workstation in a matching logon event.

## 4. Investigation and Analysis

Splunk was used to investigate Windows Security Events and correlate related activity.

Important investigation details:

| Field | Finding |
|---|---|
| Event ID | 4698 |
| Client Process ID | 5816 |
| Parent Process | cmd.exe |
| Parent Process ID | 4128 |
| Enumerated Group | Administrators |
| Source Workstation | DEV-QA-SERVER |
| Source IP in matching logon event | 10.10.157.155 |

The scheduled task's download-and-execute behaviour, combined with system discovery activity, indicated possible malicious persistence.

## 5. Indicators of Compromise

| Indicator | Observed Value |
|---|---|
| Target Host | WIN-H015 |
| User Account | oliver.thompson |
| Scheduled Task | AssessmentTaskOne |
| Download Utility | certutil.exe |
| Downloaded File | DataCollector.exe |
| Parent Process | cmd.exe |
| Source Workstation | DEV-QA-SERVER |

## 6. Recommended Actions

1. Escalate the incident to the L2 SOC / Incident Response team.
2. Investigate the scheduled task and its execution history.
3. Verify the legitimacy and integrity of `DataCollector.exe`.
4. Review related process execution and network activity.
5. Investigate the source workstation and affected user account.
6. Remove unauthorised persistence mechanisms after appropriate investigation and approval.

## 7. Final Assessment

**Classification: True Positive (TryHackMe lab classification).**

The suspicious scheduled task, executable download-and-execute sequence and related discovery activity indicate possible persistence and host compromise.

Further investigation is required to determine the full scope and impact.

## 8. Environment and Scope

This investigation was performed using simulated security logs in the TryHackMe training environment. It represents a practical SOC investigation exercise and not a real-world production incident.

**Tools Used:** Splunk, Search Processing Language (SPL), Windows Security Event Logs.