# SOC Analyst – SIEM Monitoring & Incident Investigation

## Project Overview

This project demonstrates practical Security Operations Center (SOC) investigation skills using Splunk and simulated security logs from TryHackMe.

The objective was to investigate suspicious activities across Windows, Linux and web environments, analyse security events, identify potential indicators of compromise (IOCs), perform alert triage and document investigation findings.

## Tools and Technologies

- **SIEM:** Splunk
- **Query Language:** Search Processing Language (SPL)
- **Operating Systems:** Linux, Windows
- **Log Sources:** Windows Security Logs, Linux Authentication Logs, Web Server Logs
- **Training Platform:** TryHackMe

## Investigation Areas

### 1. SIEM Fundamentals

Covered SIEM concepts, log analysis and SPL query fundamentals.

- SIEM-Fundamentals: [SIEM Fundamentals](SIEM-Fundamentals/SIEM-Fundamentals.md)
- SPL Queries: [SPL Query Notes](SIEM-Fundamentals/SPL-Queries.md)

### 2. Security Investigations

Conducted six investigations across Windows, Linux and web environments.

**Windows Investigations**
- [Windows Log Investigation](Security-Investigations/Windows/Windows-Log-Investigation.md)
- [Windows Scheduled Task Investigation](Security-Investigations/Windows/Windows-Scheduled-Task-Investigation.md)

**Linux Investigations**
- [Linux Log Investigation](Security-Investigations/Linux/Linux-Log-Investigation.md)
- [Brute-Force Investigation](Security-Investigations/Linux/Brute-Force-Investigation.md)

**Web Investigations**
- [Web Log Investigation](Security-Investigations/Web/Web-Log-Investigation.md)
- [Web Shell Investigation](Security-Investigations/Web/Web-Shell-Investigation.md)

### 3. Incident Reports

Prepared incident reports based on the investigation findings.

- [Linux Brute-Force Incident](Incident-Reports/Linux-Brute-Force-Incident.md)
- [Windows Persistence Incident](Incident-Reports/Windows-Persistence-Incident.md)
- [Web Shell Incident](Incident-Reports/Web-Shell-Incident.md)

## Key Findings and Activities

- Analysed repeated SSH authentication failures and successful login activity.
- Investigated privilege escalation and suspicious Linux account creation.
- Analysed Windows scheduled-task creation using Event ID 4698.
- Investigated suspicious executable download and execution activity.
- Examined process relationships and local administrator group enumeration.
- Identified suspicious WordPress login requests and potential web-shell activity.
- Used SPL to filter, correlate and summarise security events.
- Classified alerts and documented recommended escalation actions.

## Skills Demonstrated

- SIEM monitoring and log analysis
- Splunk and SPL fundamentals
- Windows and Linux log investigation
- Authentication and brute-force analysis
- Persistence mechanism investigation
- Process and event correlation
- Web application log analysis
- IOC identification
- Security alert triage
- Incident documentation and escalation

## Project Evidence

Screenshots supporting the investigations are organised in the corresponding Evidence folders:

- `Security-Investigations/Windows/Evidence/`
- `Security-Investigations/Linux/Evidence/`
- `Security-Investigations/Web/Evidence/`

## Learning Outcomes

Through these practical exercises, I developed an understanding of how SOC analysts investigate suspicious activities, correlate security events, identify potential compromise indicators, assess alerts and prepare incident reports.

## Environment and Disclaimer

All investigations were conducted using simulated security logs and training scenarios from TryHackMe.

The findings represent educational lab exercises and do not describe real-world production security incidents.