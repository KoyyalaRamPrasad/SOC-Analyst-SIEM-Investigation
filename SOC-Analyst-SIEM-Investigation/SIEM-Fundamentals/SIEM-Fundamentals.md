# Day 1 – SIEM Fundamentals

## Project
SOC-Analyst-SIEM-Investigation

## Learning Platform
TryHackMe

## SIEM Tool
Splunk

## Completed Training Rooms

1. Introduction to SIEM
2. Splunk: The Basics
3. Splunk: Exploring SPL

## Key Concepts Learned

- SIEM (Security Information and Event Management)
- Centralized log collection and monitoring
- Security event investigation
- Splunk search interface
- Search Processing Language (SPL)
- Filtering and analysing security events
- Statistical analysis using SPL

## SPL Commands Practised

- index
- spath
- search
- stats
- values()
- count

## Example SPL Query

```spl
index="vpn_logs"
| spath
| search Source_ip="107.14.182.38"
| stats values(UserName) as UserName count
```

## Query Objective

Identify unique usernames associated with a particular VPN source IP and count matching events.

## Practical Learning Outcome

Developed foundational knowledge of SIEM monitoring, Splunk navigation, SPL searches, and security log analysis.

## Evidence

Screenshots and practical investigation evidence will be added as the project progresses.

## Note

This document records learning completed through TryHackMe training rooms. It does not represent independent enterprise SIEM deployment or real-world security incident investigation.