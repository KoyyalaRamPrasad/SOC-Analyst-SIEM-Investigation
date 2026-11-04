# Incident Report – Linux Brute-Force Activity

## 1. Incident Overview

| Field | Details |
|---|---|
| Alert Name | Brute Force Activity Detection |
| Target Host | tryhackme-2404 |
| Source IP | 10.10.242.248 |
| Target Account | john.smith |
| SIEM Tool | Splunk |
| Log Source | Linux Authentication Logs |
| Classification | True Positive (Lab Classification) |
| Severity | High – Analyst Assessment |

## 2. Incident Summary

A brute-force authentication attack was detected against a Linux host. Repeated failed SSH login attempts were observed against the account `john.smith`, followed by successful authentication, privilege escalation and the creation of a new user account.

## 3. Key Findings

- Observed 503 failed authentication attempts against `john.smith`.
- The failed attempts occurred over approximately five minutes.
- Identified successful SSH login activity after the failed attempts.
- Observed privilege escalation to the root account.
- Identified creation of a new account named `system-utm`.

## 4. Investigation and Analysis

Splunk was used to filter and analyse Linux authentication events.

The investigation focused on:
- Repeated failed SSH authentication attempts.
- Successful login activity.
- Privilege escalation events.
- New user account creation.

The sequence of events indicated possible account compromise and persistence.

## 5. Indicators of Compromise

| Indicator | Observed Value |
|---|---|
| Source IP | 10.10.242.248 |
| Target Host | tryhackme-2404 |
| Target Account | john.smith |
| Suspicious Account Created | system-utm |
| Authentication Method | SSH |

## 6. Recommended Actions

1. Escalate the incident to the L2 SOC / Incident Response team.
2. Investigate the source IP and related authentication activity.
3. Verify whether the newly created account is authorised.
4. Review root-level activity and commands executed.
5. Contain the affected host if compromise is confirmed.
6. Review SSH access controls and authentication policies.

## 7. Final Assessment

**Classification: True Positive (TryHackMe lab classification).**

The repeated authentication failures, subsequent successful login, privilege escalation and suspicious account creation indicate a likely successful compromise.

Further investigation is required to determine the full scope and impact.

## 8. Environment and Scope

This investigation was performed using simulated security logs in the TryHackMe training environment. It represents a practical SOC investigation exercise and not a real-world production incident.

**Tools Used:** Splunk, Search Processing Language (SPL), Linux Authentication Logs.