# Brute Force Activity Investigation

## 1. Investigation Overview

- **Alert:** Brute Force Activity Detection
- **Date:** 17 September 2025
- **Target Host:** `tryhackme-2404`
- **Source IP:** `10.10.242.248`
- **Log Source:** Linux SSH authentication logs
- **Splunk Index:** `linux-alert`

## 2. Investigation Findings

### Brute-force activity
- Identified repeated SSH authentication attempts from `10.10.242.248`.
- Four user accounts were targeted.
- `john.smith` received 503 failed login attempts.
- The brute-force activity lasted approximately 5 minutes.

### Successful authentication
- The attacker successfully authenticated as `john.smith`.
- Successful SSH login events were identified in the logs.

### Privilege escalation
- The attacker escalated privileges to the `root` account.

### Persistence
- A new user account named `system-utm` was created.
- This activity indicates an attempt to maintain access to the compromised system.

## 3. Key Indicators

| Indicator | Value |
|---|---|
| Source IP | `10.10.242.248` |
| Target host | `tryhackme-2404` |
| Targeted account | `john.smith` |
| Failed attempts | 503 |
| Attack duration | 5 minutes |
| Privilege escalation | `root` |
| Persistence account | `system-utm` |

## 4. SOC Analyst Assessment

**Classification:** True Positive

The investigation identified suspicious SSH brute-force activity followed by successful authentication, privilege escalation to root, and creation of a persistence account.

These findings indicate a successful simulated compromise of the target Linux host.

## 5. Recommended Response Actions

1. Escalate the incident to the incident response team.
2. Investigate and contain the compromised host.
3. Disable or investigate the unauthorized `system-utm` account.
4. Review SSH authentication and privilege-escalation logs.
5. Investigate the source IP and activity performed after access was obtained.
6. Reset affected credentials and review SSH access controls.

## 6. Learning Outcomes

- Analyzed Linux SSH authentication logs using Splunk.
- Identified brute-force activity and user enumeration.
- Distinguished failed and successful authentication events.
- Investigated privilege escalation.
- Identified account creation as a possible persistence technique.
- Practiced SOC alert triage and incident classification.

**Lab Environment:** Simulated TryHackMe environment. Findings are from a training investigation, not a real-world incident.