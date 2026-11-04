# Incident Report – Potential Web Shell Activity

## 1. Incident Overview

| Field | Details |
|---|---|
| Alert Name | Potential Web Shell Upload Detected |
| Target Resource | web.trywinme.thm |
| Suspicious Source IP | 171.251.232.40 |
| SIEM Tool | Splunk |
| SIEM Index | web-alert |
| Log Source | Web Server Logs |
| Classification | True Positive (Lab Classification) |
| Severity | High – Analyst Assessment |

## 2. Incident Summary

Suspicious web activity was identified against a web application. Investigation revealed Hydra-labelled requests targeting the WordPress login endpoint, followed by suspicious POST requests involving `admin-ajax.php` and a reference to `b374k.php`, which the TryHackMe scenario identified as a PHP web shell.

## 3. Key Findings

- Identified brute-force-style requests targeting `wp-login.php`.
- Observed requests associated with the suspicious source IP `171.251.232.40`.
- Identified POST requests to `admin-ajax.php`.
- Observed the referer `theme-editor.php?file=b374k.php`.
- Identified `b374k.php` as a known PHP web shell according to the lab.
- Observed four successful POST requests associated with web-shell activity in the scenario.

## 4. Investigation and Analysis

Splunk was used to investigate web server logs and identify suspicious HTTP requests.

The investigation focused on:

- Source IP address and request patterns.
- User-Agent information.
- WordPress login endpoint activity.
- HTTP POST requests.
- Referer values and web-shell-related activity.

The combination of brute-force-style activity and subsequent web-shell interactions indicated possible web application compromise.

## 5. Indicators of Compromise

| Indicator | Observed Value |
|---|---|
| Source IP | 171.251.232.40 |
| Target Resource | web.trywinme.thm |
| Login Endpoint | /wp-login.php |
| Suspicious Endpoint | /admin-ajax.php |
| Referenced File | b374k.php |
| HTTP Method | POST |

## 6. Recommended Actions

1. Escalate the incident to the L2 SOC / Incident Response team.
2. Investigate the suspicious source IP and related HTTP requests.
3. Verify whether the web shell exists on the server.
4. Review web-server access logs and application logs.
5. Determine how the web shell was initially uploaded.
6. Investigate commands and actions performed through the web shell.
7. Check for unauthorised access, data exposure and further compromise.

## 7. Final Assessment

**Classification: True Positive (TryHackMe lab classification).**

The suspicious WordPress login activity, web-shell reference and subsequent POST requests indicate potential web application compromise.

The available logs did not establish the initial upload method or the exact commands executed through the web shell. Further investigation is required to determine the full scope and impact.

## 8. Environment and Scope

This investigation was performed using simulated security logs in the TryHackMe training environment. It represents a practical SOC investigation exercise and not a real-world production incident.

**Tools Used:** Splunk, Search Processing Language (SPL), Web Server Logs.