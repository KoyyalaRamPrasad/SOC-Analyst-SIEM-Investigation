# Web Shell Investigation

## 1. Investigation Overview

- **Alert Name:** Potential Web Shell Upload Detected
- **Date:** 14 September 2025
- **Alert Time:** 09:31:51 AM
- **Target Resource:** http://web.trywinme.thm
- **Suspicious IP:** 171.251.232.40
- **SIEM:** Splunk
- **Index:** web-alert

## 2. Alert Description

An alert was generated for possible web shell activity targeting the organisation's web server.

The investigation focused on requests originating from the suspicious IP address `171.251.232.40`, including possible brute-force activity and interactions with a suspicious PHP file.

## 3. Investigation Findings

### Finding 1 – Threat Intelligence

The suspicious IP address was checked using AbuseIPDB.

The TryHackMe scenario reported that the IP had been flagged as malicious more than 3,000 times.

### Finding 2 – Hydra Brute-Force Activity

The investigation identified multiple requests from `171.251.232.40` targeting:

`wp-login.php`

The User-Agent was identified as:

`Hydra`

Hydra is a tool commonly used for password-based login attacks.

- **Brute-force start time:** [Insert confirmed timestamp]
- **Source IP:** 171.251.232.40
- **Target:** wp-login.php

### Finding 3 – Suspicious Web Shell Activity

After excluding Hydra requests, the investigation identified a POST request to:

`admin-ajax.php`

The referer contained:

`theme-editor.php?file=b374k.php`

This was suspicious because the PHP file appeared in an unusual theme-editor reference.

Further investigation identified activity involving:

`b374k.php`

Research confirmed that b374k is a known PHP web shell.

### Finding 4 – Web Shell Interaction

The logs showed four successful POST requests associated with the web shell.

- **Web shell:** b374k.php
- **User-Agent:** Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
- **Successful POST requests:** 4 
The logs did not reveal how the web shell was initially uploaded.

## 4. SPL Queries Used

### Identify Hydra brute-force activity

```spl
index=web-alert "171.251.232.40"
| search useragent="*Hydra*"
| table _time clientip useragent uri_path method status
| sort + _time
```

### Exclude Hydra requests and inspect other activity

```spl
index=web-alert "171.251.232.40" useragent!="Mozilla/5.0 (Hydra)"
| table _time clientip useragent uri_path referer referer_domain method status
```

### Investigate b374k.php activity

```spl
index=web-alert "171.251.232.40" "b374k.php"
| table _time clientip useragent uri_path referer referer_domain method status
| sort + _time
```

### Count web shell requests

```spl
index=web-alert "171.251.232.40" "b374k.php"
| stats count by method status useragent
```

## 5. Alert Assessment

**Classification:** True Positive (as classified by the TryHackMe lab).

**Reason:**

- Suspicious Hydra brute-force activity targeting the WordPress login page.
- Unusual reference to `b374k.php`.
- Evidence of successful POST requests through the identified web shell.
- Threat intelligence reputation associated with the source IP.

**Recommended Action:** Escalate to L2 SOC / Incident Response for deeper investigation and containment.

## 6. Further Investigation Required

The following questions require further investigation:

1. Was the Hydra brute-force attack successful?
2. How was the web shell uploaded to the server?
3. What commands or actions were executed through the web shell?

The available web logs did not establish the initial upload method or the exact commands executed.

## 7. Conclusion

The investigation identified suspicious web activity involving brute-force attempts and interactions with a known PHP web shell.

The activity was classified as a True Positive in the TryHackMe training scenario and should be escalated to the L2 SOC team for further investigation.

**Dataset:** Simulated TryHackMe training environment.