# Web Application Log Investigation – WordPress Brute-Force Activity

## 1. Investigation Overview

**Project:** SOC-Analyst-SIEM-Investigation
**Platform:** TryHackMe  
**SIEM:** Splunk  
**Room:** Log Analysis with SIEM  
**Task:** Web Application Logs  
**Index:** task6  
**Investigation Type:** Web server activity analysis  
**Environment:** Simulated lab environment

### Objective

Investigate an alert indicating a spike in web server activity. Analyze HTTP request logs to identify the targeted URI, source IP address, suspicious activity pattern and tool used.

---

## 2. Initial Investigation

Started by searching the web application log dataset in Splunk.

**Initial SPL query:**

```spl
index=task6
```

Further investigation focused on POST requests targeting the WordPress login endpoint.

**Investigation query:**

```spl
index=task6 method=POST uri_path="/wp-login.php"
| bin _time span=5m
| stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
| where count > 25
| table referer_domain clientip UserAgent uri_path count status
```

### Query analysis

- `method=POST` – filters HTTP POST requests.
- `uri_path="/wp-login.php"` – focuses on the WordPress login endpoint.
- `bin _time span=5m` – groups events into five-minute intervals.
- `stats` – summarizes activity by client IP and time.
- `where count > 25` – filters high-volume request groups.
- `table` – displays relevant investigation fields.

---

## 3. Investigation Findings

The Splunk results identified two notable sources of activity.

| Field | Finding 1 | Finding 2 |
|---|---|---|
| Client IP | 10.10.243.134 | 167.172.41.141 |
| URI path | /wp-login.php | /wp-login.php |
| Request count | 583 | 160 |
| User-Agent | WPScan v3.8.28 | Mozilla/5.0 (Hydra) |
| HTTP status | 200 | 200 and 302 |

### Primary finding

**Highest request count:** 583

**Targeted URI:** `/wp-login.php`

**Source IP:** `10.10.243.134`

**Identified tool:** `WPScan v3.8.28`

---

## 4. Activity Classification

### WordPress Login Brute-Force Activity

The investigation identified repeated HTTP POST requests targeting the WordPress login endpoint.

The high request volume and the User-Agent identifying WPScan suggest automated WordPress security scanning or login attack activity.

The activity is consistent with brute-force-style login attempts and requires further investigation to determine whether any authentication attempts succeeded.

### Tool identification

The User-Agent field contained:

```text
WPScan v3.8.28 (https://wpscan.com/wordpress-security-scanner)
```

WPScan is a WordPress security scanner used to identify security weaknesses in WordPress installations.

The logs also showed another source using a Hydra User-Agent, but WPScan was associated with the highest request count.

---

## 5. Indicators of Interest

| Indicator | Value |
|---|---|
| Target endpoint | /wp-login.php |
| Primary source IP | 10.10.243.134 |
| Request method | POST |
| Request count | 583 |
| Identified tool | WPScan v3.8.28 |
| Secondary source IP | 167.172.41.141 |
| Secondary User-Agent | Hydra |

These indicators are based on the observed simulated web server logs.

---

## 6. SOC Analyst Assessment

The investigation identified unusually high-volume HTTP POST activity targeting the WordPress login endpoint.

The User-Agent field identified WPScan v3.8.28 as the tool associated with the highest request volume.

This activity is consistent with automated WordPress login testing or brute-force-style activity.

### Recommended response actions

- Review authentication logs to identify successful and failed login attempts.
- Investigate the source IP address and related request patterns.
- Check whether any accounts were accessed successfully.
- Review WordPress security and web server logs for additional suspicious activity.
- Consider rate limiting and appropriate access restrictions.
- Escalate confirmed unauthorized access to the incident response team.

---

## 7. Conclusion

Using Splunk, I investigated a spike in web application activity by analyzing HTTP POST requests and grouping request counts by client IP and time.

The investigation identified `/wp-login.php` as the most frequently targeted endpoint, with 583 requests associated with source IP `10.10.243.134`.

The User-Agent field identified WPScan v3.8.28 as the tool associated with this activity.

The findings indicate automated WordPress login attack activity requiring further authentication-log analysis.

---

## 8. Skills Practiced

- Web server log analysis
- HTTP request analysis
- HTTP methods and status codes
- Source IP identification
- User-Agent analysis
- Request frequency analysis
- SPL filtering and aggregation
- Identification of automated web security tools
- Brute-force activity investigation
- SOC incident documentation

**Lab classification:** Simulated TryHackMe investigation. No real enterprise incident was investigated.