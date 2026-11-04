# SPL Queries – SOC-Analyst-SIEM-Investigation

## 1. What is SPL?

Search Processing Language (SPL) is used in Splunk to search, filter, analyse and investigate machine-generated data.

## 2. Commands Practised

| Command | Purpose |
|---|---|
| index | Selects the data index |
| spath | Extracts fields from structured data |
| search | Filters matching events |
| stats | Performs statistical calculations |
| values() | Returns distinct field values |
| count | Counts events |

## 3. VPN Log Investigation

### Objective
Identify usernames associated with a specific VPN source IP and count matching events.

### SPL Query

```spl
index="vpn_logs"
| spath
| search Source_ip="107.14.182.38"
| stats values(UserName) as UserName count
```

### Query Explanation

- `index="vpn_logs"` – Searches the VPN logs index.
- `spath` – Extracts fields from structured data.
- `search Source_ip="107.14.182.38"` – Filters events for the specified source IP.
- `stats` – Performs statistical calculations.
- `values(UserName)` – Returns unique usernames.
- `as UserName` – Names the output field.
- `count` – Counts matching events.

### Expected Investigation Output

A summary containing unique usernames and the total number of matching events.

Note: Actual results depend on the available lab dataset.

## 4. Compare Statistical Commands

### Count all matching events

```spl
| stats count
```

### Count events by username

```spl
| stats count by UserName
```

### Display unique usernames and total event count

```spl
| stats values(UserName) as UserName count
```

## 5. SOC Analyst Application

These commands help analysts:

- Identify accounts associated with an IP address.
- Count VPN authentication events.
- Examine user activity.
- Investigate suspicious login patterns.

## 6. Learning Outcome

Practised fundamental SPL commands and understood how Splunk can summarize security events for investigation.

## Evidence

Actual Splunk search screenshots will be added during practical investigation exercises.

## Note

These are training examples. The query and example IP address are not evidence of a confirmed malicious incident.