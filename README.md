# Linux Cron Persistence & Detection Techniques

A technical reference for understanding Linux cron-based persistence, investigating suspicious scheduled tasks, and identifying persistence mechanisms during security assessments.

## Table of Contents

- [Overview](#overview)
- [Cron Basics](#cron-basics)
- [Cron Schedule Format](#cron-schedule-format)
- [Cron Persistence Locations](#cron-persistence-locations)
- [Common Persistence Techniques](#common-persistence-techniques)
- [Systemd Timer Persistence](#systemd-timer-persistence)
- [Detection and Monitoring](#detection-and-monitoring)
- [Forensic Investigation](#forensic-investigation)
- [Cleanup and Removal](#cleanup-and-removal)
- [Linux Hardening](#linux-hardening)
- [References](#references)

## Overview

Cron is a Linux job scheduler that executes commands and scripts at predefined intervals.

Attackers may abuse cron to establish persistence on compromised systems, allowing unauthorized commands to execute periodically or following system reboots.

Understanding cron persistence is useful for:

- Red team security assessments.
- Linux system administration.
- Malware analysis.
- Incident response.
- Threat hunting.
- Host-based intrusion detection.

## Cron Basics

View the current user's scheduled tasks:

```bash
crontab -l
```

Edit the current user's crontab:

```bash
crontab -e
```

Remove the current user's crontab:

```bash
crontab -r
```

Check whether cron is running:

```bash
systemctl status cron
```

Start or restart the cron service:

```bash
sudo systemctl restart cron
```

## Cron Schedule Format

Cron uses five fields to determine when a scheduled task executes.

```text
* * * * * command
│ │ │ │ │
│ │ │ │ └── Day of week (0-7)
│ │ │ └──── Month (1-12)
│ │ └────── Day of month (1-31)
│ └──────── Hour (0-23)
└────────── Minute (0-59)
```

### Common Schedules

| Schedule | Description |
|---|---|
| `*/5 * * * *` | Every 5 minutes |
| `0 * * * *` | Every hour |
| `0 */6 * * *` | Every 6 hours |
| `0 0 * * *` | Daily at midnight |
| `0 0 * * 0` | Every Sunday |
| `0 0 1 * *` | First day of each month |
| `@reboot` | At system startup |

## Cron Persistence Locations

### User-Level

```text
/var/spool/cron/crontabs/
/var/spool/cron/
```

Inspect user-level scheduled tasks:

```bash
crontab -l
```

### System-Level

```text
/etc/crontab
/etc/cron.d/
/etc/cron.hourly/
/etc/cron.daily/
/etc/cron.weekly/
/etc/cron.monthly/
/etc/anacrontab
```

These locations should be included in Linux persistence investigations.

## Common Persistence Techniques

The following are common behaviors to understand during security assessments.

### 1. User Crontab Persistence

An attacker with access to a user account may attempt to add scheduled commands to that account's crontab.

Investigate unexpected entries and commands that execute scripts from temporary directories.

### 2. System-Wide Cron Persistence

An attacker with sufficient privileges may modify system-level cron configurations.

Review:

- `/etc/crontab`
- `/etc/cron.d/`
- `/etc/cron.hourly/`
- `/etc/cron.daily/`

### 3. Temporary Directory Execution

Unexpected scripts executing from the following locations can indicate suspicious activity:

```text
/tmp/
/var/tmp/
/dev/shm/
```

### 4. Suspicious Download-and-Execute Behavior

Investigate scheduled tasks that download remote scripts or execute dynamically retrieved commands.

Pay particular attention to unexpected usage of:

```text
curl
wget
bash
sh
python
perl
nc
```

These utilities are legitimate administration tools, but their presence in unexpected scheduled tasks deserves investigation.

## Systemd Timer Persistence

Systemd timers provide another way to schedule recurring tasks.

Inspect active timers:

```bash
systemctl list-timers --all
```

Inspect timer units:

```bash
find /etc/systemd/system/ -name "*.timer"
```

Inspect service units:

```bash
find /etc/systemd/system/ -name "*.service"
```

Review unfamiliar services and timers for unexpected execution paths.

## Detection and Monitoring

### 1. Inspect Cron Entries

```bash
crontab -l
```

Inspect system-wide configuration:

```bash
sudo cat /etc/crontab
sudo ls -la /etc/cron.d/
```

### 2. Search for Suspicious Commands

```bash
sudo grep -RniE \
'curl|wget|nc|netcat|python|perl|bash' \
/etc/cron* /var/spool/cron/ 2>/dev/null
```

Note: This is a basic indicator search, not a definitive malware detector.

### 3. Monitor Cron Processes

```bash
ps aux | grep -E '[c]ron|[C]RON'
```

### 4. Inspect Cron Logs

Debian-based systems:

```bash
sudo grep -i cron /var/log/syslog
```

Follow logs in real time:

```bash
sudo journalctl -u cron -f
```

### 5. Monitor Cron Configuration Changes

Install inotify-tools:

```bash
sudo apt install inotify-tools
```

Monitor cron directories:

```bash
sudo inotifywait -m -r \
-e create,modify,delete,move \
/etc/cron.d/ /var/spool/cron/
```

## Forensic Investigation

When investigating suspected cron persistence, collect evidence before modifying the system.

### Identify Cron Files

```bash
sudo find /etc/cron* /var/spool/cron/ \
-type f -ls 2>/dev/null
```

### Inspect File Timestamps

```bash
sudo stat /etc/crontab
```

### Identify Unexpected Executables

```bash
sudo find /tmp /var/tmp /dev/shm \
-type f -executable -ls 2>/dev/null
```

### Inspect Running Processes

```bash
ps auxf
```

### Review System Logs

```bash
sudo journalctl --since "24 hours ago"
```

Correlate file modification times, process execution, cron logs, and user authentication events.

## Cleanup and Removal

If unauthorized cron persistence is identified:

1. Preserve relevant logs and evidence.
2. Identify the affected user or system configuration.
3. Determine which scheduled task is unauthorized.
4. Investigate the associated script or executable.
5. Remove the unauthorized entry after preserving evidence.
6. Check for additional persistence mechanisms.
7. Rotate potentially compromised credentials.
8. Verify that the system is no longer executing unauthorized tasks.

**Important:** Avoid blindly deleting all hidden files or removing entire crontabs. Legitimate system tasks may be affected.

## Linux Hardening

Recommended defensive practices:

- Restrict access to cron using `/etc/cron.allow` and `/etc/cron.deny`.
- Limit administrative privileges.
- Monitor modifications to cron directories.
- Enable centralized system logging.
- Use file integrity monitoring such as AIDE.
- Review systemd timers periodically.
- Monitor unexpected network connections.
- Keep the operating system and installed packages updated.
- Investigate scripts executing from temporary directories.

### Cron Access Restrictions

Example:

```bash
sudo nano /etc/cron.allow
```

Add authorized users, one per line.

Set appropriate permissions:

```bash
sudo chmod 600 /etc/cron.allow
```

Verify your distribution's cron access-control behavior before applying restrictions.

## References

- [MITRE ATT&CK – Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [MITRE ATT&CK – Cron](https://attack.mitre.org/techniques/T1053/003/)
- [MITRE ATT&CK – Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [Linux Cron Manual](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [Systemd Timer Documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html)

---

**Disclaimer:** This documentation is intended for authorized security research, defensive security operations, penetration testing, and educational purposes. Only investigate systems you own or have explicit authorization to assess.
