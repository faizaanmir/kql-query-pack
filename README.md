# KQL Query Pack — Microsoft Sentinel & Defender XDR

A curated collection of KQL (Kusto Query Language) queries for threat detection, threat hunting, and incident investigation. Organized by MITRE ATT&CK tactic.

All queries are tested against Microsoft Sentinel and/or Microsoft Defender XDR Advanced Hunting schemas. Sanitized — no production or client data.

---

## Structure

```
kql-query-pack/
├── identity/              # TA0006 - Credential Access, TA0005 - Defense Evasion
├── endpoint/              # TA0002 - Execution, TA0003 - Persistence, TA0004 - Privilege Escalation
├── email/                 # TA0001 - Initial Access (Phishing)
├── lateral-movement/      # TA0008 - Lateral Movement
├── persistence/           # TA0003 - Persistence
└── exfiltration/          # TA0010 - Exfiltration
```

---

## Schema Reference

| Query Folder | Primary Table (Sentinel) | Primary Table (Defender XDR) |
|---|---|---|
| identity | SigninLogs, AADNonInteractiveUserSignInLogs | IdentityLogonEvents |
| endpoint | SecurityEvent, Sysmon | DeviceProcessEvents, DeviceFileEvents |
| email | EmailEvents (Defender for O365) | EmailEvents |
| lateral-movement | SecurityEvent | DeviceLogonEvents, IdentityLogonEvents |
| persistence | SecurityEvent, AuditLogs | DeviceRegistryEvents, DeviceScheduledTaskEvents |
| exfiltration | DnsEvents, CommonSecurityLog | DeviceNetworkEvents |

---

## Usage

Each `.kql` file contains:
- **Description** — What the query detects and why it matters
- **MITRE ATT&CK Mapping** — Tactic and Technique ID
- **Data Source** — Table(s) used
- **Query** — The KQL
- **Tuning Notes** — False positive guidance and threshold suggestions

---

## Queries Index

### Identity
| File | Technique | Description |
|---|---|---|
| `identity/ntlm-brute-force.kql` | T1110.002 | Detects NTLM password spray from a single source |
| `identity/dcsync-detection.kql` | T1003.006 | Detects DCSync replication requests from non-DC hosts |
| `identity/impossible-travel.kql` | T1078 | Flags logins from geographically impossible locations |
| `identity/mfa-fatigue.kql` | T1621 | Detects repeated MFA push attempts (fatigue attack pattern) |

### Endpoint
| File | Technique | Description |
|---|---|---|
| `endpoint/lolbas-execution.kql` | T1218 | Detects common LOLBAS (Living off the Land Binary) abuse |
| `endpoint/powershell-encoded-commands.kql` | T1059.001 | Flags PowerShell with encoded/obfuscated command strings |
| `endpoint/hta-file-execution.kql` | T1218.005 | Detects mshta.exe executing HTA files from suspicious paths |
| `endpoint/scheduled-task-creation.kql` | T1053.005 | Detects scheduled task creation via command line |

### Email
| File | Technique | Description |
|---|---|---|
| `email/phishing-url-click.kql` | T1566.002 | Users who clicked URLs in emails flagged as phishing |
| `email/attachment-malware-delivery.kql` | T1566.001 | Email delivery of known-malicious attachment types |

### Lateral Movement
| File | Technique | Description |
|---|---|---|
| `lateral-movement/pass-the-hash.kql` | T1550.002 | Detects Pass-the-Hash via NTLM logon type 3 anomalies |
| `lateral-movement/smb-lateral-movement.kql` | T1021.002 | Lateral movement via SMB to multiple internal hosts |

---

## Contributing / Adapting

These queries are starting points. Tune thresholds and allowlists to your environment before using in production.

---

*Author: Faizaan Sajjad | Orange Cyber Defense*  
*All data in examples is synthetic.*
