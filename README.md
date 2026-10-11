# Cyber Range – Cyber Defense Final Investigation

**Analyst:** Harold L.R. Watkins · **Course:** The Cyber Range (Josh Madakor) — Cyber Defense Final · **Date:** October 2026
**Stack:** Microsoft Defender for Endpoint (Advanced Hunting), Microsoft Sentinel / Log Analytics, KQL, Azure NSG / AzureActivity, MySQL 8.0 general log

This is an end-to-end investigation of a compromised lab VM, `corp-nao1-lreed`, written up as an incident report and a host DFIR report. It also includes the KQL I used, a Sentinel workbook that maps login origins, and supporting telemetry extracts.

**[Read the final report (PDF)](reports/cyber-defense-final-report.pdf)** · [DOCX](reports/cyber-defense-final-report.docx) · [searchable text](reports/report-text.md)

![Sentinel workbook — VM login origins, last 10 days](screenshots/01-login-origins-workbook.png)

## What happened

| | Finding | Evidence |
| --- | --- | --- |
| **Initial access** | Oct 9, 04:01 UTC: 64.89.163.94 logged in to the internet-reachable MySQL server as `root` on its second attempt, after one empty-password probe. | [mysql-connects-by-ip.csv](evidence/mysql-connects-by-ip.csv) |
| **Actions** | In 100 seconds the attacker made 19 `LIMIT 10` sample reads across 17 tables, dropped the `sakila` and `world` databases, and left a `RECOVER_YOUR_DATA` ransom note (0.0103 BTC, DATAID 27JC). It then ran `RESET MASTER` / `PURGE BINARY LOGS`, `REVOKE` and `SHUTDOWN`. | [mysql-remote-sessions.csv](evidence/mysql-remote-sessions.csv) |
| **Exfiltration claim** | The note claims a full backup. The logs show only 10-row samples, and NTANetAnalytics shows about 472 KB sent to the attacker IP. Bulk theft is not supported by the evidence. | Report §3 |
| **Windows logons** | 8 public IPs generated 200 public-IP login events (9 successes, 191 failures). All successes were against the decoy local account `administrator`. No process, persistence or file activity attributable to those sessions was identified in the reviewed exports. | [windows-public-logons-by-ip.csv](evidence/windows-public-logons-by-ip.csv) |
| **Root cause** | An operator-created `root`@`%` superuser combined with an NSG rule widened to all ports, and the Windows Firewall was already off. | [azure-nsg-rule-changes.csv](evidence/azure-nsg-rule-changes.csv) |
| **Containment** | NSG rule deleted Oct 9 at 22:24 UTC. Later inbound 3306 traffic shows as **Denied**. `root`@`%` was dropped Oct 10. | Report §7 |

Severity: **High**, for privileged access, irreversible deletion and log destruction. All data was synthetic lab data.

## MDE investigation-package comparison

I diffed two Microsoft Defender for Endpoint live-response packages from the same host. The baseline was collected Oct 7 at 00:21 UTC and the comparison Oct 8 at 23:07 UTC. I compared autoruns, services, tasks, processes, network, local groups, prefetch and the full Security.evtx.

- **Verdict:** no compromise indicators in that window (high confidence). Every change traces to operator activity, updates, reboots or the collection tool itself.
- **Key caveat:** both packages predate the Oct 9 attack, so no compromise indicators were identified in those captures; they cannot establish what happened afterward.
- **Notable delta:** Windows Firewall disabled on all profiles (4950 events). It lines up with the operator's lab setup three minutes before the NSG rule was created.
- **Forensic detail:** both Security.evtx files had stale headers (chunk count 311–315 vs 321 on disk). Header-trusting parsers lose about a day of events, so I carved the chunks directly.

## IOC reconciliation

The task sheet supplied a different IOC set: wallet `bc1qk9kv…`, `ak+28t2@…`, `2no[.]co/2mysql`, DATAID 28T2. Searching every export and both MDE packages returned **0 hits**. The same wallet and URL appear in the course's sample report for a different host, so they are course reference values, not IOCs of this host. The report uses only the log-derived 27JC set ([ioc-sweep.csv](evidence/ioc-sweep.csv)).

## Repository contents

| Path | Contents |
| --- | --- |
| [reports/](reports/) | Final incident report + host DFIR report (PDF, DOCX, Markdown text) |
| [queries/](queries/) | 11 KQL hunts — 10 from the report plus the login-origin map query ([catalog](queries/README.md)) |
| [workbooks/login-origins.template.json](workbooks/login-origins.template.json) | Sentinel workbook (map + source-IP table), workspace IDs replaced with placeholders |
| [evidence/](evidence/) | Sanitized CSV extracts of the rows each finding rests on ([notes](evidence/README.md)) |
| [screenshots/](screenshots/) | Advanced Hunting and Sentinel workbook captures ([notes](screenshots/README.md)) |

## Import the workbook

1. Replace the all-zero subscription ID and the `REPLACE_*` workspace resource-ID placeholders in the template with your Log Analytics workspace.
2. Change `corp-nao1-lreed` to your device name in both queries.
3. In Sentinel → **Workbooks** → **Add workbook** → **Edit**, open the workbook-level **Advanced Editor** (`</>` in the top toolbar). Paste the JSON into **Gallery Template**, click **Apply**, then **Done Editing** and **Save**.
4. The query uses `ago(10d)`. To reproduce this October window later, change it to a fixed UTC range.

## Skills demonstrated

- Hunting across `DeviceLogonEvents`, `DeviceNetworkEvents`, `DeviceEvents`, `DeviceRegistryEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `MySQLAudit_CL`, `AzureActivity` and `NTANetAnalytics`
- Parsing a raw MySQL general log in KQL and reconstructing attacker sessions by thread
- Separating operator lab setup from attacker activity using event-log provenance
- Differential DFIR on MDE investigation packages, including recovery of events past a stale EVTX header
- Building Sentinel map workbooks with `geo_info_from_ip_address()`
- Writing findings that state what the evidence does *not* show, including statements logged versus executed, exfiltration claims, and collection timing

## Limits

- **ATT&CK mapping clarification:** the report lists T1190 alongside valid-account access. No application exploit is demonstrated in the published evidence; treat initial access as valid-account use, with T1190 unconfirmed.
- **Connection-count interpretation:** `mysql-connects-by-ip.csv` counts connection-attempt rows excluding separate Access-denied diagnostic rows. These totals are not the number of successful authenticated sessions; correlate each thread with query activity.

- **Statements vs. results:** the MySQL general log records statements *submitted*, not their results.
- **Pre-attack captures:** both MDE packages are pre-attack, so a post-attack package would be needed to assess later host persistence.
- **Untuned queries:** these are investigation hunts. The report's §9 analytic is a draft and has not been tuned as a production detection.
- **No raw exports:** only sanitized extracts are published. Subscription IDs and caller identities are removed.

## Attribution

The lab environment, scenario and login-origin query/workbook structure come from Josh Madakor's **The Cyber Range**. The investigation, analysis, evidence extraction and report are my own work, with AI assistance for packaging and document formatting. This project contains no employer data.
