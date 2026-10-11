# KQL Query Catalog

`report-01`–`report-10` are the hunts from the final report, in report order. Each one is followed in the report by the rows it returned in the exported results. `login-origins.kql` drives the Sentinel map workbook.

| File | Report § | Table(s) | Purpose |
| --- | --- | --- | --- |
| report-01.kql | 1 | MySQLAudit_CL | Destructive statements and ransom-note markers |
| report-02.kql | 2 | DeviceLogonEvents | Host/account logon context |
| report-03.kql | 3 | MySQLAudit_CL | Classify the attack burst: data reads vs. destruction |
| report-04.kql | 3 | NTANetAnalytics | Bytes VM → attacker (exfiltration check) |
| report-05.kql | 4 | DeviceLogonEvents, DeviceNetworkEvents, MySQLAudit_CL | IOC sweep (16 IPs + ransom strings) |
| report-06.kql | 5 | MySQLAudit_CL | Incident timeline: connects, privilege and destructive statements |
| report-07.kql | 6 | AzureActivity | NSG rule changes (exposure) |
| report-08.kql | 6 | DeviceLogonEvents | Windows failures/successes per public source IP |
| report-09.kql | 7 | DeviceRegistryEvents, DeviceEvents, DeviceProcessEvents | Persistence during the `administrator` sessions |
| report-10.kql | 9 | MySQLAudit_CL | Draft analytic: destructive/ransom SQL from a public source |
| login-origins.kql | — | DeviceLogonEvents | Geo-enriched public logon origins for the workbook map |

## Notes

- **Host scoping:** every MySQL query filters on `_ResourceId has "corp-nao1-lreed"`, so it is safe to run in a shared workspace. `report-10` joins on `_ResourceId` + `ThreadId`.
- **Thread IDs:** MySQL thread IDs restart when the server restarts. Review joined rows by time as well as thread.
- **UTC windows:** time windows are fixed to the incident in UTC, except `login-origins.kql` and `report-10`, which use rolling windows.
- **Validation:** these are investigation hunts. `report-10` is a draft detection; tune its thresholds and suppression before deploying it.
- **Map coverage:** `RemoteIPType == "Public"` drops private and unresolved sources, so one RDP session logged from `0.0.0.0` does not plot.
