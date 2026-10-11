# Evidence extracts

These are sanitized excerpts of the Advanced Hunting / Log Analytics results exported during the investigation. Each report finding cites one of these files. All times are UTC.

| File | Source table | Rows | Supports |
| --- | --- | ---: | --- |
| mysql-remote-sessions.csv | MySQLAudit_CL | 770 | Every Connect/Query from a remote (non-localhost) source |
| mysql-connects-by-ip.csv | MySQLAudit_CL | 8 | Remote MySQL sources, denied vs. accepted |
| mysql-operator-cleanup.csv | MySQLAudit_CL | 6 | Oct 10 eradication: `DROP USER 'root'@'%'`, ransom schema removal |
| windows-public-logons-by-ip.csv | DeviceLogonEvents | 8 | Public-IP logon attempts per source (matches the workbook) |
| windows-administrator-successes.csv | DeviceLogonEvents | 11 | Each successful `administrator` logon |
| azure-nsg-rule-changes.csv | AzureActivity | 3 | NSG rule created, widened, deleted |
| ioc-sweep.csv | 3 tables | 24 | Hits per IOC, including 0 hits for the task-sheet 28T2 set |

**Removed:** Azure subscription IDs, tenant IDs, caller identities and MySQL password hashes (the general log already shows `IDENTIFIED BY <secret>`). Attacker IPs and ransom-note IOCs are kept on purpose; the URL and email appear defanged in the report.

**Not included:** the full raw exports (about 300 MB) and the MDE investigation packages.
