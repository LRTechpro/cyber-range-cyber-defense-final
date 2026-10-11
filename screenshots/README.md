# Screenshots

Captured from the Microsoft Defender portal during the investigation. Browser chrome is cropped; telemetry values are unaltered.

| File | Shows | Used in |
| --- | --- | --- |
| 01-login-origins-workbook.png | Sentinel workbook: 10-day map + source-IP table, 8 IPs / 200 logons (9 success, 191 failed) | Report Figure 2 (§6) |
| 02-advanced-hunting-results.png | Advanced Hunting run of the login-origin query, 8 result rows | Report Figure 1 (§2) |
| 03-map-coordinate-settings.png | Workbook map settings: latitude, longitude, size = attempts | Workbook build |
| 04-workbook-query-results.png | Workbook query step returning coordinates and counts | Workbook build |

The counts in 01 and 02 match the `DeviceLogonEvents` export exactly ([evidence/windows-public-logons-by-ip.csv](../evidence/windows-public-logons-by-ip.csv)).
