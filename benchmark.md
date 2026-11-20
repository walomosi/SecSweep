# Detection benchmark

Run 2026-11-21 02:14 on 0BEEBFDD-VDUXLB

Each technique is planted, scanned, then removed. A miss means the rule set did not
see it, not that the plant failed.

| TTP | Technique | Domain | Expected | Detected |
|---|---|---|---|---|
| T1547.001 | Registry Run key | persistence | PS-001 | yes |
| T1053.005 | Scheduled task from a writable path | persistence | PS-003 | yes |
| T1546.003 | WMI event subscription | persistence | PS-004 | yes |
| T1543.003 | Service from a writable path | services | SV-002 | yes |
| T1136.001 | Local account creation | accounts | AC-001 | yes |

Detected 5 of 5.
