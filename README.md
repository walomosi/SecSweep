# SecSweep

Read-only security sweep for one Windows box. Twelve domains in a single pass, HTML and JSON out, nothing leaves the machine.

I built it because antivirus answers "is this file a known virus" and I kept needing the other question: has anything on this machine been quietly changed. An orphaned Run entry pointing at a nonexistent file, a service loading its exe off the desktop, 3389 bound to every interface — AV reports none of that, and those are the things that matter after someone has been in.

## Run it

```powershell
.\build.cmd
```

Or, from a shell:

```powershell
pwsh -File src\SecSweep.ps1
```

Or Ctrl+Shift+B in VS Code, which runs the default task.

Output goes to `out\` — one HTML report plus the same data as JSON. The report has a zh/en toggle in the top right; both language packs are baked into the file, so switching does not need a network.

Flags that actually matter:

| flag | effect |
| --- | --- |
| `-Lang zh-CN` / `en-US` / `auto` | report language; `auto` follows system culture |
| `-Domains accounts,services` | run a subset |
| `-SaveBaseline` | snapshot accounts / Run keys / services / listening ports, then exit |
| `-IncludeRaw` | stop masking usernames, hostname and IPs |
| `-Fix` | show the reversible fix plan with current values, nothing applied |
| `-Fix -Apply` | apply them, then write `out\undo-<stamp>.ps1` |

## A real run

On a 1-core Server 2019 VM with a few consumer apps installed: 76/B, 43 findings, 22 seconds, and 26 of 45 hardening rules triggered.

Twenty-six of those are hardening gaps: password policy never configured, SMB signing not required, LSASS unprotected, AutoRun on. The password numbers alone are worth staring at — minimum length 0, no lockout, no history, no complexity — and none of it was visible before these rules existed.

The other seventeen are actual findings, and most of those are ordinary software noise: a leftover Epic Games launcher entry for a program already uninstalled, a Douyin guard process running out of `Desktop\`. That is the point of the thing. A generic scanner would have produced a hundred more and buried them.

## Score versus hardening gaps

Two different questions, two different counters.

The score only moves for findings that describe something odd about this specific machine: a persistence entry that should not exist, a port that should not be open, a log that was cleared. The 45 hardening rules — password policy, SMB signing, RDP redirection, and so on — are reported as a separate `n/45` line and capped at six points together.

Without that split, a stock server lights up twenty-odd unset policy keys and lands in "possible compromise", which teaches the reader to stop reading the grade.

## Benchmark

`tools\benchmark.ps1` plants five techniques, scans the affected domain, and removes each one again in a `finally` block. Run it from Windows PowerShell, not pwsh 7: the WMI subscription case needs `Set-WmiInstance`.

| TTP | Technique | Rule |
|---|---|---|
| T1547.001 | Run key pointing at a missing file | PS-001 |
| T1053.005 | Scheduled task out of a writable path | PS-003 |
| T1546.003 | Permanent WMI event subscription | PS-004 |
| T1543.003 | Service binary outside System32 | SV-002 |
| T1136.001 | New local account | AC-001 |

Latest run: 5 of 5 on this box, nothing left behind.

## Whitelist: two files, deliberately

- `rules/whitelist.json` — generic Windows noise. Shipped with the repo. Edit it, but keep it small.
- `rules/whitelist.local.json` — your machine. Gitignored, never committed.

On a fresh box, start with an empty local file, run once, and add only what you have personally looked at and confirmed harmless. Copying someone else's whitelist is how you end up with a scanner that reports nothing and catches nothing.

The local file is merged on top of the shipped one at load time, so you never have to edit the tracked file.

## Privacy

Not a marketing claim here, the code is 1400 lines and you can check it:

- No outbound calls. No HTTP client, no sockets, no update check. The "external connections" check reads the local connection table; it does not send anything.
- No browser history, no chat logs, no document contents. Registry, service table, process list, file metadata.
- Masked by default: usernames become `<user>`, hostname becomes `<host>`, IPv4 keeps its first two octets. `-IncludeRaw` turns that off.
- Reports are written only under `out\`. Scan results stay in memory until the report is written.
- Credential check reads filenames and sizes, never opens a file.

## What it cannot do

- **Userland only.** A driver-level rootkit controls the process list and registry you are reading. If you suspect one, this tool will show you what the rootkit wants shown.
- **"Writable path" is a prefix guess**, not an ACL check. Checking ACLs properly means `Get-Acl` per service, which is slow enough to make the 16 seconds become minutes.
- **4625 count of zero may mean auditing is off**, not that nobody tried. There is a separate check for exactly that, but it can only tell you the setting.
- **Signature checks are slow.** They only run against processes under user directories, which is why this finishes in seconds rather than minutes.

## Layout

```
src/SecSweep.ps1        entry point
src/lib/i18n.ps1        language pack loading
src/lib/paths.ps1       shared path helpers
src/lib/report.ps1      scoring, masking, HTML
src/lib/fix.ps1         reversible fixes and undo script
src/checks/*.ps1        one file per domain, function Invoke-Check<Domain>
rules/rules.json        rule definitions: id, severity, zh/en copy, reversible
rules/whitelist.json    generic noise
rules/whitelist.local.json   your noise (gitignored)
lang/*.json             language packs
tools/benchmark.ps1     adversary simulation, one TTP at a time
```

## Adding a language

Copy `lang/en-US.json`, translate the values, change `meta.code`. That covers the interface and the section headings.

Rule text is separate — `rules/rules.json` carries a `zh` and `en` field per rule. A third language needs a new field on every `title`/`why`/`fix` plus one more `data-xx` attribute in `New-FindingRow`. Two places, they have to move together.
