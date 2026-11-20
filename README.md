# SecSweep

Read-only security sweep for one Windows box. Eleven domains in a single pass, HTML and JSON out, nothing leaves the machine.

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
| `-Fix` | list reversible fixes. Dry run only, nothing is applied |

## A real run

On a 1-core Server 2019 VM, stock desktop apps installed: 82/B, 14 findings, 16 seconds.

Nearly all of them were noise from ordinary consumer software — a leftover Epic Games launcher entry for a program already uninstalled, a Douyin guard process running out of `Desktop\`. That is the point of the thing. A generic scanner would have produced a hundred more and buried them.

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
src/lib/report.ps1      scoring, masking, HTML
src/checks/*.ps1        one file per domain, function Invoke-Check<Domain>
rules/rules.json        rule definitions: id, severity, zh/en copy, reversible
rules/whitelist.json    generic noise
rules/whitelist.local.json   your noise (gitignored)
lang/*.json             language packs
```

## Adding a language

Copy `lang/en-US.json`, translate the values, change `meta.code`. That covers the interface and the section headings.

Rule text is separate — `rules/rules.json` carries a `zh` and `en` field per rule. A third language needs a new field on every `title`/`why`/`fix` plus one more `data-xx` attribute in `New-FindingRow`. Two places, they have to move together.
