# conmon-kit

The monthly continuous monitoring run for a FedRAMP, GovRAMP (formerly StateRAMP) or similar authorization, built
on free scanners. One command scans, then writes the three files a monthly package needs: every raw finding as CSV,
a summary report, and a POA&M that carries forward from last month's.

```
$ conmon scan ~/private/evidence --config conmon.json
/Users/you/private/evidence/2026-11: scan-results-2026-11-15.csv, scan-summary-2026-11-15.md, poam-2026-11-15.csv
POA&M: 1 high, 4 moderate, 1 low open; 3 closed
```

## Why

A small team going through an authorization runs the same scans every month, then hand-copies the findings into a
spreadsheet. The spreadsheet is where it goes wrong:

- **Deadlines reset.** A weakness found in October and still open in December is due 30, 90 or 180 days after
  *October*. Copy-paste turns it into a new December item and the clock restarts. Here every item keeps its POA&M ID
  and first detection date for as long as it is open.
- **Missing scans look like fixes.** If the web scanner did not run this month, its findings vanish from a
  hand-built list. Here an item closes only when the scanner that found it ran again and no longer finds it.
  Otherwise it stays open as last reported.
- **Gaps in coverage go unnoticed.** Assessors reject a month whose scans skipped a boundary component or ran signed
  out. The kit matches every scan to your boundary inventory. An asset with no source scan, a web application
  scanned without signing in, or an administrator workstation that was not checked becomes a POA&M item itself.
- **CDN addresses churn.** A TLS scan behind a CDN reaches a different IP address each month. TLS findings are keyed
  by host, so they keep their ID.

## What it runs

Each scanner runs only if it is installed and named in your config. A scanner that cannot run leaves a
`<scanner>-<date>.skipped` file saying why, and the summary lists it.

| Scanner | Output | Controls it supports |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) on each source folder | `trivy-<component>-<date>.json` | RA-5, SI-2 (vulnerabilities, secrets, misconfiguration) |
| [nuclei](https://github.com/projectdiscovery/nuclei) on your web app | `nuclei-<date>.jsonl` and `.auth` | RA-5, RA-5(5) |
| [testssl.sh](https://github.com/testssl/testssl.sh) | `testssl-<date>.json` and `.csv` | SC-8, SC-13 |
| GitHub Dependabot alerts (through `gh`) | `dependabot-<date>.json` | RA-5, SI-2 |
| Security headers | `headers-<date>.txt` | SC-8, CM-6 |
| The administrator workstation (macOS or Linux) | `workstation-<date>.txt` | CM-6, SC-28, SI-2 |
| Cloudflare account and zone baseline (optional) | `check-cloudflare-<date>.json` and `.csv` | IA-2(1), AC-2(7), SC-7, SC-8, SC-21, CM-6 |
| Cloudflare inventory against bindings and routes (optional) | `check-cloudflare-inventory-<date>.json` | CM-8 |
| Code your Cloudflare Workers actually run (optional) | `deployed-code-<date>.json`, `trivy-deployed-<worker>-<date>.json` | RA-5, CM-2, SI-7 |

The web scan uses every nuclei template except denial-of-service and intrusive ones, at 10 requests a second. Set
`SCAN_COOKIE` to the Cookie header of a dedicated scan account and it runs signed in. The cookie goes only to the
scanner, never into the evidence.

Scanner, engine and signature versions are updated and recorded first, in `scanner-versions-<date>.txt`, so the
evidence says what each scan knew.

## The three reports

- **`poam-<date>.csv`**, with the columns POA&M ID, Controls, Weakness Name, Weakness Description, Weakness Detector
  Source, Weakness Source Identifier (CVE, GHSA or template ID), Asset Identifier, Point of Contact, Original
  Detection Date, Original Risk Rating, Scheduled Completion Date, Overall Remediation Plan, Status, Status Date and
  Boundary. Findings outside your boundary, such as Dependabot alerts in another product's folder, are listed as
  "Outside boundary" so they stay visible without counting against the system. Copy the rows into your program's
  POA&M template.
- **`scan-summary-<date>.md`**: an executive summary (findings by source and risk), a detailed summary and an
  inventory report showing which scans covered each asset.
- **`scan-results-<date>.csv`**: every raw Trivy, nuclei and Dependabot finding in one CSV, for assessors who want
  raw results in CSV or Excel.

A gap assessment in Markdown can feed the POA&M too: any table row whose status is not **Met** becomes an item, with
priority P1 as high risk, P2 moderate and P3 low ([example](examples/gap-assessment.example.md)).

## Usage

```
conmon scan <evidence-dir> [--config conmon.json]
conmon report <month-dir> [--config conmon.json] [--today YYYY-MM-DD]
```

`scan` writes into `<evidence-dir>/<YYYY-MM>/`. `report` rebuilds the reports from the files already in a month folder,
for example after you re-run one scanner by hand. Run it again the same day after a fix and the IDs stay the same.

Run it without installing: `npx github:mthburnsbarber-web/conmon-kit scan <evidence-dir> --config conmon.json`.

Copy [`conmon.example.json`](conmon.example.json) and [`inventory.example.json`](inventory.example.json) and edit them:

- `system`, `organization`, `pointOfContact`, `idPrefix`: what the reports say.
- `deadlines`: days to fix by risk. The default is high 30, moderate 90 and low 180.
- `boundaryPaths`: path prefixes inside your boundary, for Dependabot alerts in a monorepo.
- `scans`: what to run. Paths are relative to the config file. `scans.nuclei.tags` limits the web scan to some
  template tags, for a quick test run.
- `inventory`: your boundary, with the same IDs as your SSP inventory. `source` names the Trivy component that
  scans an asset's code, `worker` its Cloudflare Worker, and `url` its web scan target. Managed data services with no
  operating system or database engine you can scan are `managed`. The summary marks them for a scan exception
  request.

Cloudflare checks need `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Use a read-only token: every call is a
GET. Member emails are masked in the results.

Schedule it monthly with [launchd](examples/com.example.conmon.plist) or [cron](examples/crontab.txt). Keep the
evidence folder out of your code repository, because it names hosts and weaknesses.

Your own checks can feed the POA&M too. Write `check-<name>-<date>.json` into the month folder:

```json
{ "source": "Backup check", "rows": [{ "control": "CP-9", "check": "Nightly database export", "expected": "present", "actual": "missing since 2026-11-20", "pass": "FAIL", "risk": "High", "asset": "backups" }] }
```

Zero dependencies beyond the scanners themselves. Plain Node 20+.

## What it doesn't do

- It does not make you compliant or replace an assessor. It produces evidence and a POA&M; people still fix things
  and sign off.
- It does not run intrusive or denial-of-service tests. Run those against a copy of the system with its own data.
- It does not fill your program's spreadsheet template. The CSV columns are named so the copy is mechanical.

## License

MIT
