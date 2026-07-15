# Graph API Error Finder

A PowerShell diagnostic script that gathers hard evidence about how Microsoft Graph and the Intune reports
Export API actually behave in your tenant: pagination, throttling, retries, page-size failures, export-job
latency, and silent data loss. The output is designed to be attached to a Microsoft Support case.

Published by **PowerStacks** for **BI for Intune** customers, and for anyone integrating with Intune Graph
endpoints who needs to prove what is going wrong rather than describe it.

> **Use this when:** your Intune sync is slow, intermittently failing, returning HTTP 429/500/502/503/504,
> or quietly returning less data than it should, and you need reproducible evidence for Microsoft.

**Current version: 4.5.1.** The script's `.NOTES` block carries the full version history, including the
field observations behind each change. That is the authoritative changelog; this README describes what the
script does today.

---

## What the script does

It authenticates as a service principal and runs two families of diagnostics.

### 1. Paged Graph collection endpoints

Exercises the endpoints BI for Intune reads, at production shape and page size:

| Endpoint | What it exercises |
|---|---|
| `deviceAppManagement/mobileApps` | `$expand=assignments,categories` at production page size, plus isolation variants (assignments only, categories only, no expand, and the proposed fix shape) to separate payload composition from page size |
| `deviceManagement/deviceManagementScripts` | Platform scripts with `assignments` expanded |
| `deviceManagement/deviceHealthScripts` | Proactive remediations with `assignments` expanded |

For each page it records HTTP status, per-attempt and per-page timing, `Retry-After` handling, backoff, and
retry counts. Two behaviors get special handling:

- **Adaptive page size.** On timeout-class failures the script halves `$top` and retries immediately (no
  backoff, because a smaller request is a different request, not a transient one). After 3 consecutive pages
  need reduction it rides at the reduced size instead of relearning the same failure on every page. This is
  configurable, including a pure evidence mode that retries every page at full size to maximize
  fail/succeed pairs for escalation.
- **Problems (HTTP 200, but wrong).** A page that returns fewer rows than `$top` **and** carries an
  `@odata.nextLink` is recorded as a small-result-set anomaly: Graph claims more data exists while handing
  back a partial page, which silently breaks any consumer that treats `count < $top` as end-of-data. The
  detector runs against every paged call, so new endpoints exhibiting it are caught automatically.

### 2. Intune reports Export API

Exercises `deviceManagement/reports/exportJobs`, the pipeline BI for Intune's compliance reporting uses:
job creation, queue and processing latency, download, and CSV row validation. It flags stuck jobs, failed
jobs, and jobs that complete but return the wrong number of rows.

It also reproduces the silent-incomplete-data pattern directly: an **unfiltered baseline export** is
compared against **per-ID filtered exports** (the production access pattern). Because a live tenant drifts
while the jobs run, the baseline is **bracketed**: a second unfiltered export runs after the filtered jobs,
and a mismatch is only reported as deterministic when the filtered count falls outside *both* baselines.
Drift-consistent mismatches are recorded separately rather than reported as data loss.

### Remediation run states

`deviceRunStates` is the largest dataset in this family (hundreds of scripts across tens of thousands of
devices), and its export report requires a `PolicyId` filter, so no bulk ground truth exists. The script
therefore tests three witnesses per sampled script: the filtered export, the paged endpoint, and the
script's own `runSummary` counters. Export versus paged is the hard comparison, and disagreement is flagged.

### Optional scale test

`$doScaleTest = $True` queries `/assignments` for every item individually, capturing per-item response
times, assignment counts, "All Devices" / "All Users" scope flags, and the slowest items. Useful for showing
whether one noisy item is causing backend pressure. It is slow, and off by default.

---

## Output

Everything lands in `$LogDir` (default `C:\Temp`), timestamped per run:

| File | Contents |
|---|---|
| `GraphDiag_<ts>.log` | The run log, in **CMTrace format**: millisecond timestamps, severity types, and bias, so failures and warnings colour-code in CMTrace. Open it with CMTrace or any text editor. |
| `RetryEvents_<ts>.csv` | Every retry: endpoint, page, attempt, HTTP status, wait, request id, and the scale unit that served it |
| `Problems_<ts>.csv` | Every small-result-set anomaly and other 200-but-wrong finding |
| `ExportDiagnostic_<ts>.csv` | Export job lifecycle and the baseline-vs-filtered reconciliation |
| `ScaleDiagnostic_<ts>.csv` | Per-item assignment data (only when `$doScaleTest` is on) |

The run ends with a **verdict-first summary**: an Overall line (areas failed or warned, problem/retry
counts), then one `[PASS]` / `[WARN]` / `[FAIL]` line per diagnostic area with the single fact behind it,
then problem counts by type. The detailed tables follow under a `DETAIL` divider as drill-down.

### Traceability

Every request carries a generated `client-request-id`, and Graph is asked to echo it back, so even failures
with no response (client timeouts, dropped connections) remain traceable. Every failed response's
`x-ms-ags-diagnostic` is parsed for the **scale unit** that served that specific request, and recorded in the
retry CSV. Note this identifies the Graph front-end gateway node, which varies per request by load
balancing. It is not your tenant's home scale unit (the Intune console's "Tenant location"), which is worth
recording separately when comparing across tenants.

---

## Prerequisites

- **PowerShell 5.1 or 7+.** No external modules: `Invoke-RestMethod` and standard cmdlets only.
- **An Entra ID app registration** using client-credentials auth, with these **application** permissions
  granted admin consent:

| Permission | Why |
|---|---|
| `DeviceManagementApps.Read.All` | Mobile apps and their assignments |
| `DeviceManagementConfiguration.Read.All` | Platform scripts, compliance policies, export reports |
| `DeviceManagementManagedDevices.Read.All` | Proactive remediations, device run states, device reports |

> If you already run BI for Intune, its existing app registration typically has these and can be reused.
> Check with your administrator first.

---

## Running it

`TenantId` and `ClientId` have in-file defaults and can be overridden per run. The secret is never stored in
the script:

```powershell
# Prompted for the secret (hidden input)
.\"Graph API Error Finder.ps1" -TenantId <tenant-guid> -ClientId <app-id>

# Or from the environment
$env:GRAPH_DIAG_SECRET = 'paste-secret-here'
.\"Graph API Error Finder.ps1"

# Or passed explicitly (avoid: it lands in your shell history)
.\"Graph API Error Finder.ps1" -ClientSecret '<secret>'
```

Runtime depends heavily on which diagnostics are enabled and on tenant size. The paged passes are minutes.
The export comparison submits one job per distinct key value and can run considerably longer, which is why
export jobs are batched (see `$ExportJobConcurrency`).

---

## Configuration

Set these in the **Configuration** region near the top of the script.

### Core

| Setting | Default | Purpose |
|---|---|---|
| `$PageSize` | `50` | Default `$top` for paged endpoints |
| `$MaxRetries` | `3` | Per-page retry ceiling |
| `$TimeoutSec` | `60` | Per-request timeout |
| `$LogDir` | `C:\Temp` | Where the log and CSV artifacts are written |

### Adaptive page size

| Setting | Default | Purpose |
|---|---|---|
| `$ReduceTopOnTimeout` | `$true` | Halve `$top` on timeout-class failures |
| `$MinTop` | `5` | Floor for reduction |
| `$AdaptiveStickyThreshold` | `3` | Consecutive reduced pages before riding at the reduced size. `0` = pure evidence mode (retry every page at full size) |
| `$AdaptiveProbeInterval` | `0` | `0` = never retry full size once it is known to fail. Set to e.g. `20` to periodically probe and recover if the service heals mid-run |

### Diagnostic toggles

| Setting | Default | Purpose |
|---|---|---|
| `$doVariantTest` | `$True` | Re-collect variant `$expand` shapes to isolate payload composition from page size |
| `$doExportTest` | `$True` | Exercise the reports Export API |
| `$doExportComparison` | `$True` | Unfiltered baseline vs per-ID filtered exports |
| `$doRemediationTest` | `$True` | Remediation run-state three-witness comparison |
| `$doScaleTest` | `$False` | Per-item assignment diagnostic (slow) |

### Export and comparison

| Setting | Default | Purpose |
|---|---|---|
| `$ExportJobConcurrency` | `5` | Export jobs in flight at once. Raise cautiously: export job creation is tenant-throttled |
| `$ExportPollIntervalSec` | `10` | Seconds between job status polls |
| `$ExportPollTimeoutSec` | `900` | Give up and flag `ExportJobStuck` |
| `$ComparisonReport` | `DevicePolicySettingsComplianceReportV3` | Report the comparison runs against |
| `$ComparisonKeyColumn` | `PolicyId` | Column the comparison keys on. Must match production's filter |
| `$ComparisonMaxSettings` | `0` | `0` = every distinct key value; `N` = top-N by row count (quick runs) |
| `$ComparisonBracketBaseline` | `$True` | Second baseline after the filtered jobs, so drift is not misreported as data loss |
| `$ComparisonRetestMismatches` | `$True` | Re-run each mismatched filtered job once |

### Remediation

| Setting | Default | Purpose |
|---|---|---|
| `$RemediationSampleCount` | `5` | Scripts to test, ranked by device count. `0` = all (expect hours) |
| `$RemediationPagedPageCap` | `400` | Max paged pages per script (~40k rows) |
| `$RemediationPagedTop` | `100` | `$top` for paged run states. Note the Intune console itself pages this data at 40 |

---

## What to send Microsoft Support

Attach `GraphDiag_<ts>.log` plus the CSV artifacts. They are already in the shape a support engineer wants:

- The verdict summary states what failed and why, in one line per area.
- `RetryEvents.csv` gives every failure with status, timing, request id, and serving scale unit.
- `Problems.csv` is the concrete evidence of 200-but-incomplete responses: endpoint, page, exact URL,
  expected rows, actual rows, and the `nextLink` Graph returned alongside the short page.
- `ExportDiagnostic.csv` shows the baseline-vs-filtered reconciliation, including which mismatches are
  deterministic and which are drift.

The log contains your tenant ID and app registration object ID, which is normally fine for a support case.
It does not log secrets. Scan before sharing if you have local policy about it.

---

## Notes on behavior worth knowing

- **Read-only.** Only `GET` requests against Graph, plus `POST` to create export jobs (which create a report
  export, not a tenant change). Nothing in your tenant is modified.
- **Console QuickEdit is disabled at startup** (Windows only). Selecting text in a console window blocks
  writes and will freeze a long run. The script turns QuickEdit off for the session, and writes to the log
  file before the console, so if output ever blocks again the log still advances with true progress. If the
  file is ahead of the screen, the console is frozen, not the script.
- **Paged passes run sequentially by design.** Their product is timing and failure-rate measurement, so
  running them concurrently would contaminate the numbers. Only export jobs are batched.

---

## Security

- Never commit a client secret. Prefer the prompt or `$env:GRAPH_DIAG_SECRET` over `-ClientSecret`.
- Rotate the secret after the support case closes. Treat any secret pasted into a file as compromised.
- Keep the app registration read-only, and remove it when you are done diagnosing.
- Network access is limited to `login.microsoftonline.com` and `graph.microsoft.com`.

---

## License

[MIT](LICENSE)

## Maintainer

Maintained by **PowerStacks**. Issues and pull requests welcome on the [issue tracker](../../issues).
