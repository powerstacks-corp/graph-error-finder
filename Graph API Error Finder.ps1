<#
.SYNOPSIS
    Graph API diagnostic script for Intune endpoints used by BI for Intune.
.DESCRIPTION
    Two diagnostic families:
    1. Paged Graph collection endpoints (mobileApps, deviceManagementScripts,
       deviceHealthScripts with $expand) — pagination, throttling, timeout,
       and silent partial-page anomaly detection.
    2. Intune reports Export API (deviceManagement/reports/exportJobs) — the
       pipeline BI for Intune uses for compliance reporting: job creation,
       queue/processing latency, download, and CSV row validation.
.NOTES
    Author  : John Marcum (PJM)
    Version : 4.5.1
    Requires: App registration with read scopes. Secret via -ClientSecret,
              $env:GRAPH_DIAG_SECRET, or hidden prompt. TenantId/ClientId
              default in-file, overridable via parameters for customer runs.

    v4.5.1 — attempt lines carry location context; comparison hardening:
      * Aborted comparisons now produce a [FAIL] verdict line instead of
        silently disappearing from the summary (observed 20260715).
      * The comparison baseline export is resubmitted once on terminal
        failure before aborting (observed: server-side 'failed' after 265s
        on a job that succeeded the previous day).
      * Every 'Attempt N succeeded/FAILED/in flight' line now identifies the
        endpoint, page, and optional caller context (e.g. 'deviceRunStates
        p224 (22300 rows so far)'). Long paged sections no longer scroll
        anonymous attempt lines.

    v4.5 — verdict-first executive summary:
      * The final summary now opens with an Overall line (areas failed/
        warned, problem/retry/refresh counts) and a VERDICTS section: one
        [PASS]/[WARN]/[FAIL] line per diagnostic area with the one-fact
        reason (worst run-state delta, deterministic mismatch count, retry
        counts). Problems-by-type counts follow; the existing tables move
        under a DETAIL divider as drill-down. [FAIL]/[WARN] render red/
        yellow in CMTrace.

    v4.4.1 — final summary honors the bracket re-verdict (drift-resolved
      mismatches no longer produce a false DISAGREE verdict; 20260714 run
      showed 35 drift-resolved mismatches wrongly reported as disagreement).

    v4.4 — single CMTrace log:
      * The twin-log design is collapsed: GraphDiag_<ts>.log IS the CMTrace-
        format log (per-line millisecond timestamps, severity types, bias).
      * Tabular evidence formerly embedded in the report log now writes to
        real CSV artifact files: RetryEvents_<ts>.csv, Problems_<ts>.csv,
        ExportDiagnostic_<ts>.csv, ScaleDiagnostic_<ts>.csv — attachable to
        the escalation package directly; paths listed at the end of the log.

    v4.3.1 — console freeze eliminated (root cause of the 'stuck' reports):
      * Field evidence: a 5m43s gap between two ADJACENT log lines, ended at
        the exact moment of Ctrl+C — the signature of Windows console
        QuickEdit: selecting text in the window blocks [Console]::WriteLine
        and freezes the whole run until the selection clears. Also explains
        ~50 unlogged minutes in the first run of this series.
      * QuickEdit is now disabled for the session at startup via
        SetConsoleMode (Windows only, silently skipped in non-console hosts).
      * Write-Log writes file and CMTrace BEFORE console, so even if output
        ever blocks again, the log files advance with true execution progress
        ('file ahead of screen' = frozen console, definitively).
      * Accounting fix: v4.2's skipped backoff waits are no longer added to
        Total page time (a failing page showed 44.6s when actual work was
        29.6s).

    v4.3 — CMTrace twin log:
      * Every Write-Log entry is additionally written to
        GraphDiag_<ts>_cmtrace.log in CMTrace format: millisecond timestamp,
        date, timezone bias, PID, and severity type per entry (3 = PROBLEM/
        FATAL/ERROR/FAILED, 2 = WARN/STICKY/CAPPED/RESCUE/MISMATCH,
        1 = info) for color-coded timeline review. Multi-line messages emit
        one CMTrace entry per line.
      * The human-readable report log is unchanged — summary tables and
        embedded CSV blocks stay intact for the escalation package.

    v4.2.3 — in-flight visibility and hang fixes:
      * Field report: run appeared "stuck" after an immediate size-reduced
        retry. Harness-verified the retry logic is correct; the silence was
        the retry request itself in flight (bounded by TimeoutSec) with no
        output until completion. Every attempt after the first now logs a
        timestamped "Attempt N in flight ($top=X)" line, so silence is
        always attributable (in-flight vs console freeze).
      * Real bug found in the audit: the token POST had no timeout (infinite
        in PS7) — a stalled mid-run token refresh could hang the script
        forever. Now bounded at 30s; failure flows into existing handling.
      * Failure log corrected to distinguish 'no response received' from
        'response carried no request-id header'.

    v4.2.2 — scale-unit terminology clarified:
      * The x-ms-ags-diagnostic ScaleUnit identifies the Graph FRONT-END
        gateway node that served an individual request — it varies per
        request/run by load balancing (observed: 007 -> 005 between runs,
        007 -> 000 mid-run) and is NOT the tenant's home ASU. The home ASU
        (Intune portal 'Tenant location', e.g. 'North America 0501') is the
        stable backend partition where tenant data lives and expands are
        assembled — record THAT per tenant for cross-tenant comparison.
        Log labels updated to prevent conflation. Observed finding stands:
        dual-expand failures occurred on multiple front-ends in one run,
        implicating the backend rather than front-end health.

    v4.2.1 — sticky is final by default:
      * $AdaptiveProbeInterval default changed 20 -> 0: after 3 consecutive
        pages fail at full size, the run logs "we know $top=N isn't working
        ... not trying it again this run" and never retries it. Set the
        interval to a positive value to probe full size periodically and
        recover mid-run if the service heals.

    v4.2 — no backoff on size-reduced retries:
      * Field observation: each failing page cost fail (15.5s) + backoff wait
        (15s) + reduced success (13s) = ~43.5s. The wait is useless when the
        retry is a DIFFERENT, smaller request — these failures are payload-
        deterministic, not transient. Size-reduced retries now fire
        immediately; backoff is kept for 429 (Retry-After) and for same-size
        retries. Failing-page cost drops from ~43.5s to ~28.5s; combined with
        v4.1 sticky, the mobileApps production pass projects ~6 min vs the
        measured 24.8 min.

    v4.1 — sticky adaptive page size with recovery probing:
      * Replaces the v2.2 restore-every-page policy, which retried every page
        at full size and relearned the same failure repeatedly (measured cost
        on the 20260714 run: 59.4s/page average vs 10.2s clean — ~5x).
      * After $AdaptiveStickyThreshold consecutive pages require reduction
        (default 3), collection rides at the reduced size instead of
        restoring. Every $AdaptiveProbeInterval pages (default 20) one page
        probes the full configured size: success resumes full size (the
        failure was transient/scale-unit health), failure walks back down via
        the normal adaptive path. Self-tuning in both directions.
      * Threshold 0 restores pure evidence mode (every page retried at full
        size — maximizes fail/succeed pairs for escalation runs).
      * Same algorithm recommended for BI for Intune's own back-off: start at
        100, halve on failure, sticky after 3 consecutive, probe every 20.

    v4.0 — server-side concurrency (single client thread):
      * Export-job sections were hours of client idle time: one job at a
        time, ~50s each, almost all of it waiting for Microsoft to build the
        CSV. Invoke-ExportJobBatch keeps $ExportJobConcurrency jobs (default
        5) in flight from a single thread — submit, poll round-robin, harvest
        completions, refill. No runspaces/threads, so token refresh, logging,
        and retry machinery work unchanged. Comparison Phase B (~412 jobs:
        ~3.5h -> ~45min) and retests are batched; remediation exports are
        batched up front and consumed as the paged passes run.
      * The paged collection passes remain sequential BY DESIGN: their
        product is timing and failure-rate measurements, and concurrent
        passes would contaminate each other's numbers.
      * Raise $ExportJobConcurrency cautiously: export job creation is
        tenant-throttled; 5 is deliberately modest.

    v3.9.1 — console-export calibration:
      * ExpectedApprox now includes the not-applicable counter (5.7% of rows
        in the tenant's console export; omitting it produced a phantom
        shortfall against both APIs). Property name probed defensively.
      * $RemediationPagedTop knob added (default 100, the documented max).
        Field observation: the Intune console itself pages remediation data
        at $top=40 — Microsoft's own client does not use the documented
        maximum. Set to 40 for console-parity runs.

    v3.9 — Remediation run-state diagnostic (the millions-of-rows dataset):
      * Hundreds of remediation scripts x tens of thousands of devices makes
        deviceRunStates the largest dataset BI for Intune consumes from this
        family. The DeviceRunStatesByProactiveRemediation export report
        REQUIRES a PolicyId filter — no unfiltered mode exists — so per-script
        is the only export access pattern, and no bulk ground truth exists on
        the export side.
      * Invoke-RemediationRunStateDiagnostic therefore tests three witnesses
        per sampled script (ranked by runSummary detection-state counts):
        the filtered export, the paged deviceRunStates endpoint (loop-detected
        and page-capped), and the script's runSummary counters (approximate
        context). Export vs paged is the hard comparison: same data, two
        APIs — disagreement is flagged as RunStateCountMismatch.
      * Config: $doRemediationTest, $RemediationSampleCount (default 5),
        $RemediationPagedPageCap (default 400 pages / ~40k rows per script).

    v3.8.2 — deviceHealthScripts finding (20260714 run):
      * The legacy discovery probe caught deviceHealthScripts?$expand=
        assignments failing at $top=100 with HTTP 500 (15.2s) and succeeding
        at 50 — the same payload disease as mobileApps, on a Cosmos-backed
        endpoint ([cosmosdb] skiptokens) with a different error code. Both
        production paged endpoints fail at production page size.
      * HTTP 500 added to the reduction-eligible class (payload-dependent 500
        demonstrated; reduction is harmless when a 500 is genuine).
      * deviceHealthScripts RunDiscovery disabled: the probe silently settled
        on 50 before collection, masking per-page evidence. The adaptive walk
        now documents fail-at-100/succeed-at-50 pairs per page.

    v3.8.1 — categories isolation variants:
      * Two new mobileApps variants complete the expand matrix: categories-
        only at top=100 (is categories expensive alone, or only combined with
        assignments?) and the proposed production fix's exact second-pass
        shape ($select=id,displayName&$expand=categories at top=100) so the
        run validates the remedy, not just the diagnosis. Endpoint objects
        now support an optional Select property.

    v3.8 — findings from the 20260714 run:
      * HTTP 502 added to retryable and timeout-class status codes. The dual-
        expand variants died on 502 after a single attempt because 502 was
        not classified; production-relevant failures must never be one-shot.
      * Bracketed baseline ($ComparisonBracketBaseline): the 20260714
        comparison showed 78 small, BIDIRECTIONAL mismatches (max +44 of
        134k rows) — the signature of live-tenant check-in drift, not
        truncation, over the hours between baseline and filtered jobs. Phase
        B2 now reruns the unfiltered export after the filtered jobs; a
        mismatch is Deterministic (flagged) only when the filtered count
        falls OUTSIDE both baselines. Drift-consistent mismatches are
        recorded as DriftLikely and removed from the Problems evidence.
        Reconciliation CSV gains Baseline2Rows and FinalVerdict columns.
      * Headline run finding (no code change): assignments,categories dual
        expand at top=100 = 33 retries / 59.4s per page / 24.8 min, while
        assignments-only at top=100 = 0 retries / 10.2s per page / 1.9 min,
        same hour, same scale unit. Recommended production fix: split the
        dual expand into two single-expand passes.

    v3.7.3 — per-failure scale-unit attribution (harvested from John's
    earlier header-capture script, with its PS7 bugs fixed):
      * return-client-request-id: true is sent on every request so Graph
        echoes the client id back for correlation.
      * Every failed response's x-ms-ags-diagnostic is parsed for the
        ScaleUnit that served THAT request — logged with the failure and
        added as a ScaleUnit column in the retry CSV. Requests within one run
        can land on different front-end partitions; per-failure attribution
        is what demonstrates scale-unit variance, not just per-run.
      * The earlier script's captures failed on PS7 because its catch path
        type-tested for HttpWebResponse (PS7 throws HttpResponseException
        with an HttpResponseMessage), and it reused one client-request-id for
        the entire run. Both corrected here.

    v3.7.2 — client-request-id on every request:
      * The server request-id only exists when a response arrives; client
        timeouts and connection drops were untraceable. Every request now
        carries a generated client-request-id header, which Graph records on
        receipt — so failures with no response are still traceable (logged and
        recorded in the retry CSV as client:<guid>). Per-attempt header clone;
        the shared token headers are never mutated.

    v3.7 — Scale-unit attribution (field report: behavior varies by ASU):
      * Failure behavior differs across Azure scale units — the same call
        succeeds on one partition and fails on another, which is why repro
        varies between customer tenants and why single-tenant support cases
        get "cannot reproduce".
      * Get-ServiceFingerprint logs the x-ms-ags-diagnostic ServerInfo
        (DataCenter/Slice/Ring/ScaleUnit) once per run, plus intuneAccountId,
        so every log is attributable to the infrastructure partition that
        produced it. Record the Intune portal 'Tenant location' (backend ASU)
        alongside each run for cross-tenant, per-scale-unit failure-rate
        comparison — evidence a single-tenant repro attempt cannot dismiss.
      * Every failed attempt now captures the response's request-id header —
        the exact identifier Microsoft engineers use to locate the request in
        service telemetry — logged with an ISO timestamp and added as a
        RequestId column in the retry events CSV.

    v3.6 — Poison-record isolation (field report: 503 persists at top=1):
      * A customer hit 503 at $top=1, proving the failure is per-RECORD, not
        per-page-payload: specific items cannot be served through $expand at
        ANY page size. Size reduction bottoms out; pagination is permanently
        blocked at that record — matching "once we hit the 503/504 we can
        never recover."
      * New rescue path when all retries (including size reduction) fail:
        refetch the page WITHOUT $expand (metadata always serves), then pull
        assignments per item via the /assignments endpoint, which bypasses
        the expand machinery. This unblocks pagination (expand is re-attached
        to the subsequent nextLink), recovers the page's data, and identifies
        the culprit precisely.
      * New Problem types: PageRescued (page recovered via fallback),
        HeavyRecord (item with >500 assignments or >10s per-item fetch —
        candidate culprit), UnservableRecord (assignments fail even per-item
        — the definitive poison record, with app id and name for Microsoft).
      * The same fallback pattern is the recommended production fix: expand
        -> halve on 503/504 -> at floor, no-expand + per-item assignments.
        Guarantees forward progress at any tenant scale.

    v3.5 — Production page size (top=100) per actual product code:
      * Production code sample confirms mobileApps is paged with
        $expand=assignments,categories&$top=100 — double the page size the
        diagnostic had been testing, at which 50% of pages already failed.
        The production pass now runs at top=100 (per-endpoint PageSize
        property, overriding the global $PageSize when present).
      * Variant matrix rebuilt around the two levers: page size (prod expand
        at top=100 vs 50 vs 25) and expand composition (assignments-only and
        no-expand at top=100).
      * v3.5.1 — confirmed production pages ALL endpoints at top=100 with
        back-off on failure (the same strategy as this script's v2.2 adaptive
        reduction). deviceManagementScripts, deviceHealthScripts, and the
        deviceHealthScripts control now run at top=100 to match.
      * Adaptive reduction walks 100 -> 50 -> 25 naturally on failures,
        mirroring production's back-off behavior.

    v3.4 — Expand-variant passes (production 503/504 characterization):
      * Production BI for Intune still pages mobileApps and deviceHealthScripts
        with $expand=assignments (assignment definitions have no export
        report), and that call is what fails in the product. The paged tests
        are therefore production-critical, not historical.
      * $doVariantTest re-collects configured variant endpoints after the
        production-shaped passes: mobileApps with assignments-only expand,
        mobileApps with no expand (control), deviceHealthScripts with no
        expand (control). Empty Expand values are now supported (the $expand
        parameter is omitted from the URL).
      * The final summary prints a pass-comparison table (items, pages, retry
        events, total and average seconds per page). Retries present on a
        production pass but absent on its variant implicate the removed
        expand content — separating payload composition from page size in the
        failure characterization for Microsoft.

    v3.3 — List-source enumeration (matches production; pending dev input):
      * Per the dev team, production enumerates the ids it filters on from
        ANOTHER export report — not from a Graph collection. When
        $ComparisonListReport is set, Phase A2 runs that report, extracts
        distinct ids from $ComparisonListColumn (defaults to the key column),
        and iterates exactly the ids production would.
      * Ids present in the list report but ABSENT from the unfiltered bulk
        export are flagged immediately as ExportIdMissingFromBulk — an entire
        id omitted by the bulk export, the strongest form of the silent-
        incomplete-data bug. Filtered jobs then verify (baseline treated as 0).
      * Empty $ComparisonListReport preserves v3.2 behavior (ids derived from
        the baseline itself).
      * PENDING from dev: list reportName + column for compliance, and the
        export reportName(s)/filters now used for mobileApps data (the paged
        mobileApps test is retained for the historical 503/504 case only).

    v3.2 — Policy-centric comparison keying:
      * BI for Intune release notes indicate a policy-centric model (policy↔
        setting relationship, Policy Name surfaced throughout), implying
        production filters export jobs per PolicyId enumerated from
        deviceCompliancePolicies — not per SettingId. The comparison key is
        now configurable ($ComparisonKeyColumn: 'PolicyId' default, or
        'SettingId'); column indexes are resolved from the CSV header.
      * When keyed on PolicyId, the tenant's deviceCompliancePolicies
        collection is retrieved as an independent third source of truth:
        policies absent from the unfiltered export are logged ([WARN]), export
        PolicyIds unknown to the collection are logged ([INFO], e.g. deleted
        policies with lingering state), and policy display names are resolved
        into the log and reconciliation CSV (KeyName column).
      * Practical effect: ~16 filtered jobs (one per policy, ~15 min) instead
        of 300+ per-setting jobs (~5 h). CONFIRM the key column and exact
        filter expression with the dev team before an evidence run.

    v3.1 — Export API comparison diagnostic (silent-incomplete-data repro):
      * Background: bulk pulls of compliance data return HTTP 200 with silently
        incomplete results (reported to Microsoft multiple times; answered
        "not a bug"). BI for Intune works around this in production by issuing
        one filtered export job per SettingId. Per the dev team, filtered jobs
        return MORE rows than the unfiltered export — i.e., the unfiltered
        export undercounts.
      * Invoke-ExportComparisonDiagnostic proves this with the API against
        itself: Phase A runs one unfiltered export and streams the CSV to
        tally rows per SettingId (baseline + iteration list in one pass).
        Phase B runs one filtered job per SettingId (production pattern) and
        validates every returned row against the requested id. Phase C
        re-tests mismatches once to rule out check-in drift, then writes a
        reconciliation CSV (ExportComparison_<ts>.csv).
      * Verdicts: FilteredExceedsBaseline (unfiltered undercounts — the bug),
        FilteredBelowBaseline, FilterNotHonored (service ignored the filter),
        DriftResolved (retest did not confirm; not flagged).
      * Confirmed mismatches land in the Problems CSV as ExportCountMismatch
        with baseline in Requested, filtered count in Returned.
      * Export job execution refactored into Invoke-SingleExportJob, shared by
        the health diagnostic and the comparison. Filtered zips that match are
        deleted after counting ($ComparisonKeepAllZips to keep them); the
        baseline zip is always retained as evidence.
      * Runtime scales with distinct SettingIds (~50s per filtered job,
        sequential). $ComparisonMaxSettings limits quick runs to the top-N
        settings by row count. Token auto-refresh (v2.1) covers multi-hour runs.

    v3.0.1 — Secret handling:
      * Client secret is no longer hardcoded in the script. It is read from the
        GRAPH_DIAG_SECRET environment variable, falling back to a hidden
        Read-Host prompt. The script file never needs to be edited to run,
        which prevents accidental syntax corruption during secret insertion
        and keeps the secret out of plaintext files.

    v3.0 — Compliance test replaced with Export API diagnostic:
      * BI for Intune migrated compliance reporting off the
        deviceComplianceSettingStates endpoint family and onto the Intune
        reports Export API, so the v2.x compliance drill-down test
        (Invoke-CompliancePolicyDiagnostic) has been removed and replaced with
        Invoke-ExportApiDiagnostic, which exercises the production data path.
      * Per report in $ExportReports: creates an export job (POST), polls to
        terminal status with queue-vs-processing timing, downloads the zip,
        and counts CSV data rows. All Graph calls go through the shared retry/
        token machinery; the download URL is a SAS link and is fetched without
        the Graph bearer token.
      * New Problem types: ExportJobCreateFailed, ExportJobFailed (terminal
        'failed' status), ExportJobStuck (poll deadline exceeded),
        ExportDownloadFailed, EmptyExport (0 data rows — may be legitimate for
        some reports; review in context).
      * The diagnostic intentionally omits 'select' so default columns are
        returned — it only counts rows, and this avoids maintaining per-report
        column lists. Production automation should always select columns
        explicitly per Microsoft's guidance.
      * managedDeviceOverview.enrolledDeviceCount is logged once as an
        informational baseline for judging device-level report row counts.
      * Invoke-GraphRequestWithRetry now supports -Method and -Body (POST for
        job creation). Note: a retried POST can create a duplicate export job
        if the original succeeded but the response was lost — harmless here,
        jobs expire on their own.

    v2.4 — Row count validation against Microsoft's own counters:
      * Each deviceCompliancePolicySettingStateSummary documents seven per-state
        device counters (unknown/notApplicable/compliant/remediated/nonCompliant/
        error/conflict). Their sum is Microsoft's stated total for how many
        deviceComplianceSettingStates rows the child endpoint should return.
      * Phase 2 now logs the expected row count per summary, and after a clean
        (uncapped, error-free) enumeration compares it against rows actually
        retrieved. A divergence is flagged as a 'RowCountMismatch' Problem:
        fewer rows = under-enumeration (silent data loss evidence), more rows
        = over-enumeration (duplication or cycling pagination).
      * Comparison is skipped (and logged as skipped) when the page cap fired,
        a pagination loop was detected, or a page failed — the enumerated total
        is not authoritative in those cases.

    v2.3 — Runaway pagination protection:
      * $MaxPagesPerSummary caps Phase 2 pagination per compliance summary
        (default 60; 0 = unlimited). deviceComplianceSettingStates returns one
        row per device per setting — at large-tenant scale a single summary can
        run to thousands of pages. The small-result-set bug surfaces in early
        pages or not at all, so full enumeration adds runtime without evidence.
        Capped summaries are logged as [CAPPED] with the nextLink noted.
      * Pagination loop detection on all paged collections: every nextLink is
        recorded per collection; if Graph serves a nextLink already seen, the
        script flags a 'PaginationLoop' Problem and breaks out instead of
        paging forever. Cycling skiptokens are a known Graph failure mode and
        are indistinguishable from large datasets without this check.

    v2.2 — Adaptive page size on timeout:
      * On 503/504 (or no HTTP response, i.e. client timeout), retries now halve
        the $top value in the request URL before the next attempt (floor $MinTop),
        logged as [ADAPTIVE]. Skiptoken is position-based, so rewriting $top on a
        nextLink resumes from the correct record at the smaller page size.
      * 429 retries intentionally keep the original $top and honor Retry-After —
        throttling is not payload-related.
      * Reduction applies within a single page fetch only; the next page's URL is
        restored to the endpoint's configured page size (failures are typically
        localized to specific records, so permanent degradation is unnecessary).
      * The small-result-set Problem detector now compares against the $top
        actually requested (EffectiveTop) so reduced pages don't false-flag.
      * Toggle with $ReduceTopOnTimeout = $false to preserve fixed-size repro
        behavior for escalation evidence.

    v2.1 — Token resilience:
      * Token acquisition moved into Get-GraphToken; token state is script-scoped
        and the shared $script:Headers hashtable is mutated in place on refresh,
        so every function holding a reference picks up the new token instantly.
      * Assert-GraphToken proactively refreshes when within 5 minutes of expiry,
        checked before every Graph request (client credentials flow — a new
        token is one POST, no refresh token needed).
      * HTTP 401 is now handled reactively: refresh the token once and retry
        the request immediately. A second consecutive 401 after refresh is
        treated as fatal (indicates revocation/permission change, not expiry).
      * $TimeoutSec is now actually defined in Configuration (previously it was
        referenced but never set, passing $null → 0 → infinite timeout).
      * Every page log line now includes a wall-clock timestamp so gaps between
        requests (machine sleep, console QuickEdit freeze) are visible.
      * Final summary reports token refresh count.

    v2.0 — Adds Problem detection (distinct from Error detection):
      * Generic small-result-set detector on all paged Graph calls.
        Flags responses where row count < requested $top AND @odata.nextLink
        is present (Graph claims more data exists but returned a partial page).
      * New compliance policy diagnostic that exercises the
        /deviceCompliancePolicySettingStateSummaries/{id}/deviceComplianceSettingStates
        endpoint per Julien's 2026-05-20 confirmation that this is THE
        endpoint family exhibiting the silent small-result-set bug.
      * Bug occurs on both /beta/ and v1.0 endpoints — detection is
        endpoint-agnostic.
#>

# v3.7.1 — command-line parameters. Secret resolution order:
#   1. -ClientSecret parameter
#   2. GRAPH_DIAG_SECRET environment variable
#   3. Hidden interactive prompt
# TenantId/ClientId default to the PowerStacks tenant but are overridable so
# the same file runs unmodified in customer tenants.
param(
    [string]$ClientSecret = '',
    [string]$TenantId = "",
    [string]$ClientId = ""
)

#region --- Configuration ---
# v3.0.1 — secret is never hardcoded; v3.7.1 — resolution order:
# -ClientSecret parameter > GRAPH_DIAG_SECRET env var > hidden prompt.
if ([string]::IsNullOrWhiteSpace($ClientSecret))
{
    $ClientSecret = $env:GRAPH_DIAG_SECRET
}
if ([string]::IsNullOrWhiteSpace($ClientSecret))
{
    $SecureSecret = Read-Host -Prompt 'Client secret (input hidden)' -AsSecureString
    $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureSecret))
}
$PageSize = 50
$MaxRetries = 3
$TimeoutSec = 60            # v2.1 — was referenced but never defined ($null → 0 → infinite timeout)
$TokenRefreshBufferSec = 300 # v2.1 — proactively refresh when within 5 min of expiry
$ReduceTopOnTimeout = $true  # v2.2 — halve $top on 503/504/client-timeout retries (payload-size mitigation)
$MinTop = 5                  # v2.2 — floor for adaptive $top reduction
$AdaptiveStickyThreshold = 3 # v4.1 — after N CONSECUTIVE pages needing reduction, stop restoring full size and ride at the reduced size (0 = never sticky: pure evidence mode, every page retried at full size)
$AdaptiveProbeInterval = 0   # v4.2.1 — 0 = once we know full size isn't working, never try it again this run (per JM). Set to e.g. 20 to probe full size periodically and recover if the service heals mid-run
$LogDir = "C:\Temp"
$doScaleTest = $False
$doVariantTest = $True       # v3.4 — after the production-shaped passes, re-collect variant endpoints (different $expand) to isolate payload composition vs page size
$VariantEndpoints = @(       # v3.5 — two levers against production shape (expand=assignments,categories @ top=100): page size and expand composition
    [PSCustomObject]@{
        Name         = 'mobileApps (prod expand, top=50)'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        Expand       = 'assignments,categories'
        PageSize     = 50              # page-size lever, step 1
        PerItemUrl   = ''
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'mobileApps (prod expand, top=25)'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        Expand       = 'assignments,categories'
        PageSize     = 25              # page-size lever, step 2 — the level that never failed
        PerItemUrl   = ''
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'mobileApps (assignments only, top=100)'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        Expand       = 'assignments'   # expand lever: is 'categories' contributing at production page size?
        PageSize     = 100
        PerItemUrl   = ''
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'mobileApps (categories only, top=100)'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        Expand       = 'categories'   # v3.8.1 — expand lever: is categories expensive alone, or only combined with assignments?
        PageSize     = 100
        PerItemUrl   = ''
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'mobileApps (fix shape: id+categories, top=100)'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        Expand       = 'categories'   # v3.8.1 — validates the proposed production fix's second pass
        Select       = 'id,displayName'
        PageSize     = 100
        PerItemUrl   = ''
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'mobileApps (no expand, top=100)'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        Expand       = ''              # control: metadata only at production page size
        PageSize     = 100
        PerItemUrl   = ''
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'deviceHealthScripts (no expand, top=100)'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'
        Expand       = ''              # control vs the production assignments-expanded pass
        PageSize     = 100
        PerItemUrl   = ''
        RunDiscovery = $false
    }
)
$doExportTest = $True        # v3.0 — exercise the Intune reports Export API (the path BI for Intune's compliance reporting now uses)
$ExportReports = @(          # v3.0 — align with the reportName values BI for Intune actually requests
    'DevicePolicySettingsComplianceReportV3',   # per-device per-setting — replaces the old deviceComplianceSettingStates drill-down
    'DevicePoliciesComplianceReportV3',         # per-device per-policy
    'DeviceNonCompliance'                       # noncompliant device list
)
$ExportPollIntervalSec = 10  # v3.0 — seconds between export job status polls
$ExportPollTimeoutSec = 900  # v3.0 — give up on a job after 15 min and flag ExportJobStuck
$doExportComparison = $True  # v3.1 — reproduce the silent-incomplete-data bug: unfiltered export vs per-ID filtered exports (production pattern)
$ComparisonReport = 'DevicePolicySettingsComplianceReportV3'   # v3.1 — report to run the comparison against
$ComparisonKeyColumn = 'PolicyId'   # v3.2 — CSV column to key the comparison on: 'PolicyId' (policy-centric model per BI for Intune release notes) or 'SettingId'. CONFIRM WITH DEV which one production filters on.
$ComparisonFilterTemplate = "PolicyId eq '{0}'"                # v3.2 — align with production's exact filter expression; must match $ComparisonKeyColumn
$ComparisonMaxSettings = 0   # v3.1 — 0 = test every distinct key value in the baseline; N = top-N by baseline row count (quick runs)
$ComparisonListReport = ''   # v3.3 — reportName of the export report production uses to ENUMERATE the ids it filters on (per dev: the list comes from another export API report). Empty = derive ids from the unfiltered baseline.
$ComparisonListColumn = ''   # v3.3 — column in the list report containing the ids (defaults to $ComparisonKeyColumn when empty)
$ComparisonRetestMismatches = $True   # v3.1 — re-run each mismatched filtered job once to rule out check-in drift
$ComparisonBracketBaseline = $True    # v3.8 — run a second unfiltered baseline AFTER the filtered jobs; a mismatch is deterministic only if the filtered count falls outside BOTH baselines (drift lands between them)
$ExportJobConcurrency = 5             # v4.0 — export jobs kept in flight simultaneously (server-side concurrency, single client thread). Applies to the comparison and remediation diagnostics; raise cautiously — export job creation is tenant-throttled
$ComparisonKeepAllZips = $False       # v3.1 — $False keeps only the baseline zip; matching filtered zips are deleted after counting
$doRemediationTest = $True        # v3.9 — remediation run states: per-script filtered export vs paged deviceRunStates vs runSummary counters (three witnesses, same data)
$RemediationSampleCount = 5       # v3.9 — number of scripts to test, ranked by runSummary device counts (0 = all; at hundreds of scripts expect hours)
$RemediationPagedPageCap = 400    # v3.9 — max paged deviceRunStates pages per script (~40k rows); comparison skipped past the cap
$RemediationPagedTop = 100        # v3.9.1 — $top for paged deviceRunStates. 100 = documented max (adaptive walk documents any failures); NOTE: the Intune console itself pages this data at 40 — Microsoft's own client does not use the documented maximum

$Endpoints = @(
    [PSCustomObject]@{
        Name         = 'mobileApps'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        Expand       = 'assignments,categories'
        PageSize     = 100   # v3.5 — matches production code: $expand=assignments,categories&$top=100
        PerItemUrl   = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{id}/assignments'
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'deviceManagementScripts'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
        Expand       = 'assignments'
        PageSize     = 100   # v3.5.1 — production pages everything at top=100 then backs off
        PerItemUrl   = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/{id}/assignments'
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'deviceHealthScripts'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'
        Expand       = 'assignments'
        PageSize     = 100   # v3.5.1 — production pages everything at top=100 then backs off
        PerItemUrl   = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/{id}/assignments'
        RunDiscovery = $false   # v3.8.2 — discovery masked the per-page evidence (it settled on 50 before collection); the adaptive walk now documents the fail-at-100 pairs per page, production-faithfully   # Auto-discover working page size — demonstrates threshold to MSFT
    }
)
#endregion

#region --- Logging ---
# Initialize log files — every entry goes to console, the human-readable
# report log, AND (v4.3) a CMTrace-format twin with per-entry timestamps
# and severity types for color-coded timeline review in CMTrace.
if (-not (Test-Path $LogDir))
{
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# v4.3.1 — disable console QuickEdit for this session. Clicking/selecting in
# the console window blocks [Console]::WriteLine and freezes the ENTIRE run
# (observed: a 5m43s stall between two adjacent log lines, unfrozen by the
# Ctrl+C that cancelled the selection; also ~50 unlogged minutes in run one).
if ($IsWindows -or $env:OS -eq 'Windows_NT')
{
    try
    {
        $Sig = @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@
        $K32 = Add-Type -MemberDefinition $Sig -Name 'ConsoleMode' -Namespace 'GraphDiag' -PassThru
        $StdIn = $K32::GetStdHandle(-10)   # STD_INPUT_HANDLE
        $Mode = 0
        if ($K32::GetConsoleMode($StdIn, [ref]$Mode))
        {
            # Clear ENABLE_QUICK_EDIT_MODE (0x0040), set ENABLE_EXTENDED_FLAGS (0x0080)
            $null = $K32::SetConsoleMode($StdIn, (($Mode -band (-bnot 0x0040)) -bor 0x0080))
        }
    }
    catch { }   # non-console hosts (ISE, scheduled task) — harmless to skip
}

$RunTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogPath = "$LogDir\GraphDiag_$RunTimestamp.log"

function Write-Log
{
    param([string]$Message)
    # v4.4 — single CMTrace-format log. One CMTrace entry per physical line;
    # severity inferred from the message so CMTrace highlights errors and
    # warnings. File is written BEFORE console (v4.3.1) — the console is the
    # only sink that can block, so the log always reflects true progress.
    $Now = Get-Date
    $BiasMinutes = [int](-1 * [System.TimeZoneInfo]::Local.GetUtcOffset($Now).TotalMinutes)
    $BiasStr = if ($BiasMinutes -ge 0) { "+$BiasMinutes" } else { "$BiasMinutes" }
    $Type = if ($Message -match '\[PROBLEM\]|\[FATAL\]|\[FAIL\]|\[ERROR\]|FAILED|POISON|Giving up') { 3 }
    elseif ($Message -match '\[WARN\]|\[STICKY\]|\[CAPPED\]|\[RESCUE\]|MISMATCH') { 2 }
    else { 1 }
    foreach ($Line in ($Message -split "`n"))
    {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }
        $CmLine = "<![LOG[$Line]LOG]!><time=`"$($Now.ToString('HH:mm:ss.fff'))$BiasStr`" date=`"$($Now.ToString('MM-dd-yyyy'))`" component=`"GraphDiag`" context=`"`" type=`"$Type`" thread=`"$PID`" file=`"`">"
        Add-Content -Path $script:LogPath -Value $CmLine
    }
    [Console]::WriteLine($Message)
}

Write-Log "=========================================="
Write-Log "  Graph API Diagnostic Script"
Write-Log "  Run timestamp : $RunTimestamp"
Write-Log "  Log file      : $($script:LogPath) (CMTrace format)"
Write-Log "=========================================="
#endregion

#region --- Token Acquisition ---
# v2.1 — Token state is script-scoped. $script:Headers is created ONCE and
# mutated in place on refresh. Because hashtables are reference types, every
# function that received $Headers as a parameter sees the new Authorization
# value immediately — no re-plumbing required.
$script:AccessToken = $null
$script:TokenExpires = [datetime]::MinValue
$script:TokenRefreshCount = -1   # first acquisition brings this to 0
$script:Headers = @{ Authorization = '' }

function Get-GraphToken
{
    <#
    .SYNOPSIS
        Acquires (or re-acquires) an app-only Graph token and updates the
        shared $script:Headers hashtable in place.
    #>
    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] Acquiring token..."

    $TokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $ClientId
        Client_Secret = $ClientSecret
    }

    try
    {
        $TokenResponse = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Body $TokenBody -TimeoutSec 30 -ErrorAction Stop   # v4.2.3 — was unbounded; a stalled token refresh could hang the run forever

        $script:AccessToken = $TokenResponse.access_token
        $script:TokenExpires = (Get-Date).AddSeconds($TokenResponse.expires_in)
        $script:TokenRefreshCount++

        # Mutate in place — do NOT reassign $script:Headers to a new hashtable,
        # or existing references held by in-flight functions would go stale.
        $script:Headers['Authorization'] = "Bearer $($script:AccessToken)"

        # Decode JWT for diagnostic visibility
        $TokenParts = $script:AccessToken.Split('.')
        $Padded = $TokenParts[1].PadRight($TokenParts[1].Length + (4 - $TokenParts[1].Length % 4) % 4, '=')
        $TokenClaims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Padded)) | ConvertFrom-Json

        Write-Log "  Token acquired successfully (refresh #$($script:TokenRefreshCount))"
        Write-Log "  Expires      : $($script:TokenExpires.ToString('HH:mm:ss')) (in $($TokenResponse.expires_in)s)"
        Write-Log "  Token type   : $($TokenResponse.token_type)"
        Write-Log "  App ID (oid) : $($TokenClaims.oid)"
        Write-Log "  Tenant       : $($TokenClaims.tid)"
        Write-Log "  Roles        : $($TokenClaims.roles -join ', ')"
    }
    catch
    {
        Write-Log "  [FATAL] Token acquisition failed: $_"
        if ($script:TokenRefreshCount -lt 0)
        {
            # Initial acquisition failure — nothing to salvage
            exit 1
        }
        throw
    }
}

function Assert-GraphToken
{
    <#
    .SYNOPSIS
        Proactively refreshes the token if it expires within
        $TokenRefreshBufferSec seconds. Called before every Graph request.
    #>
    if ((Get-Date) -ge $script:TokenExpires.AddSeconds(-$TokenRefreshBufferSec))
    {
        Write-Log "    [TOKEN] Within $TokenRefreshBufferSec s of expiry ($($script:TokenExpires.ToString('HH:mm:ss'))) — refreshing proactively"
        Get-GraphToken
    }
}

function Get-ServiceFingerprint
{
    <#
    .SYNOPSIS
        v3.7 — Logs which Graph infrastructure partition is serving this run.
        Failure behavior varies by Azure scale unit; the x-ms-ags-diagnostic
        header attributes every log to the partition that produced it,
        enabling failure-rate-by-scale-unit comparison across tenants.
    #>
    try
    {
        $R = Invoke-WebRequest -Uri 'https://graph.microsoft.com/beta/deviceManagement?$select=intuneAccountId' `
            -Headers $script:Headers -UseBasicParsing -TimeoutSec 30
        $Diag = $R.Headers['x-ms-ags-diagnostic']
        if ($Diag -is [array]) { $Diag = $Diag -join '' }
        Write-Log "  Graph FRONT-END fingerprint (x-ms-ags-diagnostic) — this is the gateway node that served THIS request; it varies per request/run and is NOT your tenant's home ASU:"
        try
        {
            $Info = ($Diag | ConvertFrom-Json).ServerInfo
            Write-Log "    DataCenter : $($Info.DataCenter)"
            Write-Log "    Slice/Ring : $($Info.Slice) / $($Info.Ring)"
            Write-Log "    ScaleUnit  : $($Info.ScaleUnit)"
        }
        catch
        {
            Write-Log "    $Diag"
        }
        $Acct = ($R.Content | ConvertFrom-Json).intuneAccountId
        Write-Log "    IntuneAcct : $Acct"
        Write-Log "    Your tenant's HOME ASU (the one that rarely changes, and the one that matters for per-tenant behavior): Intune admin center > Tenant administration > Tenant details > 'Tenant location'. Record it alongside this log for cross-tenant comparison."
    }
    catch
    {
        Write-Log "  Service fingerprint unavailable: $($_.Exception.Message)"
    }
}

Get-GraphToken
$Headers = $script:Headers   # legacy alias — same object, kept so existing call sites work unchanged
Get-ServiceFingerprint
#endregion

#region --- Functions ---
function Invoke-GraphRequestWithRetry
{
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [int]$MaxRetries = 7,
        [int]$PageNumber = 1,
        [string]$Endpoint = '',
        [int]$TimeoutSec = 60,
        [string]$Method = 'Get',   # v3.0 — POST support for export job creation
        [string]$Body = $null,     # v3.0 — JSON body for POST requests
        [string]$Context = ''      # v4.5.1 — optional caller context (e.g. running row count) appended to attempt lines
    )

    # v4.5.1 — every attempt line identifies WHERE it is: endpoint, page, and
    # any caller context. Long paged sections previously scrolled dozens of
    # anonymous 'Attempt 1 succeeded' lines.
    $Where = "$(if ($Endpoint) { " — $Endpoint" })$(if ($PageNumber -gt 0) { " p$PageNumber" })$(if ($Context) { " ($Context)" })"

    $Attempt = 0
    $RetryLog = [System.Collections.Generic.List[object]]::new()
    $TotalElapsedMs = 0
    $TokenRefreshedFor401 = $false   # v2.1 — allow exactly one 401-triggered refresh per request

    # v2.2 — track the $top currently in the URL so we can reduce it on
    # timeout-class failures. $null if the URL has no $top parameter.
    $CurrentTop = $null
    if ($Uri -match '\$top=(\d+)')
    {
        $CurrentTop = [int]$Matches[1]
    }

    do
    {
        $Attempt++

        # v2.1 — proactive refresh before every attempt. Cheap clock check;
        # only hits the token endpoint when inside the expiry buffer.
        Assert-GraphToken

        # v3.7.2 — send our own client-request-id: Graph records it server-side
        # ON RECEIPT, so even requests that die without a response (client
        # timeout, connection drop) are traceable by the PG. Cloned per attempt
        # so the shared token headers are never mutated.
        $ClientRequestId = [guid]::NewGuid().ToString()
        $ReqHeaders = $Headers.Clone()
        $ReqHeaders['client-request-id'] = $ClientRequestId
        $ReqHeaders['return-client-request-id'] = 'true'   # v3.7.3 — Graph echoes our id back for correlation

        # v4.2.3 — log attempt start so in-flight requests are never silent:
        # after an immediate size-reduced retry there is otherwise no output
        # until the request completes, which reads as a hang.
        if ($Attempt -gt 1)
        {
            $AttemptTop = if ($Uri -match '\$top=(\d+)') { " (`$top=$($Matches[1]))" } else { '' }
            Write-Log "    [$(Get-Date -Format 'HH:mm:ss')] Attempt $Attempt in flight$AttemptTop$Where..."
        }

        $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        try
        {
            # v3.0 — splat so GET and POST share the retry/token machinery
            $RequestParams = @{
                Method      = $Method
                Uri         = $Uri
                Headers     = $ReqHeaders
                TimeoutSec  = $TimeoutSec
                ErrorAction = 'Stop'
            }
            if ($Body)
            {
                $RequestParams.Body = $Body
                $RequestParams.ContentType = 'application/json'
            }
            $Response = Invoke-RestMethod @RequestParams
            $StopWatch.Stop()
            $TotalElapsedMs += $StopWatch.ElapsedMilliseconds

            Write-Log "    Attempt $Attempt succeeded in $($StopWatch.ElapsedMilliseconds)ms ($([math]::Round($StopWatch.ElapsedMilliseconds / 1000, 1))s)$Where"

            return [PSCustomObject]@{
                Response       = $Response
                RetryLog       = $RetryLog
                ElapsedMs      = $StopWatch.ElapsedMilliseconds
                TotalElapsedMs = $TotalElapsedMs
                Attempts       = $Attempt
                EffectiveTop   = $CurrentTop   # v2.2 — the $top actually used on the successful attempt
            }
        }
        catch
        {
            $StopWatch.Stop()
            $TotalElapsedMs += $StopWatch.ElapsedMilliseconds

            $StatusCode = $null
            $RetryAfter = $null
            $ExceptionMsg = $_.Exception.Message

            if ($_.Exception.Response)
            {
                $StatusCode = $_.Exception.Response.StatusCode.value__
                $RetryAfter = $_.Exception.Response.Headers['Retry-After']
            }

            if ($_.Exception.InnerException)
            {
                $ExceptionMsg += " | Inner: $($_.Exception.InnerException.Message)"
            }

            # v3.7 — extract request-id from the failed response: the traceable
            # hook Microsoft engineers use to find this exact request in their
            # telemetry. Quote it with the timestamp in any escalation.
            $RequestId = ''
            $FailScaleUnit = ''
            try
            {
                $FailResp = $_.Exception.Response
                if ($FailResp -and $FailResp.Headers)
                {
                    $IdVals = $null
                    if ($FailResp.Headers.TryGetValues('request-id', [ref]$IdVals)) { $RequestId = @($IdVals)[0] }
                    # v3.7.3 — which infrastructure partition produced THIS failure.
                    # Requests within one run can land on different front ends, so
                    # per-failure attribution is what proves scale-unit variance.
                    $DiagVals = $null
                    if ($FailResp.Headers.TryGetValues('x-ms-ags-diagnostic', [ref]$DiagVals))
                    {
                        $DiagRaw = @($DiagVals) -join ''
                        if ($DiagRaw -match '"ScaleUnit"\s*:\s*"([^"]+)"') { $FailScaleUnit = $Matches[1] }
                        elseif ($DiagRaw) { $FailScaleUnit = $DiagRaw }
                    }
                }
            }
            catch { }

            Write-Log "    Attempt $Attempt FAILED — HTTP $StatusCode | $($StopWatch.ElapsedMilliseconds)ms ($([math]::Round($StopWatch.ElapsedMilliseconds / 1000, 1))s)$Where"
            Write-Log "    Error: $ExceptionMsg"
            if ($RequestId)
            {
                Write-Log "    request-id: $RequestId  (traceable by Microsoft — quote with timestamp $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'))"
                if ($FailScaleUnit)
                {
                    Write-Log "    served by front-end ScaleUnit: $FailScaleUnit (gateway node for this request — not the tenant's home ASU)"
                }
            }
            else
            {
                # Either no response at all (client timeout / connection drop)
                # or a response that carried no request-id header — the
                # client-request-id we SENT is in Microsoft's logs either way.
                $RequestId = "client:$ClientRequestId"
                $WhyNoId = if ($null -ne $_.Exception.Response) { 'response carried no request-id header' } else { 'no response received' }
                Write-Log "    client-request-id: $ClientRequestId  ($WhyNoId; Microsoft can trace by this id — sent at $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'))"
            }

            # v2.1 — 401 handling: refresh the token once and retry immediately.
            # A 401 after a fresh token is NOT expiry (revocation, secret rotation,
            # or permission change) and falls through to the fatal path below.
            if ($StatusCode -eq 401 -and -not $TokenRefreshedFor401)
            {
                Write-Log "    HTTP 401 — token likely expired mid-run. Refreshing and retrying immediately..."
                $TokenRefreshedFor401 = $true
                try
                {
                    Get-GraphToken
                    $RetryLog.Add([PSCustomObject]@{
                            Endpoint  = $Endpoint
                            Page      = $PageNumber
                            Attempt   = $Attempt
                            Status    = 401
                            ElapsedMs = $StopWatch.ElapsedMilliseconds
                            WaitedSec = 0
                            RequestId = $RequestId
                            ScaleUnit = $FailScaleUnit
                            Error     = "401 — token refreshed, retried"
                        })
                    continue   # jump straight to next attempt, no backoff wait
                }
                catch
                {
                    Write-Log "    [FATAL] Token refresh after 401 failed — cannot continue this request"
                    throw
                }
            }

            # Retryable: 429, 500, 502, 503, 504, or null status (gateway timeout before HTTP response)
            # v3.8 — 502 added: the 20260714 run showed Bad Gateway on the dual-expand
            # calls dying after one attempt because 502 was not in this list.
            $IsRetryable = ($StatusCode -in @(429, 500, 502, 503, 504)) -or ($null -eq $StatusCode)

            if ($IsRetryable -and $Attempt -lt $MaxRetries)
            {

                if ($RetryAfter)
                {
                    $WaitSeconds = [int]$RetryAfter
                    Write-Log "    Retry-After header: ${WaitSeconds}s"
                }
                else
                {
                    # Aggressive backoff: 15s, 30s, 60s, 120s, 240s, 300s (capped)
                    $WaitSeconds = [math]::Min([math]::Pow(2, $Attempt) * 7.5, 300)
                    Write-Log "    No Retry-After — exponential backoff: ${WaitSeconds}s"
                }

                $RetryLog.Add([PSCustomObject]@{
                        Endpoint  = $Endpoint
                        Page      = $PageNumber
                        Attempt   = $Attempt
                        RequestId = $RequestId
                        ScaleUnit = $FailScaleUnit
                        Status    = if ($StatusCode)
                        {
                            $StatusCode
                        }
                        else
                        {
                            'No HTTP Response'
                        }
                        ElapsedMs = $StopWatch.ElapsedMilliseconds
                        WaitedSec = $WaitSeconds
                        Error     = $ExceptionMsg
                    })

                # v4.2 — decide reduction BEFORE waiting. A size-reduced retry is
                # a DIFFERENT request (payload mitigation), so backoff adds nothing:
                # these failures are payload-deterministic, not transient. Backoff
                # is kept for 429 (Retry-After = actual throttling) and for retries
                # at the SAME size (where transience is the only hope).
                # v2.2/v3.8.2 — timeout-class: 500/502/503/504 or no HTTP response;
                # 429 keeps its size and honors Retry-After.
                $IsTimeoutClass = ($StatusCode -in @(500, 502, 503, 504)) -or ($null -eq $StatusCode)
                $ReducedForRetry = $false
                if ($ReduceTopOnTimeout -and $IsTimeoutClass -and $CurrentTop -and ($CurrentTop -gt $MinTop))
                {
                    $NewTop = [math]::Max([math]::Floor($CurrentTop / 2), $MinTop)
                    $Uri = $Uri -replace '(\$top=)\d+', ('${1}' + $NewTop)
                    Write-Log "    [ADAPTIVE] Reducing `$top $CurrentTop -> $NewTop — retrying immediately (no backoff: payload mitigation, not throttling)"
                    $CurrentTop = $NewTop
                    $ReducedForRetry = $true
                }

                if (-not $ReducedForRetry)
                {
                    Write-Log "    Waiting ${WaitSeconds}s before retry..."
                    Start-Sleep -Seconds $WaitSeconds
                }
                if (-not $ReducedForRetry) { $TotalElapsedMs += ($WaitSeconds * 1000) }   # v4.3.1 — skipped waits must not inflate the total

            }
            else
            {
                Write-Log "    Giving up on $Endpoint page $PageNumber after $Attempt attempts"

                $RetryLog.Add([PSCustomObject]@{
                        Endpoint  = $Endpoint
                        Page      = $PageNumber
                        Attempt   = $Attempt
                        RequestId = $RequestId
                        ScaleUnit = $FailScaleUnit
                        Status    = if ($StatusCode)
                        {
                            $StatusCode
                        }
                        else
                        {
                            'No HTTP Response'
                        }
                        ElapsedMs = $StopWatch.ElapsedMilliseconds
                        WaitedSec = 0
                        Error     = "FATAL: $ExceptionMsg"
                    })

                throw
            }
        }

    } while ($Attempt -le $MaxRetries)

    # v2.1 — safety net: reachable only if a 401-triggered 'continue' lands on
    # the final allowed attempt. Never return $null silently.
    throw "Exhausted $MaxRetries attempts (including post-401 token refresh) for $Endpoint page $PageNumber"
}

function Invoke-EndpointCollection
{
    param(
        [PSCustomObject]$Endpoint,
        [hashtable]$Headers,
        [int]$MaxRetries = 7,
        [int]$TimeoutSec = 60
    )

    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] ===== $($Endpoint.Name) ====="

    $Results = [System.Collections.Generic.List[object]]::new()
    $RetryLog = [System.Collections.Generic.List[object]]::new()
    $Problems = [System.Collections.Generic.List[object]]::new()
    $Page = 0
    $TotalMs = 0
    $FatalError = $false

    #region Page Size Discovery
    if ($Endpoint.RunDiscovery)
    {
        Write-Log "`n  Running page size discovery for $($Endpoint.Name)..."
        Write-Log "  (This demonstrates the failure threshold to MSFT)"

        $EffectivePageSize = if ($Endpoint.PSObject.Properties['PageSize'] -and $Endpoint.PageSize) { $Endpoint.PageSize } else { $PageSize }   # v3.5 — per-endpoint page size (production mobileApps uses 100)

        while ($EffectivePageSize -ge 1)
        {
            $TestQs = @()
            if ($Endpoint.PSObject.Properties['Select'] -and $Endpoint.Select) { $TestQs += "`$select=$($Endpoint.Select)" }   # v3.8.1
            if ($Endpoint.Expand) { $TestQs += "`$expand=$($Endpoint.Expand)" }
            $TestQs += "`$top=$EffectivePageSize"
            $TestUrl = "$($Endpoint.BaseUrl)?$($TestQs -join '&')"
            Assert-GraphToken   # v2.1
            $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            try
            {
                $TestResponse = Invoke-RestMethod -Method Get -Uri $TestUrl -Headers $Headers `
                    -TimeoutSec $TimeoutSec -ErrorAction Stop
                $StopWatch.Stop()
                Write-Log "  Page size $($EffectivePageSize.ToString().PadLeft(4)) : SUCCESS in $($StopWatch.ElapsedMilliseconds)ms ($([math]::Round($StopWatch.ElapsedMilliseconds / 1000, 1))s) — using this for collection"
                break
            }
            catch
            {
                $StopWatch.Stop()
                $StatusCode = $_.Exception.Response.StatusCode.value__
                $PreviousPageSize = $EffectivePageSize
                $EffectivePageSize = [math]::Floor($EffectivePageSize / 2)
                Write-Log "  Page size $($PreviousPageSize.ToString().PadLeft(4)) : FAILED HTTP $StatusCode in $($StopWatch.ElapsedMilliseconds)ms ($([math]::Round($StopWatch.ElapsedMilliseconds / 1000, 1))s) — trying $EffectivePageSize"

                if ($EffectivePageSize -lt 1)
                {
                    Write-Log "  [FATAL] No working page size found — endpoint unusable with expand"
                    $FatalError = $true
                    return [PSCustomObject]@{
                        EndpointName      = $Endpoint.Name
                        Results           = $Results
                        RetryLog          = $RetryLog
                        Pages             = 0
                        TotalMs           = 0
                        FatalError        = $true
                        ItemCount         = 0
                        EffectivePageSize = 0
                    }
                }
            }
        }
    }
    else
    {
        $EffectivePageSize = if ($Endpoint.PSObject.Properties['PageSize'] -and $Endpoint.PageSize) { $Endpoint.PageSize } else { $PageSize }   # v3.5 — per-endpoint page size (production mobileApps uses 100)
        Write-Log "  Using page size: $EffectivePageSize"
    }
    #endregion

    $MainQs = @()
    if ($Endpoint.PSObject.Properties['Select'] -and $Endpoint.Select) { $MainQs += "`$select=$($Endpoint.Select)" }   # v3.8.1 — variants may add $select
    if ($Endpoint.Expand) { $MainQs += "`$expand=$($Endpoint.Expand)" }
    $MainQs += "`$top=$EffectivePageSize"
    $Url = "$($Endpoint.BaseUrl)?$($MainQs -join '&')"
    Write-Log "  URL: $Url"
    $SeenLinks = [System.Collections.Generic.HashSet[string]]::new()   # v2.3 — pagination loop detection
    $WorkingTop = $EffectivePageSize      # v4.1 — sticky adaptive: current riding size
    $ConsecutiveReduced = 0
    $PagesSinceProbe = 0
    $StickyActive = $false

    do
    {
        $Page++
        $RequestedUrl = $Url   # capture before reassignment for Problem tracking
        $ThisPageRequestedTop = if ($Url -match '\$top=(\d+)') { [int]$Matches[1] } else { $EffectivePageSize }   # v4.1
        Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] [Page $Page] GET $Url"

        try
        {
            $Result = Invoke-GraphRequestWithRetry -Uri $Url -Headers $Headers `
                -MaxRetries $MaxRetries -PageNumber $Page -Endpoint $Endpoint.Name `
                -TimeoutSec $TimeoutSec
            $Response = $Result.Response

            foreach ($entry in $Result.RetryLog)
            {
                $RetryLog.Add($entry)
            }

            $PageCount = $Response.value.Count
            $Results.AddRange($Response.value)
            $TotalMs += $Result.TotalElapsedMs

            Write-Log "    Records this page : $PageCount"
            Write-Log "    Running total     : $($Results.Count)"
            Write-Log "    Last attempt time : $($Result.ElapsedMs)ms ($([math]::Round($Result.ElapsedMs / 1000, 1))s)"
            Write-Log "    Total page time   : $($Result.TotalElapsedMs)ms ($([math]::Round($Result.TotalElapsedMs / 1000, 1))s) — inc. retries and waits"
            Write-Log "    Attempts required : $($Result.Attempts)"

            if ($Response.'@odata.count')
            {
                Write-Log "    @odata.count      : $($Response.'@odata.count')"
            }

            # v2.2 — the $top actually used may be smaller than configured if
            # adaptive reduction kicked in during retries.
            $PageTop = if ($Result.EffectiveTop) { $Result.EffectiveTop } else { $EffectivePageSize }
            if ($PageTop -ne $EffectivePageSize)
            {
                Write-Log "    [ADAPTIVE] Page succeeded at reduced `$top=$PageTop (configured: $EffectivePageSize)"
            }

            $Url = $Response.'@odata.nextLink'
            if ($Url)
            {
                Write-Log "    nextLink present  : YES"

                # v4.1 — sticky adaptive with recovery probing. Replaces the v2.2
                # restore-every-page behavior, which relearned the same failure on
                # every page (measured: 59.4s/page avg vs 10.2s clean).
                $ReducedThisPage = $PageTop -lt $ThisPageRequestedTop
                if ($ReducedThisPage) { $ConsecutiveReduced++ } else { $ConsecutiveReduced = 0 }

                if (-not $StickyActive -and $AdaptiveStickyThreshold -gt 0 -and $ConsecutiveReduced -ge $AdaptiveStickyThreshold)
                {
                    $StickyActive = $true
                    $WorkingTop = $PageTop
                    $PagesSinceProbe = 0
                    $ProbeNote = if ($AdaptiveProbeInterval -gt 0) { "will probe `$top=$EffectivePageSize every $AdaptiveProbeInterval pages" } else { "not trying `$top=$EffectivePageSize again this run" }
                    Write-Log "    [STICKY] We know `$top=$EffectivePageSize isn't working ($ConsecutiveReduced consecutive pages failed at it) — riding at `$top=$WorkingTop; $ProbeNote"
                }
                elseif ($StickyActive)
                {
                    if ($ReducedThisPage -and $PageTop -lt $WorkingTop)
                    {
                        $WorkingTop = $PageTop   # walked down further even from the sticky level
                        Write-Log "    [STICKY] Riding size lowered to `$top=$WorkingTop"
                    }
                    elseif ((-not $ReducedThisPage) -and ($ThisPageRequestedTop -ge $EffectivePageSize))
                    {
                        # A probe page succeeded at full size — service recovered
                        $StickyActive = $false
                        $WorkingTop = $EffectivePageSize
                        $ConsecutiveReduced = 0
                        Write-Log "    [PROBE] Full `$top=$EffectivePageSize succeeded — resuming full page size"
                    }
                }

                # Choose the next page's top
                $NextTop = $EffectivePageSize
                if ($StickyActive)
                {
                    $PagesSinceProbe++
                    if ($AdaptiveProbeInterval -gt 0 -and $PagesSinceProbe -ge $AdaptiveProbeInterval)
                    {
                        $PagesSinceProbe = 0
                        $NextTop = $EffectivePageSize
                        Write-Log "    [PROBE] Next page will try full `$top=$EffectivePageSize"
                    }
                    else
                    {
                        $NextTop = $WorkingTop
                    }
                }

                if ($PageTop -ne $NextTop)
                {
                    $Url = $Url -replace '(\$top=)\d+', ('${1}' + $NextTop)
                    Write-Log "    [ADAPTIVE] Next page `$top=$NextTop"
                }
            }

            # Small-result-set detector (Problem, not Error):
            # If we got fewer rows than $top AND nextLink claims more exists,
            # Graph returned a partial page silently. Microsoft has acknowledged
            # this behavior and says "not a bug" (per BI for Intune team, 2026-05-20).
            # v2.2 — compare against $PageTop (the size actually requested), not
            # the configured size, so adaptively reduced pages don't false-flag.
            if (($PageCount -lt $PageTop) -and ($Url))
            {
                Write-Log "    [PROBLEM] Small result set — got $PageCount, requested $PageTop, but nextLink present"
                $Problems.Add([PSCustomObject]@{
                        Type         = 'SmallResultSet'
                        Endpoint     = $Endpoint.Name
                        Page         = $Page
                        RequestedUrl = $RequestedUrl
                        Requested    = $PageTop
                        Returned     = $PageCount
                        NextLink     = $Url
                        Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                        Description  = "Got $PageCount of $PageTop requested, but nextLink present — Graph claims more data exists"
                    })
            }

            # v2.3 — pagination loop detection
            if ($Url -and (-not $SeenLinks.Add($Url)))
            {
                Write-Log "    [PROBLEM] Pagination loop — nextLink after page $Page was already served earlier. Breaking out."
                $Problems.Add([PSCustomObject]@{
                        Type         = 'PaginationLoop'
                        Endpoint     = $Endpoint.Name
                        Page         = $Page
                        RequestedUrl = $RequestedUrl
                        Requested    = $PageTop
                        Returned     = $PageCount
                        NextLink     = $Url
                        Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                        Description  = "Graph re-served a previously seen nextLink after page $Page (cycling skiptoken)"
                    })
                $Url = $null
            }
        }
        catch
        {
            Write-Log "    [FATAL] $($Endpoint.Name) page $Page failed all retries"
            Write-Log "    Last error: $($_.Exception.Message)"

            # v3.6 — Poison-record isolation. When size reduction bottoms out,
            # the failure is per-RECORD, not per-page: a specific item cannot
            # be served through $expand at any page size (observed in the
            # field down to $top=1). Rescue: refetch this page WITHOUT the
            # expand (metadata always serves), then pull assignments per item
            # via PerItemUrl — which both unblocks pagination and identifies
            # exactly which record is unservable.
            $Rescued = $false
            if ($Endpoint.Expand -and $Endpoint.PSObject.Properties['PerItemUrl'] -and $Endpoint.PerItemUrl)
            {
                Write-Log "    [RESCUE] Refetching page $Page without `$expand to isolate the poison record..."
                $NoExpandUrl = ($RequestedUrl -replace '\$expand=[^&]+&', '') -replace '[?&]\$expand=[^&]+', ''
                try
                {
                    $RescueResult = Invoke-GraphRequestWithRetry -Uri $NoExpandUrl -Headers $Headers `
                        -MaxRetries $MaxRetries -PageNumber $Page -Endpoint "$($Endpoint.Name)/rescue" -TimeoutSec $TimeoutSec
                    foreach ($e in $RescueResult.RetryLog) { $RetryLog.Add($e) }
                    $RescueItems = $RescueResult.Response.value
                    Write-Log "    [RESCUE] Metadata-only fetch succeeded: $($RescueItems.Count) items. Probing assignments per item..."

                    foreach ($Item in $RescueItems)
                    {
                        $ItemUrl = $Endpoint.PerItemUrl -replace '\{id\}', $Item.id
                        $ItemWatch = [System.Diagnostics.Stopwatch]::StartNew()
                        try
                        {
                            $ItemResult = Invoke-GraphRequestWithRetry -Uri $ItemUrl -Headers $Headers `
                                -MaxRetries 2 -Endpoint "$($Endpoint.Name)/perItem" -TimeoutSec $TimeoutSec
                            $ItemWatch.Stop()
                            $AssignCount = $ItemResult.Response.value.Count
                            $Item | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $ItemResult.Response.value -Force
                            $Flag = if ($ItemWatch.ElapsedMilliseconds -gt 10000 -or $AssignCount -gt 500) { '  <-- SUSPECT (slow or heavy)' } else { '' }
                            Write-Log "      $($Item.id) '$($Item.displayName)': $AssignCount assignments in $($ItemWatch.ElapsedMilliseconds)ms$Flag"
                            if ($Flag)
                            {
                                $Problems.Add([PSCustomObject]@{
                                        Type         = 'HeavyRecord'
                                        Endpoint     = $Endpoint.Name
                                        Page         = $Page
                                        RequestedUrl = $ItemUrl
                                        Requested    = 0
                                        Returned     = $AssignCount
                                        NextLink     = ''
                                        Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                                        Description  = "'$($Item.displayName)' ($($Item.id)) on the expand-failing page: $AssignCount assignments, per-item fetch $($ItemWatch.ElapsedMilliseconds)ms — candidate poison record"
                                    })
                            }
                        }
                        catch
                        {
                            $ItemWatch.Stop()
                            Write-Log "      $($Item.id) '$($Item.displayName)': per-item assignments FAILED after $($ItemWatch.ElapsedMilliseconds)ms — $($_.Exception.Message)  <-- POISON RECORD"
                            $Problems.Add([PSCustomObject]@{
                                    Type         = 'UnservableRecord'
                                    Endpoint     = $Endpoint.Name
                                    Page         = $Page
                                    RequestedUrl = $ItemUrl
                                    Requested    = 0
                                    Returned     = 0
                                    NextLink     = ''
                                    Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                                    Description  = "'$($Item.displayName)' ($($Item.id)) cannot serve assignments even per-item — this record blocks `$expand pagination at any page size"
                                })
                        }
                    }

                    $Results.AddRange($RescueItems)
                    $Problems.Add([PSCustomObject]@{
                            Type         = 'PageRescued'
                            Endpoint     = $Endpoint.Name
                            Page         = $Page
                            RequestedUrl = $RequestedUrl
                            Requested    = 0
                            Returned     = $RescueItems.Count
                            NextLink     = ''
                            Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                            Description  = "Page $Page unservable via `$expand at any size; recovered via no-expand fetch + per-item assignments ($($RescueItems.Count) items)"
                        })

                    # Resume pagination: re-attach the expand to the rescue nextLink
                    $Url = $RescueResult.Response.'@odata.nextLink'
                    if ($Url)
                    {
                        $Url = "$Url&`$expand=$($Endpoint.Expand)"
                        Write-Log "    [RESCUE] Pagination resumed — expand re-attached for subsequent pages"
                    }
                    $Rescued = $true
                }
                catch
                {
                    Write-Log "    [RESCUE] Metadata-only fetch ALSO failed ($($_.Exception.Message)) — endpoint itself is down for this range"
                }
            }

            if (-not $Rescued)
            {
                $FatalError = $true
                break
            }
        }

    } while ($Url)

    return [PSCustomObject]@{
        EndpointName      = $Endpoint.Name
        Results           = $Results
        RetryLog          = $RetryLog
        Problems          = $Problems
        Pages             = $Page
        TotalMs           = $TotalMs
        FatalError        = $FatalError
        ItemCount         = $Results.Count
        EffectivePageSize = $EffectivePageSize
    }
}

function Get-AssignmentScaleDiagnostic
{
    param(
        [PSCustomObject]$Endpoint,
        [hashtable]$Headers,
        [int]$TimeoutSec = 60,
        [int]$ItemPageSize = 100   # Page size for the no-expand ID collection pass
    )

    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] Assignment scale diagnostic — $($Endpoint.Name)"
    Write-Log "  Collecting all items without expand first..."

    # Collect all item IDs without expand — should be fast and reliable
    $AllItems = [System.Collections.Generic.List[object]]::new()
    $BaseUrl = "$($Endpoint.BaseUrl)?`$select=id,displayName&`$top=$ItemPageSize"

    try
    {
        do
        {
            Assert-GraphToken   # v2.1
            $Response = Invoke-RestMethod -Method Get -Uri $BaseUrl -Headers $Headers `
                -TimeoutSec $TimeoutSec -ErrorAction Stop
            $AllItems.AddRange($Response.value)
            $BaseUrl = $Response.'@odata.nextLink'
            Write-Log "  Collected $($AllItems.Count) items so far..."
        } while ($BaseUrl)
    }
    catch
    {
        Write-Log "  [ERROR] Failed to collect item list: $($_.Exception.Message)"
        return $null
    }

    Write-Log "  Total items found : $($AllItems.Count)"
    Write-Log "  Testing assignments per item individually...`n"

    $Results = [System.Collections.Generic.List[object]]::new()
    $Tested = 0
    $Failed = 0

    foreach ($Item in $AllItems)
    {
        $Tested++
        $AssignUrl = $Endpoint.PerItemUrl -replace '\{id\}', $Item.id
        Assert-GraphToken   # v2.1
        $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $Status = 'OK'
        $AssignCount = 0
        $HasAllDevices = $false
        $HasAllUsers = $false
        $AssignTargets = ''
        $AssignResponse = $null

        try
        {
            $AssignResponse = Invoke-RestMethod -Method Get -Uri $AssignUrl -Headers $Headers `
                -TimeoutSec $TimeoutSec -ErrorAction Stop
            $StopWatch.Stop()
            $AssignCount = $AssignResponse.value.Count
            $HasAllDevices = ($AssignResponse.value.target.'@odata.type' -contains '#microsoft.graph.allDevicesAssignmentTarget')
            $HasAllUsers = ($AssignResponse.value.target.'@odata.type' -contains '#microsoft.graph.allLicensedUsersAssignmentTarget')

            # Build readable assignment target summary
            $AssignTargets = ($AssignResponse.value | ForEach-Object {
                    "$($_.intent):$($_.target.'@odata.type' -replace '#microsoft.graph.','')"
                }) -join '; '
        }
        catch
        {
            $StopWatch.Stop()
            $Status = "HTTP $($_.Exception.Response.StatusCode.value__)"
            $Failed++
        }

        $Entry = [PSCustomObject]@{
            Endpoint          = $Endpoint.Name
            ItemId            = $Item.id
            DisplayName       = $Item.displayName
            AssignCount       = $AssignCount
            HasAllDevices     = $HasAllDevices
            HasAllUsers       = $HasAllUsers
            AssignmentTargets = $AssignTargets
            ElapsedMs         = $StopWatch.ElapsedMilliseconds
            Status            = $Status
        }

        $Results.Add($Entry)

        $Flag = if ($HasAllDevices)
        {
            ' <-- ALL DEVICES'
        }
        elseif ($HasAllUsers)
        {
            ' <-- ALL USERS'
        }
        else
        {
            ''
        }
        Write-Log "  [$Status] $($Item.displayName)$Flag | Assignments: $AssignCount | $($StopWatch.ElapsedMilliseconds)ms"

        if ($Tested % 25 -eq 0)
        {
            Write-Log "  --- Progress: $Tested / $($AllItems.Count) tested, $Failed failed ---"
        }
    }

    Write-Log "`n  Scale diagnostic summary — $($Endpoint.Name):"
    Write-Log "    Items tested        : $($Results.Count)"
    Write-Log "    Failed requests     : $Failed"
    Write-Log "    All Devices scope   : $(($Results | Where-Object HasAllDevices).Count) items"
    Write-Log "    All Users scope     : $(($Results | Where-Object HasAllUsers).Count) items"
    Write-Log "    Unassigned items    : $(($Results | Where-Object { $_.AssignCount -eq 0 }).Count) items"

    if ($Results.Count -gt 0)
    {
        Write-Log "    Avg response time   : $([math]::Round(($Results | Measure-Object ElapsedMs -Average).Average, 1))ms"
        Write-Log "    Max response time   : $(($Results | Measure-Object ElapsedMs -Maximum).Maximum)ms"
        $Slowest = $Results | Sort-Object ElapsedMs -Descending | Select-Object -First 1
        Write-Log "    Slowest item        : $($Slowest.DisplayName) ($($Slowest.ElapsedMs)ms)"

        # Top 10 by assignment count — most likely contributors to backend load
        Write-Log "`n    Top 10 items by assignment count:"
        $Results | Sort-Object AssignCount -Descending | Select-Object -First 10 | ForEach-Object {
            Write-Log "      $($_.AssignCount.ToString().PadLeft(4))  $($_.DisplayName)"
        }
    }

    return $Results
}

function Invoke-SingleExportJob
{
    <#
    .SYNOPSIS
        Runs one Intune reports export job end to end: create, poll, download,
        count rows. Shared by Invoke-ExportApiDiagnostic and
        Invoke-ExportComparisonDiagnostic.
    .DESCRIPTION
        Returns a result object with timings, row count, final status, and a
        FailureStage field ('none','create','poll:failed','poll:stuck',
        'download') so callers can map failures to Problem entries with their
        own context. When -TallyColumn is set, also returns a hashtable of
        row counts keyed by that CSV column (resolved from the header). When
        -KeyColumn and -ExpectedKeyValue are provided, counts rows NOT matching
        that value into MismatchRows so callers can detect a filter the
        service ignored.
    #>
    param(
        [string]$ReportName,
        [string]$Filter = '',
        [string]$Format = 'csv',
        [int]$PollIntervalSec = 10,
        [int]$PollTimeoutSec = 900,
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 60,
        [string]$ZipLabel = '',
        [string]$TallyColumn = '',        # v3.2 — CSV column name to tally row counts by (resolved from header)
        [string]$KeyColumn = '',          # v3.2 — CSV column name for -ExpectedKeyValue validation
        [string]$ExpectedKeyValue = '',
        [switch]$DeleteZipAfterCount
    )

    if ([string]::IsNullOrWhiteSpace($ZipLabel)) { $ZipLabel = $ReportName }

    $Entry = [PSCustomObject]@{
        ReportName    = $ReportName
        Filter        = $Filter
        JobId         = ''
        FinalStatus   = ''
        FailureStage  = 'none'
        CreateMs      = 0
        QueueSec      = 0
        ProcessSec    = 0
        PollCount     = 0
        TotalSec      = 0
        DownloadMs    = 0
        ZipBytes      = 0
        CsvRows       = -1
        MismatchRows  = 0
        KeyCounts     = $null
        ZipPath       = ''
        RetryLog      = [System.Collections.Generic.List[object]]::new()
    }
    $JobStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    #region 1. Create
    $BodyHash = @{
        reportName       = $ReportName
        format           = $Format
        localizationType = 'LocalizedValuesAsAdditionalColumn'
    }
    if (-not [string]::IsNullOrWhiteSpace($Filter)) { $BodyHash.filter = $Filter }
    $CreateBody = $BodyHash | ConvertTo-Json

    try
    {
        $CreateResult = Invoke-GraphRequestWithRetry `
            -Uri 'https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs' `
            -Headers $Headers -MaxRetries $MaxRetries -Endpoint "exportJobs/$ZipLabel" `
            -TimeoutSec $TimeoutSec -Method 'Post' -Body $CreateBody
        foreach ($e in $CreateResult.RetryLog) { $Entry.RetryLog.Add($e) }
    }
    catch
    {
        Write-Log "    [ERROR] Job creation failed: $($_.Exception.Message)"
        $Entry.FinalStatus = 'createFailed'
        $Entry.FailureStage = 'create'
        return $Entry
    }

    $Job = $CreateResult.Response
    $Entry.JobId = $Job.id
    $Entry.CreateMs = $CreateResult.TotalElapsedMs
    $Status = $Job.status
    Write-Log "    Job created in $($CreateResult.TotalElapsedMs)ms — id: $($Job.id)$(if ($Filter) { ", filter: $Filter" })"
    #endregion

    #region 2. Poll
    $PollUrl = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$($Job.id)')"
    $Deadline = (Get-Date).AddSeconds($PollTimeoutSec)

    while (($Status -notin @('completed', 'failed')) -and ((Get-Date) -lt $Deadline))
    {
        Start-Sleep -Seconds $PollIntervalSec
        try
        {
            $PollResult = Invoke-GraphRequestWithRetry -Uri $PollUrl -Headers $Headers `
                -MaxRetries $MaxRetries -Endpoint "exportJobs/$ZipLabel/poll" -TimeoutSec $TimeoutSec
            foreach ($e in $PollResult.RetryLog) { $Entry.RetryLog.Add($e) }
            $Job = $PollResult.Response
            $Status = $Job.status
            $Entry.PollCount++
            if (($Entry.QueueSec -eq 0) -and ($Status -ne 'notStarted'))
            {
                $Entry.QueueSec = [math]::Round($JobStopwatch.Elapsed.TotalSeconds)
            }
        }
        catch
        {
            Write-Log "    [WARN] Poll failed ($($_.Exception.Message)) — will retry at next interval"
        }
    }

    $Entry.TotalSec = [math]::Round($JobStopwatch.Elapsed.TotalSeconds)
    $Entry.ProcessSec = $Entry.TotalSec - $Entry.QueueSec
    $Entry.FinalStatus = $Status

    if ($Status -eq 'failed')
    {
        Write-Log "    [ERROR] Job reported FAILED after $($Entry.TotalSec)s"
        $Entry.FailureStage = 'poll:failed'
        return $Entry
    }
    if ($Status -ne 'completed')
    {
        Write-Log "    [ERROR] Job STUCK — still '$Status' after ${PollTimeoutSec}s ($($Entry.PollCount) polls)"
        $Entry.FailureStage = 'poll:stuck'
        return $Entry
    }
    Write-Log "    Completed — queue: $($Entry.QueueSec)s, processing: $($Entry.ProcessSec)s, polls: $($Entry.PollCount)"
    #endregion

    #region 3. Download (SAS URL — no Graph bearer token)
    $ZipPath = Join-Path $LogDir "ExportDiag_${RunTimestamp}_$ZipLabel.zip"
    $DownloadOk = $false
    for ($DlAttempt = 1; $DlAttempt -le 2 -and -not $DownloadOk; $DlAttempt++)
    {
        $DlWatch = [System.Diagnostics.Stopwatch]::StartNew()
        try
        {
            Invoke-WebRequest -Uri $Job.url -OutFile $ZipPath -UseBasicParsing -TimeoutSec 600
            $DlWatch.Stop()
            $DownloadOk = $true
            $Entry.DownloadMs = $DlWatch.ElapsedMilliseconds
            $Entry.ZipBytes = (Get-Item $ZipPath).Length
            $Entry.ZipPath = $ZipPath
            Write-Log "    Downloaded $([math]::Round($Entry.ZipBytes / 1KB, 1)) KB in $($Entry.DownloadMs)ms"
        }
        catch
        {
            $DlWatch.Stop()
            Write-Log "    Download attempt $DlAttempt failed: $($_.Exception.Message)"
        }
    }
    if (-not $DownloadOk)
    {
        $Entry.FailureStage = 'download'
        return $Entry
    }
    #endregion

    #region 4. Count rows (streaming; key columns resolved from the CSV header)
    $ExtractDir = Join-Path $LogDir "ExportDiag_${RunTimestamp}_${ZipLabel}_extract"
    try
    {
        Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
        $Csv = Get-ChildItem -Path $ExtractDir -Filter '*.csv' | Select-Object -First 1
        if ($Csv)
        {
            $Rows = 0
            $Reader = [System.IO.StreamReader]::new($Csv.FullName)
            try
            {
                # Resolve column indexes from the header. Fields are quoted:
                # "Col1","Col2",... Split on '","' after trimming outer quotes.
                $HeaderLine = $Reader.ReadLine()
                $HeaderCols = @($HeaderLine.TrimStart('"').TrimEnd('"') -split '","')
                $TallyIdx = if ($TallyColumn) { [array]::IndexOf($HeaderCols, $TallyColumn) } else { -1 }
                $KeyIdx = if ($KeyColumn) { [array]::IndexOf($HeaderCols, $KeyColumn) } else { -1 }
                if ($TallyColumn -and $TallyIdx -lt 0)
                {
                    Write-Log "    [WARN] Tally column '$TallyColumn' not found in CSV header — tally skipped. Header: $HeaderLine"
                }
                if ($KeyColumn -and $KeyIdx -lt 0)
                {
                    Write-Log "    [WARN] Key column '$KeyColumn' not found in CSV header — filter validation skipped. Header: $HeaderLine"
                }
                if ($TallyIdx -ge 0) { $Entry.KeyCounts = @{} }

                # NOTE: '","' splitting is exact only while columns at or before
                # the resolved indexes contain no embedded '","' sequences. The
                # id columns (SettingId/DeviceId/PolicyId) are GUIDs, so indexes
                # this low are safe; free-text columns appear later in the row.
                $NeedFields = ($TallyIdx -ge 0) -or ($KeyIdx -ge 0 -and $ExpectedKeyValue)
                while ($null -ne ($Line = $Reader.ReadLine()))
                {
                    $Rows++
                    if ($NeedFields)
                    {
                        $Fields = $Line.TrimStart('"').TrimEnd('"') -split '","'
                        if ($TallyIdx -ge 0 -and $TallyIdx -lt $Fields.Count)
                        {
                            $K = $Fields[$TallyIdx]
                            if ($Entry.KeyCounts.ContainsKey($K)) { $Entry.KeyCounts[$K]++ }
                            else { $Entry.KeyCounts[$K] = 1 }
                        }
                        if ($KeyIdx -ge 0 -and $ExpectedKeyValue -and $KeyIdx -lt $Fields.Count)
                        {
                            if ($Fields[$KeyIdx] -ne $ExpectedKeyValue)
                            {
                                $Entry.MismatchRows++
                            }
                        }
                    }
                }
            }
            finally
            {
                $Reader.Dispose()
            }
            $Entry.CsvRows = $Rows
        }
        else
        {
            Write-Log "    [WARN] Zip contained no CSV file"
            $Entry.CsvRows = -1
        }
    }
    catch
    {
        Write-Log "    [ERROR] CSV count failed: $($_.Exception.Message)"
    }
    finally
    {
        if (Test-Path $ExtractDir)
        {
            Remove-Item -Path $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($DeleteZipAfterCount -and (Test-Path $ZipPath))
        {
            Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue
            $Entry.ZipPath = ''
        }
    }
    #endregion

    return $Entry
}

function Invoke-ExportApiDiagnostic
{
    <#
    .SYNOPSIS
        Exercises the Intune reports Export API with unfiltered jobs — one per
        report name — for pipeline health baselining (timings, row counts).
    #>
    param(
        [string[]]$Reports,
        [int]$PollIntervalSec = 10,
        [int]$PollTimeoutSec = 900,
        [string]$Format = 'csv',
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 60
    )

    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] ===== Intune Reports Export API Diagnostic ====="
    Write-Log "  Endpoint : POST https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs"
    Write-Log "  Reports  : $($Reports -join ', ')"
    Write-Log "  Polling  : every ${PollIntervalSec}s, deadline ${PollTimeoutSec}s per job"

    $Problems = [System.Collections.Generic.List[object]]::new()
    $RetryLog = [System.Collections.Generic.List[object]]::new()
    $Results = [System.Collections.Generic.List[object]]::new()

    try
    {
        $Overview = (Invoke-GraphRequestWithRetry `
                -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDeviceOverview' `
                -Headers $Headers -MaxRetries $MaxRetries -Endpoint 'managedDeviceOverview' `
                -TimeoutSec $TimeoutSec).Response
        Write-Log "  Baseline : managedDeviceOverview.enrolledDeviceCount = $($Overview.enrolledDeviceCount)"
    }
    catch
    {
        Write-Log "  Baseline : managedDeviceOverview unavailable ($($_.Exception.Message))"
    }

    foreach ($ReportName in $Reports)
    {
        Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] ===== Export report: $ReportName ====="
        $Entry = Invoke-SingleExportJob -ReportName $ReportName -Format $Format `
            -PollIntervalSec $PollIntervalSec -PollTimeoutSec $PollTimeoutSec `
            -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
        foreach ($e in $Entry.RetryLog) { $RetryLog.Add($e) }
        $Results.Add($Entry)

        # Map failure stages to Problem entries
        $ProblemType = switch ($Entry.FailureStage)
        {
            'create' { 'ExportJobCreateFailed' }
            'poll:failed' { 'ExportJobFailed' }
            'poll:stuck' { 'ExportJobStuck' }
            'download' { 'ExportDownloadFailed' }
            default { $null }
        }
        if ($ProblemType)
        {
            Write-Log "    [PROBLEM] $ProblemType for $ReportName"
            $Problems.Add([PSCustomObject]@{
                    Type         = $ProblemType
                    Endpoint     = "exportJobs/$ReportName"
                    Page         = $Entry.PollCount
                    RequestedUrl = 'deviceManagement/reports/exportJobs'
                    Requested    = 0
                    Returned     = 0
                    NextLink     = ''
                    Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                    Description  = "Report '$ReportName' — job $($Entry.JobId) failed at stage '$($Entry.FailureStage)'"
                })
            continue
        }

        Write-Log "    CSV rows (excl. header): $($Entry.CsvRows)"
        if ($Entry.CsvRows -eq 0)
        {
            Write-Log "    [PROBLEM] Empty export — 0 data rows (may be legitimate for this report; review in context)"
            $Problems.Add([PSCustomObject]@{
                    Type         = 'EmptyExport'
                    Endpoint     = "exportJobs/$ReportName"
                    Page         = 0
                    RequestedUrl = 'deviceManagement/reports/exportJobs'
                    Requested    = 0
                    Returned     = 0
                    NextLink     = ''
                    Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                    Description  = "Report '$ReportName' — export completed but contained 0 data rows"
                })
        }
    }

    Write-Log "`n  Export API diagnostic summary:"
    Write-Log "    Reports tested   : $($Results.Count)"
    Write-Log "    Problems flagged : $($Problems.Count)"
    Write-Log "    Retry events     : $($RetryLog.Count)"

    return [PSCustomObject]@{
        Results  = $Results
        Problems = $Problems
        RetryLog = $RetryLog
    }
}

function Invoke-ExportJobBatch
{
    <#
    .SYNOPSIS
        v4.0 — Runs many export jobs with server-side concurrency from a
        single client thread: submit up to $Concurrency jobs, poll them
        round-robin, harvest completions, submit the next from the queue.
        No client threads — so the shared token refresh, logging, and retry
        machinery all work unchanged.
    .DESCRIPTION
        Requests: objects with Key and Filter properties. Returns a hashtable
        keyed by Key with per-job results (CsvRows, MismatchRows, JobId,
        FailureStage, TotalSec). Row counting validates each row's KeyColumn
        value against the request Key when KeyColumn is provided.
    #>
    param(
        [array]$Requests,
        [string]$ReportName,
        [string]$KeyColumn = '',
        [int]$Concurrency = 5,
        [int]$PollIntervalSec = 10,
        [int]$PollTimeoutSec = 900,
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 60,
        [switch]$KeepZips
    )

    $RetryLog = [System.Collections.Generic.List[object]]::new()
    $Out = @{}
    $Queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($R in $Requests) { $Queue.Enqueue($R) }
    $InFlight = [System.Collections.Generic.List[object]]::new()
    $Seq = 0
    $DoneCount = 0

    while ($Queue.Count -gt 0 -or $InFlight.Count -gt 0)
    {
        # Fill the in-flight slots
        while ($InFlight.Count -lt $Concurrency -and $Queue.Count -gt 0)
        {
            $Req = $Queue.Dequeue()
            $Seq++
            $BodyHash = @{ reportName = $ReportName; format = 'csv'; localizationType = 'LocalizedValuesAsAdditionalColumn' }
            if ($Req.Filter) { $BodyHash.filter = $Req.Filter }
            try
            {
                $CR = Invoke-GraphRequestWithRetry `
                    -Uri 'https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs' `
                    -Headers $Headers -MaxRetries $MaxRetries -Endpoint "exportJobs/batch$Seq" `
                    -TimeoutSec $TimeoutSec -Method 'Post' -Body ($BodyHash | ConvertTo-Json)
                foreach ($e in $CR.RetryLog) { $RetryLog.Add($e) }
                $InFlight.Add([PSCustomObject]@{
                        Key      = $Req.Key
                        Seq      = $Seq
                        JobId    = $CR.Response.id
                        PollUrl  = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$($CR.Response.id)')"
                        Deadline = (Get-Date).AddSeconds($PollTimeoutSec)
                        Watch    = [System.Diagnostics.Stopwatch]::StartNew()
                    })
                Write-Log "    [batch] submitted $Seq/$($Requests.Count) ($($Req.Key)) — in flight: $($InFlight.Count)"
            }
            catch
            {
                Write-Log "    [batch] SUBMIT FAILED for $($Req.Key): $($_.Exception.Message)"
                $Out[$Req.Key] = [PSCustomObject]@{ JobId = ''; FailureStage = 'create'; CsvRows = -1; MismatchRows = 0; TotalSec = 0 }
                $DoneCount++
            }
        }

        if ($InFlight.Count -eq 0) { break }
        Start-Sleep -Seconds $PollIntervalSec

        $Done = @()
        foreach ($J in $InFlight)
        {
            try
            {
                $P = Invoke-GraphRequestWithRetry -Uri $J.PollUrl -Headers $Headers `
                    -MaxRetries $MaxRetries -Endpoint "exportJobs/batch$($J.Seq)/poll" -TimeoutSec $TimeoutSec
                foreach ($e in $P.RetryLog) { $RetryLog.Add($e) }
                $Status = $P.Response.status

                if ($Status -eq 'completed')
                {
                    $Res = [PSCustomObject]@{ JobId = $J.JobId; FailureStage = 'none'; CsvRows = -1; MismatchRows = 0; TotalSec = [math]::Round($J.Watch.Elapsed.TotalSeconds) }
                    $ZipPath = Join-Path $LogDir "ExportDiag_${RunTimestamp}_batch$($J.Seq).zip"
                    try
                    {
                        Invoke-WebRequest -Uri $P.Response.url -OutFile $ZipPath -UseBasicParsing -TimeoutSec 600
                        $ExtractDir = Join-Path $LogDir "ExportDiag_${RunTimestamp}_batch$($J.Seq)_extract"
                        Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
                        $Csv = Get-ChildItem -Path $ExtractDir -Filter '*.csv' | Select-Object -First 1
                        if ($Csv)
                        {
                            $Rows = 0
                            $Reader = [System.IO.StreamReader]::new($Csv.FullName)
                            try
                            {
                                $HeaderCols = @(($Reader.ReadLine()).TrimStart('"').TrimEnd('"') -split '","')
                                $KeyIdx = if ($KeyColumn) { [array]::IndexOf($HeaderCols, $KeyColumn) } else { -1 }
                                while ($null -ne ($Line = $Reader.ReadLine()))
                                {
                                    $Rows++
                                    if ($KeyIdx -ge 0)
                                    {
                                        $Fields = $Line.TrimStart('"').TrimEnd('"') -split '","'
                                        if ($KeyIdx -lt $Fields.Count -and $Fields[$KeyIdx] -ne $J.Key) { $Res.MismatchRows++ }
                                    }
                                }
                            }
                            finally { $Reader.Dispose() }
                            $Res.CsvRows = $Rows
                        }
                        Remove-Item -Path $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not $KeepZips) { Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue }
                    }
                    catch
                    {
                        Write-Log "    [batch] download/count failed for $($J.Key): $($_.Exception.Message)"
                        $Res.FailureStage = 'download'
                    }
                    $Out[$J.Key] = $Res
                    $Done += $J
                    $DoneCount++
                    Write-Log "    [batch] completed $DoneCount/$($Requests.Count) ($($J.Key)): $($Res.CsvRows) rows in $($Res.TotalSec)s"
                }
                elseif ($Status -eq 'failed')
                {
                    $Out[$J.Key] = [PSCustomObject]@{ JobId = $J.JobId; FailureStage = 'poll:failed'; CsvRows = -1; MismatchRows = 0; TotalSec = [math]::Round($J.Watch.Elapsed.TotalSeconds) }
                    $Done += $J; $DoneCount++
                    Write-Log "    [batch] FAILED ($($J.Key)) — job reported terminal 'failed'"
                }
                elseif ((Get-Date) -gt $J.Deadline)
                {
                    $Out[$J.Key] = [PSCustomObject]@{ JobId = $J.JobId; FailureStage = 'poll:stuck'; CsvRows = -1; MismatchRows = 0; TotalSec = [math]::Round($J.Watch.Elapsed.TotalSeconds) }
                    $Done += $J; $DoneCount++
                    Write-Log "    [batch] STUCK ($($J.Key)) — still '$Status' past ${PollTimeoutSec}s deadline"
                }
            }
            catch
            {
                Write-Log "    [batch] poll failed for $($J.Key): $($_.Exception.Message) — will retry next interval"
            }
        }
        foreach ($D in $Done) { [void]$InFlight.Remove($D) }
    }

    return [PSCustomObject]@{ Results = $Out; RetryLog = $RetryLog }
}

function Invoke-ExportComparisonDiagnostic
{
    <#
    .SYNOPSIS
        Reproduces the silently-incomplete-data bug on the Export API by
        comparing one unfiltered export against per-ID filtered exports
        (BI for Intune's production pattern) for the same report.
    .DESCRIPTION
        Phase A: one unfiltered job. The CSV is streamed once to build row
        counts per key value (PolicyId or SettingId) — simultaneously the
        baseline and the list of ids to test. When keyed on PolicyId, the
        tenant's deviceCompliancePolicies collection is also retrieved as an
        independent cross-check: policies missing from the unfiltered export
        are logged, and policy display names are resolved into the output.
        Phase B: one filtered job per key value. Row counts are compared to
        the baseline; every returned row is validated against the requested
        id to detect a filter the service silently ignored.
        Phase C: mismatches are re-tested once (if enabled) to rule out
        check-in drift, then written to a reconciliation CSV.

        Verdicts:
          FilteredExceedsBaseline — the unfiltered export UNDERCOUNTS. This is
            the reported bug: Microsoft's own API contradicting itself.
          FilteredBelowBaseline   — the filtered job returned fewer rows than
            the unfiltered baseline holds for that id.
          FilterNotHonored        — filtered job returned rows for other ids.
    #>
    param(
        [string]$ReportName,
        [string]$KeyColumn = 'PolicyId',
        [string]$FilterTemplate = "PolicyId eq '{0}'",
        [string]$ListReport = '',
        [string]$ListColumn = '',
        [int]$MaxSettings = 0,
        [switch]$RetestMismatches,
        [switch]$BracketBaseline,
        [switch]$KeepAllZips,
        [int]$Concurrency = 5,
        [int]$PollIntervalSec = 10,
        [int]$PollTimeoutSec = 900,
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 60
    )

    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] ===== Export API Comparison Diagnostic (unfiltered vs per-$KeyColumn) ====="
    Write-Log "  Report          : $ReportName"
    Write-Log "  Key column      : $KeyColumn"
    Write-Log "  Filter template : $FilterTemplate"

    $Problems = [System.Collections.Generic.List[object]]::new()
    $RetryLog = [System.Collections.Generic.List[object]]::new()
    $Reconciliation = [System.Collections.Generic.List[object]]::new()

    #region Phase A — unfiltered baseline
    Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] Phase A: unfiltered baseline export"
    $Baseline = Invoke-SingleExportJob -ReportName $ReportName -ZipLabel "${ReportName}_BASELINE" `
        -PollIntervalSec $PollIntervalSec -PollTimeoutSec $PollTimeoutSec `
        -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec -TallyColumn $KeyColumn
    foreach ($e in $Baseline.RetryLog) { $RetryLog.Add($e) }

    # v4.5.1 — one resubmission on baseline failure. A terminal 'failed' job
    # (observed 20260715: server-side failure after 265s on a job that
    # succeeded the previous day) costs the entire comparison; one retry is
    # cheap insurance against transient export-service health.
    if ($Baseline.FailureStage -ne 'none' -or $Baseline.CsvRows -lt 0)
    {
        Write-Log "    [WARN] Baseline failed at stage '$($Baseline.FailureStage)' — resubmitting once..."
        $Baseline = Invoke-SingleExportJob -ReportName $ReportName -ZipLabel "${ReportName}_BASELINE2ND" `
            -PollIntervalSec $PollIntervalSec -PollTimeoutSec $PollTimeoutSec `
            -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec -TallyColumn $KeyColumn
        foreach ($e in $Baseline.RetryLog) { $RetryLog.Add($e) }
    }

    if ($Baseline.FailureStage -ne 'none' -or $Baseline.CsvRows -lt 0)
    {
        Write-Log "    [PROBLEM] Baseline export failed at stage '$($Baseline.FailureStage)' — comparison aborted"
        $Problems.Add([PSCustomObject]@{
                Type         = 'ExportJobFailed'
                Endpoint     = "exportJobs/$ReportName (baseline)"
                Page         = 0
                RequestedUrl = 'deviceManagement/reports/exportJobs'
                Requested    = 0
                Returned     = 0
                NextLink     = ''
                Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                Description  = "Comparison baseline for '$ReportName' failed at stage '$($Baseline.FailureStage)'"
            })
        return [PSCustomObject]@{ Baseline = $Baseline; Reconciliation = $Reconciliation; Problems = $Problems; RetryLog = $RetryLog; ReconciliationCsv = '' }
    }

    $AllIds = @($Baseline.KeyCounts.Keys | Where-Object { $_ })   # drop empty-id rows if any
    Write-Log "    Baseline rows           : $($Baseline.CsvRows)"
    Write-Log "    Distinct $KeyColumn values : $($AllIds.Count)"

    # v3.2 — independent cross-check: when keyed on PolicyId, the tenant's own
    # compliance policy collection is a third source of truth. A policy that
    # exists (and is assigned) but is absent from the unfiltered export is
    # evidence of missing data without running a single filtered job.
    $KeyNames = @{}
    if ($KeyColumn -eq 'PolicyId')
    {
        try
        {
            $PolUrl = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?$select=id,displayName&$top=100'
            while ($PolUrl)
            {
                $PolResult = Invoke-GraphRequestWithRetry -Uri $PolUrl -Headers $Headers `
                    -MaxRetries $MaxRetries -Endpoint 'deviceCompliancePolicies' -TimeoutSec $TimeoutSec
                foreach ($e in $PolResult.RetryLog) { $RetryLog.Add($e) }
                foreach ($Pol in $PolResult.Response.value) { $KeyNames[$Pol.id] = $Pol.displayName }
                $PolUrl = $PolResult.Response.'@odata.nextLink'
            }
            Write-Log "    Tenant compliance policies : $($KeyNames.Count)"

            $MissingFromExport = @($KeyNames.Keys | Where-Object { $AllIds -notcontains $_ })
            $UnknownInExport = @($AllIds | Where-Object { -not $KeyNames.ContainsKey($_) })
            if ($MissingFromExport.Count -gt 0)
            {
                Write-Log "    [WARN] $($MissingFromExport.Count) tenant policies have NO rows in the unfiltered export (legitimate if unassigned; suspicious otherwise):"
                foreach ($Mp in $MissingFromExport)
                {
                    Write-Log "      $Mp : $($KeyNames[$Mp])"
                }
            }
            if ($UnknownInExport.Count -gt 0)
            {
                Write-Log "    [INFO] $($UnknownInExport.Count) PolicyIds in the export are not in deviceCompliancePolicies (deleted policies with lingering state, or unified-platform policies):"
                foreach ($Up in ($UnknownInExport | Select-Object -First 10))
                {
                    Write-Log "      $Up"
                }
            }
        }
        catch
        {
            Write-Log "    [WARN] Policy cross-check unavailable: $($_.Exception.Message)"
        }
    }

    # v3.3 — Phase A2: when production's enumeration source is another export
    # report, derive the id list the same way production does. Ids present in
    # the list report but ABSENT from the unfiltered baseline are the
    # strongest possible signal: the bulk export omitted an entire id.
    if (-not [string]::IsNullOrWhiteSpace($ListReport))
    {
        if ([string]::IsNullOrWhiteSpace($ListColumn)) { $ListColumn = $KeyColumn }
        Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] Phase A2: enumeration list from export report '$ListReport' (column: $ListColumn)"
        $ListJob = Invoke-SingleExportJob -ReportName $ListReport -ZipLabel "${ListReport}_LIST" `
            -PollIntervalSec $PollIntervalSec -PollTimeoutSec $PollTimeoutSec `
            -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec -TallyColumn $ListColumn
        foreach ($e in $ListJob.RetryLog) { $RetryLog.Add($e) }

        if ($ListJob.FailureStage -ne 'none' -or $null -eq $ListJob.KeyCounts)
        {
            Write-Log "    [WARN] List report failed at stage '$($ListJob.FailureStage)' — falling back to baseline-derived ids"
        }
        else
        {
            $ListIds = @($ListJob.KeyCounts.Keys | Where-Object { $_ })
            Write-Log "    List report rows        : $($ListJob.CsvRows)"
            Write-Log "    Distinct ids in list    : $($ListIds.Count)"

            $InListNotBaseline = @($ListIds | Where-Object { $AllIds -notcontains $_ })
            $InBaselineNotList = @($AllIds | Where-Object { $ListIds -notcontains $_ })
            if ($InListNotBaseline.Count -gt 0)
            {
                Write-Log "    [PROBLEM] $($InListNotBaseline.Count) ids in the list report have ZERO rows in the unfiltered baseline — bulk export may have omitted them entirely (filtered jobs will verify):"
                foreach ($MissId in ($InListNotBaseline | Select-Object -First 10))
                {
                    Write-Log "      $MissId"
                }
                $Problems.Add([PSCustomObject]@{
                        Type         = 'ExportIdMissingFromBulk'
                        Endpoint     = "exportJobs/$ReportName"
                        Page         = 0
                        RequestedUrl = "list=$ListReport"
                        Requested    = $ListIds.Count
                        Returned     = $AllIds.Count
                        NextLink     = ''
                        Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                        Description  = "$($InListNotBaseline.Count) $KeyColumn values present in '$ListReport' are absent from the unfiltered '$ReportName' export: $($InListNotBaseline -join '; ')"
                    })
            }
            if ($InBaselineNotList.Count -gt 0)
            {
                Write-Log "    [INFO] $($InBaselineNotList.Count) ids in the baseline are not in the list report (stale state rows, or list report scoping)"
            }
            # Production iterates the list report's ids — so does the test.
            # Union keeps baseline-only ids visible in the reconciliation too.
            $AllIds = @(@($ListIds) + @($InBaselineNotList) | Select-Object -Unique)
        }
    }

    $TestIds = if ($MaxSettings -gt 0 -and $AllIds.Count -gt $MaxSettings)
    {
        Write-Log "    Testing top $MaxSettings $KeyColumn values by baseline row count (of $($AllIds.Count))"
        @($AllIds | Sort-Object { $Baseline.KeyCounts[$_] } -Descending | Select-Object -First $MaxSettings)
    }
    else
    {
        $AllIds
    }
    $EstMinutes = [math]::Round($TestIds.Count * 50 / 60)
    Write-Log "    Filtered jobs to run    : $($TestIds.Count) (estimated ~$EstMinutes min at ~50s/job)"
    #endregion

    #region Phase B — per-id filtered jobs (batched, v4.0)
    # Server-side async orchestration: keep $Concurrency export jobs in flight
    # from one client thread. The server does the work; the client only polls.
    Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] Phase B: $($TestIds.Count) filtered jobs, concurrency $Concurrency"
    $Requests = @($TestIds | ForEach-Object { [PSCustomObject]@{ Key = $_; Filter = ($FilterTemplate -f $_) } })
    $Batch = Invoke-ExportJobBatch -Requests $Requests -ReportName $ReportName -KeyColumn $KeyColumn `
        -Concurrency $Concurrency -PollIntervalSec $PollIntervalSec -PollTimeoutSec $PollTimeoutSec `
        -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec -KeepZips:$KeepAllZips
    foreach ($e in $Batch.RetryLog) { $RetryLog.Add($e) }

    # Verdicts from batch results; mismatches queue for a batched retest
    $SumFiltered = 0
    $PendingRetest = [System.Collections.Generic.List[string]]::new()
    $Interim = @{}
    foreach ($KeyValue in $TestIds)
    {
        $R = $Batch.Results[$KeyValue]
        $BaselineCount = if ($Baseline.KeyCounts.ContainsKey($KeyValue)) { $Baseline.KeyCounts[$KeyValue] } else { 0 }
        $Verdict = 'Match'
        if ($null -eq $R -or $R.FailureStage -ne 'none') { $Verdict = "JobFailed:$(if ($R) { $R.FailureStage } else { 'unknown' })" }
        elseif ($R.MismatchRows -gt 0)
        {
            $Verdict = 'FilterNotHonored'
            Write-Log "    [PROBLEM] Filter not honored — $KeyValue`: $($R.MismatchRows) of $($R.CsvRows) rows carry a different $KeyColumn"
        }
        elseif ($R.CsvRows -ne $BaselineCount)
        {
            $Verdict = 'PendingRetest'
            if ($RetestMismatches) { $PendingRetest.Add($KeyValue) }
        }
        if ($R -and $R.CsvRows -gt 0) { $SumFiltered += $R.CsvRows }
        $Interim[$KeyValue] = [PSCustomObject]@{ Result = $R; BaselineCount = $BaselineCount; Verdict = $Verdict; RetestRows = $null }
    }

    if ($PendingRetest.Count -gt 0)
    {
        Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] Retesting $($PendingRetest.Count) mismatches (batched) to rule out drift..."
        $RetestReqs = @($PendingRetest | ForEach-Object { [PSCustomObject]@{ Key = $_; Filter = ($FilterTemplate -f $_) } })
        $RetestBatch = Invoke-ExportJobBatch -Requests $RetestReqs -ReportName $ReportName -KeyColumn $KeyColumn `
            -Concurrency $Concurrency -PollIntervalSec $PollIntervalSec -PollTimeoutSec $PollTimeoutSec `
            -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec -KeepZips:$KeepAllZips
        foreach ($e in $RetestBatch.RetryLog) { $RetryLog.Add($e) }
        foreach ($K in $PendingRetest)
        {
            $RT = $RetestBatch.Results[$K]
            if ($RT -and $RT.FailureStage -eq 'none') { $Interim[$K].RetestRows = $RT.CsvRows }
        }
    }

    foreach ($KeyValue in $TestIds)
    {
        $I = $Interim[$KeyValue]
        $R = $I.Result
        $BaselineCount = $I.BaselineCount
        $KeyLabel = if ($KeyNames.ContainsKey($KeyValue)) { "$KeyValue ($($KeyNames[$KeyValue]))" } else { $KeyValue }
        $FilteredRows = if ($R) { $R.CsvRows } else { -1 }

        if ($I.Verdict -eq 'PendingRetest')
        {
            $Direction = if ($FilteredRows -gt $BaselineCount) { 'FilteredExceedsBaseline' } else { 'FilteredBelowBaseline' }
            $Confirmed = if ($null -ne $I.RetestRows)
            {
                (($I.RetestRows -gt $BaselineCount) -and ($Direction -eq 'FilteredExceedsBaseline')) -or
                (($I.RetestRows -lt $BaselineCount) -and ($Direction -eq 'FilteredBelowBaseline'))
            }
            else { $true }

            if ($Confirmed)
            {
                $I.Verdict = $Direction
                $Detail = if ($Direction -eq 'FilteredExceedsBaseline')
                {
                    "UNFILTERED EXPORT UNDERCOUNTS — the filtered job found rows the unfiltered export omitted"
                }
                else
                {
                    "filtered job returned fewer rows than the unfiltered baseline holds for this id"
                }
                Write-Log "    [PROBLEM] $Direction — $KeyLabel`: filtered $FilteredRows$(if ($null -ne $I.RetestRows) { " (retest: $($I.RetestRows))" }), baseline $BaselineCount"
                $Problems.Add([PSCustomObject]@{
                        Type         = 'ExportCountMismatch'
                        Endpoint     = "exportJobs/$ReportName"
                        Page         = 0
                        RequestedUrl = ($FilterTemplate -f $KeyValue)
                        Requested    = $BaselineCount
                        Returned     = $FilteredRows
                        NextLink     = $(if ($null -ne $I.RetestRows) { "retest=$($I.RetestRows)" } else { '' })
                        Timestamp    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                        Description  = "$KeyColumn $KeyLabel — $Direction. Baseline $BaselineCount, filtered $FilteredRows$(if ($null -ne $I.RetestRows) { ", retest $($I.RetestRows)" }). $Detail"
                    })
            }
            else
            {
                $I.Verdict = 'DriftResolved'
            }
        }

        $Reconciliation.Add([PSCustomObject]@{
                KeyColumn     = $KeyColumn
                KeyValue      = $KeyValue
                KeyName       = $(if ($KeyNames.ContainsKey($KeyValue)) { $KeyNames[$KeyValue] } else { '' })
                BaselineRows  = $BaselineCount
                FilteredRows  = $FilteredRows
                RetestRows    = $I.RetestRows
                MismatchRows  = $(if ($R) { $R.MismatchRows } else { 0 })
                Verdict       = $I.Verdict
                FilteredJobId = $(if ($R) { $R.JobId } else { '' })
            })
    }
    #endregion

    #region Phase B2 — bracketing baseline (v3.8)
    # Drift vs truncation discriminator: rerun the unfiltered export AFTER all
    # filtered jobs. Live-tenant drift puts the filtered count BETWEEN the two
    # baselines; a filtered count outside BOTH baselines is deterministic
    # disagreement — the actual bug, not check-in noise.
    $HasMismatches = @($Reconciliation | Where-Object { $_.Verdict -in @('FilteredExceedsBaseline', 'FilteredBelowBaseline') }).Count -gt 0
    if ($BracketBaseline -and $HasMismatches)
    {
        Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] Phase B2: bracketing baseline (second unfiltered export for drift discrimination)"
        $Baseline2 = Invoke-SingleExportJob -ReportName $ReportName -ZipLabel "${ReportName}_BASELINE2" `
            -PollIntervalSec $PollIntervalSec -PollTimeoutSec $PollTimeoutSec `
            -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec -TallyColumn $KeyColumn -DeleteZipAfterCount
        foreach ($e in $Baseline2.RetryLog) { $RetryLog.Add($e) }

        if ($Baseline2.FailureStage -eq 'none' -and $null -ne $Baseline2.KeyCounts)
        {
            Write-Log "    Baseline2 rows: $($Baseline2.CsvRows) (baseline1: $($Baseline.CsvRows))"
            $DriftCount = 0
            $DeterministicCount = 0
            $DeterministicKeys = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($Row in $Reconciliation)
            {
                $B2 = if ($Baseline2.KeyCounts.ContainsKey($Row.KeyValue)) { $Baseline2.KeyCounts[$Row.KeyValue] } else { 0 }
                $Row | Add-Member -NotePropertyName 'Baseline2Rows' -NotePropertyValue $B2 -Force
                if ($Row.Verdict -in @('FilteredExceedsBaseline', 'FilteredBelowBaseline'))
                {
                    $Lo = [math]::Min($Row.BaselineRows, $B2)
                    $Hi = [math]::Max($Row.BaselineRows, $B2)
                    if ($Row.FilteredRows -ge $Lo -and $Row.FilteredRows -le $Hi)
                    {
                        $Row | Add-Member -NotePropertyName 'FinalVerdict' -NotePropertyValue 'DriftLikely' -Force
                        $DriftCount++
                    }
                    else
                    {
                        $Row | Add-Member -NotePropertyName 'FinalVerdict' -NotePropertyValue 'Deterministic' -Force
                        $DeterministicCount++
                        [void]$DeterministicKeys.Add($Row.KeyValue)
                        Write-Log "    [PROBLEM] DETERMINISTIC mismatch — $($Row.KeyValue)$(if ($Row.KeyName) { " ($($Row.KeyName))" }): baseline1=$($Row.BaselineRows), baseline2=$B2, filtered=$($Row.FilteredRows) falls outside both"
                    }
                }
                else
                {
                    $Row | Add-Member -NotePropertyName 'FinalVerdict' -NotePropertyValue $Row.Verdict -Force
                }
            }
            Write-Log "    Bracket re-verdict: $DriftCount mismatches consistent with check-in drift (not flagged); $DeterministicCount deterministic"

            # Keep only deterministic count mismatches in the Problems evidence
            $Kept = [System.Collections.Generic.List[object]]::new()
            foreach ($P in $Problems)
            {
                if ($P.Type -eq 'ExportCountMismatch')
                {
                    $IsDeterministic = $false
                    foreach ($K in $DeterministicKeys) { if ($P.Description -like "*$K*") { $IsDeterministic = $true; break } }
                    if ($IsDeterministic) { $Kept.Add($P) }
                }
                else { $Kept.Add($P) }
            }
            $Problems = $Kept
        }
        else
        {
            Write-Log "    [WARN] Bracketing baseline failed at stage '$($Baseline2.FailureStage)' — original single-baseline verdicts stand"
        }
    }
    #endregion

    #region Phase C — reconciliation output
    $ReconCsvPath = Join-Path $LogDir "ExportComparison_$RunTimestamp.csv"
    $Reconciliation | Export-Csv -Path $ReconCsvPath -NoTypeInformation

    $MismatchCount = @($Reconciliation | Where-Object { ($_.PSObject.Properties['FinalVerdict'] -and $_.FinalVerdict -in @('Deterministic', 'FilterNotHonored')) -or ((-not $_.PSObject.Properties['FinalVerdict']) -and $_.Verdict -in @('FilteredExceedsBaseline', 'FilteredBelowBaseline', 'FilterNotHonored')) }).Count

    Write-Log "`n  Comparison summary:"
    Write-Log "    Baseline total rows       : $($Baseline.CsvRows)"
    Write-Log "    Sum of filtered job rows  : $SumFiltered$(if ($MaxSettings -gt 0 -and $TestIds.Count -lt $AllIds.Count) { ' (partial — sampled subset)' })"
    Write-Log "    Settings tested           : $($TestIds.Count)"
    Write-Log "    Confirmed mismatches      : $MismatchCount"
    Write-Log "    Reconciliation CSV        : $ReconCsvPath"
    Write-Log "    Baseline zip retained     : $($Baseline.ZipPath)"
    #endregion

    return [PSCustomObject]@{
        Baseline          = $Baseline
        Reconciliation    = $Reconciliation
        Problems          = $Problems
        RetryLog          = $RetryLog
        ReconciliationCsv = $ReconCsvPath
    }
}

function Invoke-RemediationRunStateDiagnostic
{
    <#
    .SYNOPSIS
        v3.9 — Tests the remediation run-state data (hundreds of scripts x
        tens of thousands of devices = the largest dataset BI for Intune
        consumes from this endpoint family) through three witnesses:
        1. Filtered export: DeviceRunStatesByProactiveRemediation
           (PolicyId filter is REQUIRED by the report — no unfiltered mode
           exists, so per-script is the only export access pattern)
        2. Paged Graph: deviceHealthScripts/{id}/deviceRunStates
        3. runSummary counters: Microsoft's own per-state device counts
        Export vs paged is the hard comparison (same data, two APIs);
        counters are approximate context (detection-state fields only).
    #>
    param(
        [int]$SampleCount = 5,
        [int]$PagedPageCap = 400,
        [int]$PagedTop = 100,
        [int]$Concurrency = 5,
        [int]$PollIntervalSec = 10,
        [int]$PollTimeoutSec = 900,
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 60
    )

    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] ===== Remediation Run-State Diagnostic (export vs paged vs runSummary) ====="

    $Problems = [System.Collections.Generic.List[object]]::new()
    $RetryLog = [System.Collections.Generic.List[object]]::new()
    $Results = [System.Collections.Generic.List[object]]::new()

    #region Enumerate scripts and rank by runSummary
    Write-Log "  Enumerating deviceHealthScripts and fetching runSummary counters..."
    $Scripts = [System.Collections.Generic.List[object]]::new()
    $ListUrl = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?$select=id,displayName&$top=100'
    try
    {
        while ($ListUrl)
        {
            $ListResult = Invoke-GraphRequestWithRetry -Uri $ListUrl -Headers $Headers `
                -MaxRetries $MaxRetries -Endpoint 'deviceHealthScripts/list' -TimeoutSec $TimeoutSec
            foreach ($e in $ListResult.RetryLog) { $RetryLog.Add($e) }
            foreach ($S in $ListResult.Response.value) { $Scripts.Add($S) }
            $ListUrl = $ListResult.Response.'@odata.nextLink'
        }
    }
    catch
    {
        Write-Log "  [ERROR] Script enumeration failed: $($_.Exception.Message) — diagnostic aborted"
        return [PSCustomObject]@{ Results = $Results; Problems = $Problems; RetryLog = $RetryLog }
    }
    Write-Log "  Scripts found: $($Scripts.Count)"

    foreach ($S in $Scripts)
    {
        $S | Add-Member -NotePropertyName 'ExpectedApprox' -NotePropertyValue -1 -Force
        try
        {
            $RS = (Invoke-GraphRequestWithRetry `
                    -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($S.id)/runSummary" `
                    -Headers $Headers -MaxRetries 2 -Endpoint 'runSummary' -TimeoutSec $TimeoutSec).Response
            # Detection-state fields partition devices with a reported state;
            # remediation fields overlap detection and are logged as context only.
            # v3.9.1 — 'Not applicable' is ~6% of rows in the console export and
            # must be included, or the counter witness shows a phantom shortfall.
            # Property name probed defensively (beta schema naming varies).
            $NotApplicable = 0
            foreach ($NaProp in @('notApplicableDeviceCount', 'detectionScriptNotApplicableDeviceCount'))
            {
                if ($RS.PSObject.Properties[$NaProp] -and $null -ne $RS.$NaProp)
                {
                    $NotApplicable = [int]$RS.$NaProp
                    break
                }
            }
            $S.ExpectedApprox = [int]$RS.noIssueDetectedDeviceCount + [int]$RS.issueDetectedDeviceCount +
                [int]$RS.detectionScriptErrorDeviceCount + [int]$RS.detectionScriptPendingDeviceCount + $NotApplicable
            $S | Add-Member -NotePropertyName 'RunSummary' -NotePropertyValue $RS -Force
        }
        catch
        {
            Write-Log "  [WARN] runSummary unavailable for $($S.displayName): $($_.Exception.Message)"
        }
    }

    $Ranked = @($Scripts | Where-Object { $_.ExpectedApprox -ge 0 } | Sort-Object ExpectedApprox -Descending)
    $TestSet = if ($SampleCount -gt 0 -and $Ranked.Count -gt $SampleCount) { @($Ranked | Select-Object -First $SampleCount) } else { $Ranked }
    Write-Log "  Testing $($TestSet.Count) scripts (ranked by runSummary detection-state device counts)"
    #endregion

    #region Witness 1 — filtered exports, batched up front (v4.0)
    Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] Submitting $($TestSet.Count) DeviceRunStatesByProactiveRemediation exports (concurrency $Concurrency)..."
    $ExpRequests = @($TestSet | ForEach-Object { [PSCustomObject]@{ Key = $_.id; Filter = "PolicyId eq '$($_.id)'" } })
    $ExpBatch = Invoke-ExportJobBatch -Requests $ExpRequests -ReportName 'DeviceRunStatesByProactiveRemediation' `
        -Concurrency $Concurrency -PollIntervalSec $PollIntervalSec -PollTimeoutSec $PollTimeoutSec `
        -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
    foreach ($e in $ExpBatch.RetryLog) { $RetryLog.Add($e) }
    #endregion

    $Index = 0
    foreach ($Script in $TestSet)
    {
        $Index++
        Write-Log "`n  [$(Get-Date -Format 'HH:mm:ss')] [$Index/$($TestSet.Count)] $($Script.displayName) ($($Script.id))"
        Write-Log "    runSummary detection-state total (approx expected): $($Script.ExpectedApprox)"

        $Export = $ExpBatch.Results[$Script.id]
        $ExportRows = if ($Export -and $Export.FailureStage -eq 'none') { $Export.CsvRows } else { -1 }
        Write-Log "    Export rows : $(if ($ExportRows -ge 0) { $ExportRows } else { "FAILED at stage '$(if ($Export) { $Export.FailureStage } else { 'unknown' })'" })"

        #region Witness 2 — paged deviceRunStates
        $PagedRows = 0
        $PagedComplete = $true
        $RunUrl = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($Script.id)/deviceRunStates?`$top=$PagedTop"
        $RunPage = 0
        $SeenRunLinks = [System.Collections.Generic.HashSet[string]]::new()
        try
        {
            while ($RunUrl)
            {
                $RunPage++
                $RunResult = Invoke-GraphRequestWithRetry -Uri $RunUrl -Headers $Headers `
                    -MaxRetries $MaxRetries -PageNumber $RunPage -Endpoint 'deviceRunStates' -TimeoutSec $TimeoutSec `
                    -Context "$PagedRows rows so far"
                foreach ($e in $RunResult.RetryLog) { $RetryLog.Add($e) }
                $PagedRows += $RunResult.Response.value.Count
                $RunUrl = $RunResult.Response.'@odata.nextLink'
                if ($RunUrl -and (-not $SeenRunLinks.Add($RunUrl)))
                {
                    Write-Log "    [PROBLEM] Pagination loop on deviceRunStates after page $RunPage"
                    $Problems.Add([PSCustomObject]@{
                            Type = 'PaginationLoop'; Endpoint = "deviceRunStates/$($Script.displayName)"; Page = $RunPage
                            RequestedUrl = "deviceHealthScripts/$($Script.id)/deviceRunStates"; Requested = 0; Returned = $PagedRows
                            NextLink = $RunUrl; Timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                            Description = "Script '$($Script.displayName)' — cycling nextLink on deviceRunStates after page $RunPage"
                        })
                    $RunUrl = $null; $PagedComplete = $false
                }
                if ($RunUrl -and $PagedPageCap -gt 0 -and $RunPage -ge $PagedPageCap)
                {
                    Write-Log "    [CAPPED] deviceRunStates at $PagedPageCap pages ($PagedRows rows); paged comparison skipped for this script"
                    $RunUrl = $null; $PagedComplete = $false
                }
            }
        }
        catch
        {
            Write-Log "    [ERROR] deviceRunStates page $RunPage failed: $($_.Exception.Message)"
            $PagedComplete = $false
        }
        Write-Log "    Paged rows  : $PagedRows$(if (-not $PagedComplete) { ' (incomplete)' }) across $RunPage pages"
        #endregion

        #region Verdict — export vs paged (hard), counters (context)
        $Verdict = 'Match'
        if ($ExportRows -lt 0 -or -not $PagedComplete)
        {
            $Verdict = 'Incomparable'
        }
        elseif ($ExportRows -ne $PagedRows)
        {
            $Verdict = 'ApiDisagreement'
            Write-Log "    [PROBLEM] API DISAGREEMENT — export says $ExportRows rows, paged endpoint says $PagedRows, for the SAME script's run states"
            $Problems.Add([PSCustomObject]@{
                    Type = 'RunStateCountMismatch'; Endpoint = "deviceRunStates/$($Script.displayName)"; Page = $RunPage
                    RequestedUrl = "PolicyId eq '$($Script.id)'"; Requested = $PagedRows; Returned = $ExportRows
                    NextLink = ''; Timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                    Description = "Script '$($Script.displayName)' ($($Script.id)) — filtered export returned $ExportRows rows, paged deviceRunStates returned $PagedRows, runSummary approx $($Script.ExpectedApprox)"
                })
        }
        else
        {
            Write-Log "    Match — both APIs agree at $ExportRows rows (runSummary approx: $($Script.ExpectedApprox))"
        }
        #endregion

        $Results.Add([PSCustomObject]@{
                ScriptId       = $Script.id
                ScriptName     = $Script.displayName
                ExpectedApprox = $Script.ExpectedApprox
                ExportRows     = $ExportRows
                PagedRows      = $PagedRows
                PagedPages     = $RunPage
                PagedComplete  = $PagedComplete
                Verdict        = $Verdict
            })
    }

    Write-Log "`n  Remediation run-state summary: $($Results.Count) scripts tested, $(@($Results | Where-Object Verdict -eq 'ApiDisagreement').Count) API disagreements"
    return [PSCustomObject]@{ Results = $Results; Problems = $Problems; RetryLog = $RetryLog }
}

#endregion

#region --- Main Execution ---
$AllEndpointResults = [System.Collections.Generic.List[object]]::new()
$AllRetryEvents = [System.Collections.Generic.List[object]]::new()
$AllScaleDiagnostics = [System.Collections.Generic.List[object]]::new()
$AllProblems = [System.Collections.Generic.List[object]]::new()
$ExportResult = $null
$ComparisonResult = $null

foreach ($Endpoint in $Endpoints)
{

    # Bulk collection with retry
    $EndpointResult = Invoke-EndpointCollection -Endpoint $Endpoint -Headers $Headers `
        -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
    $AllEndpointResults.Add($EndpointResult)
    foreach ($entry in $EndpointResult.RetryLog)
    {
        $AllRetryEvents.Add($entry)
    }
    foreach ($p in $EndpointResult.Problems)
    {
        $AllProblems.Add($p)
    }

    # Per-item assignment scale diagnostic
    if ($doScaleTest)
    {
        $ScaleResults = Get-AssignmentScaleDiagnostic -Endpoint $Endpoint -Headers $Headers `
            -TimeoutSec $TimeoutSec
        if ($ScaleResults)
        {
            foreach ($r in $ScaleResults)
            {
                $AllScaleDiagnostics.Add($r)
            }
        }
    }
}

# v3.4 — Variant passes: same endpoints, different $expand, to separate payload
# composition from page size in the 503/504 failure characterization.
if ($doVariantTest)
{
    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] ===== Variant passes (payload composition isolation) ====="
    foreach ($Variant in $VariantEndpoints)
    {
        $VariantResult = Invoke-EndpointCollection -Endpoint $Variant -Headers $Headers `
            -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
        $AllEndpointResults.Add($VariantResult)
        foreach ($entry in $VariantResult.RetryLog)
        {
            $AllRetryEvents.Add($entry)
        }
        foreach ($p in $VariantResult.Problems)
        {
            $AllProblems.Add($p)
        }
    }
}

# v3.0 — Intune reports Export API diagnostic (BI for Intune's compliance data path)
if ($doExportTest)
{
    $ExportResult = Invoke-ExportApiDiagnostic -Reports $ExportReports `
        -PollIntervalSec $ExportPollIntervalSec -PollTimeoutSec $ExportPollTimeoutSec `
        -Format 'csv' -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
    if ($ExportResult)
    {
        foreach ($entry in $ExportResult.RetryLog)
        {
            $AllRetryEvents.Add($entry)
        }
        foreach ($p in $ExportResult.Problems)
        {
            $AllProblems.Add($p)
        }
    }
}

# v3.1 — Export API comparison: unfiltered vs per-SettingId filtered (production pattern)
if ($doExportComparison)
{
    $ComparisonResult = Invoke-ExportComparisonDiagnostic -ReportName $ComparisonReport `
        -KeyColumn $ComparisonKeyColumn -FilterTemplate $ComparisonFilterTemplate -MaxSettings $ComparisonMaxSettings `
        -ListReport $ComparisonListReport -ListColumn $ComparisonListColumn `
        -RetestMismatches:$ComparisonRetestMismatches -BracketBaseline:$ComparisonBracketBaseline -KeepAllZips:$ComparisonKeepAllZips `
        -Concurrency $ExportJobConcurrency `
        -PollIntervalSec $ExportPollIntervalSec -PollTimeoutSec $ExportPollTimeoutSec `
        -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
    if ($ComparisonResult)
    {
        foreach ($entry in $ComparisonResult.RetryLog)
        {
            $AllRetryEvents.Add($entry)
        }
        foreach ($p in $ComparisonResult.Problems)
        {
            $AllProblems.Add($p)
        }
    }
}

# v3.9 — Remediation run states: three-witness comparison at the product's largest data scale
$RemediationResult = $null
if ($doRemediationTest)
{
    $RemediationResult = Invoke-RemediationRunStateDiagnostic -SampleCount $RemediationSampleCount `
        -PagedPageCap $RemediationPagedPageCap -PagedTop $RemediationPagedTop -Concurrency $ExportJobConcurrency -PollIntervalSec $ExportPollIntervalSec `
        -PollTimeoutSec $ExportPollTimeoutSec -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
    if ($RemediationResult)
    {
        foreach ($entry in $RemediationResult.RetryLog) { $AllRetryEvents.Add($entry) }
        foreach ($p in $RemediationResult.Problems) { $AllProblems.Add($p) }
    }
}
#endregion

#region --- Final Summary ---
# v4.5 — verdict-first executive summary: conclusions in the first screen,
# detail tables below as drill-down. [FAIL]/[WARN] lines render red/yellow in
# CMTrace via the severity keyword mapping.
$RunEnd = Get-Date
$RunDuration = $RunEnd - [datetime]::ParseExact($RunTimestamp, 'yyyyMMdd_HHmmss', $null)

$Verdicts = [System.Collections.Generic.List[string]]::new()

# Collection passes: one verdict line each
foreach ($R in $AllEndpointResults)
{
    $Avg = if ($R.Pages -gt 0) { [math]::Round(($R.TotalMs / $R.Pages) / 1000, 1) } else { 0 }
    if ($R.FatalError)
    {
        $Verdicts.Add("[FAIL] $($R.EndpointName): FATAL — collection did not complete ($($R.ItemCount) items before failure)")
    }
    elseif ($R.RetryLog.Count -gt 0)
    {
        $Verdicts.Add("[FAIL] $($R.EndpointName): completed with $($R.RetryLog.Count) retry events ($($R.ItemCount) items, $($R.Pages) pages, ${Avg}s/page)")
    }
    else
    {
        $Verdicts.Add("[PASS] $($R.EndpointName): clean ($($R.ItemCount) items, $($R.Pages) pages, ${Avg}s/page)")
    }
}

# Export health
if ($ExportResult -and $ExportResult.Results.Count -gt 0)
{
    $ExpBad = @($ExportResult.Results | Where-Object { $_.FinalStatus -ne 'completed' })
    $ExpEmpty = @($ExportResult.Results | Where-Object { $_.FinalStatus -eq 'completed' -and $_.CsvRows -eq 0 })
    if ($ExpBad.Count -gt 0)
    {
        $Verdicts.Add("[FAIL] Export API health: $($ExpBad.Count) of $($ExportResult.Results.Count) reports did not complete ($(@($ExpBad | ForEach-Object ReportName) -join ', '))")
    }
    elseif ($ExpEmpty.Count -gt 0)
    {
        $Verdicts.Add("[WARN] Export API health: all completed; $($ExpEmpty.Count) returned 0 rows ($(@($ExpEmpty | ForEach-Object ReportName) -join ', '))")
    }
    else
    {
        $Verdicts.Add("[PASS] Export API health: $($ExportResult.Results.Count) reports completed with data")
    }
}

# Comparison (bracket-aware)
if ($doExportComparison -and $ComparisonResult -and $ComparisonResult.Reconciliation.Count -eq 0)
{
    # v4.5.1 — an aborted comparison must appear in the verdicts, not vanish
    # (20260715: baseline job failed terminally; block silently omitted it)
    $Verdicts.Add("[FAIL] Export comparison ($ComparisonReport): ABORTED — baseline export failed; no reconciliation performed")
}
if ($ComparisonResult -and $ComparisonResult.Reconciliation.Count -gt 0)
{
    $CmpBad = @($ComparisonResult.Reconciliation | Where-Object {
            $V = if ($_.PSObject.Properties['FinalVerdict']) { $_.FinalVerdict } else { $_.Verdict }
            $V -in @('Deterministic', 'FilteredExceedsBaseline', 'FilteredBelowBaseline', 'FilterNotHonored')
        })
    $CmpDrift = @($ComparisonResult.Reconciliation | Where-Object { $_.PSObject.Properties['FinalVerdict'] -and $_.FinalVerdict -eq 'DriftLikely' })
    if ($CmpBad.Count -gt 0)
    {
        $Verdicts.Add("[FAIL] Export comparison ($ComparisonReport): $($CmpBad.Count) DETERMINISTIC mismatches of $($ComparisonResult.Reconciliation.Count) ids — the two access patterns disagree")
    }
    else
    {
        $Verdicts.Add("[PASS] Export comparison ($ComparisonReport): unfiltered and per-id filtered agree across $($ComparisonResult.Reconciliation.Count) ids$(if ($CmpDrift.Count -gt 0) { " ($($CmpDrift.Count) drift-resolved)" })")
    }
}

# Remediation run states
if ($RemediationResult -and $RemediationResult.Results.Count -gt 0)
{
    $RemBad = @($RemediationResult.Results | Where-Object Verdict -eq 'ApiDisagreement')
    $RemInc = @($RemediationResult.Results | Where-Object Verdict -eq 'Incomparable')
    if ($RemBad.Count -gt 0)
    {
        $Worst = $RemBad | Sort-Object { [math]::Abs($_.ExportRows - $_.PagedRows) } -Descending | Select-Object -First 1
        $Verdicts.Add("[FAIL] Run states (export vs paged): $($RemBad.Count) of $($RemediationResult.Results.Count) scripts disagree — worst: '$($Worst.ScriptName)' export=$($Worst.ExportRows) paged=$($Worst.PagedRows) (paged missing $($Worst.ExportRows - $Worst.PagedRows) rows)")
    }
    elseif ($RemediationResult.Results.Count -eq $RemInc.Count)
    {
        $Verdicts.Add("[WARN] Run states: all $($RemInc.Count) scripts incomparable (caps/failures) — no verdict")
    }
    else
    {
        $Verdicts.Add("[PASS] Run states (export vs paged): APIs agree for all $($RemediationResult.Results.Count) scripts tested$(if ($RemInc.Count -gt 0) { " ($($RemInc.Count) incomparable)" })")
    }
}

$FailCount = @($Verdicts | Where-Object { $_ -like '`[FAIL`]*' }).Count
$WarnCount = @($Verdicts | Where-Object { $_ -like '`[WARN`]*' }).Count

# Problems by type
$ProblemsByType = $AllProblems | Group-Object Type | Sort-Object Count -Descending

Write-Log "`n`n=========================================="
Write-Log "  FINAL DIAGNOSTIC SUMMARY"
Write-Log "=========================================="
Write-Log "  Run       : $RunTimestamp -> $($RunEnd.ToString('HH:mm:ss'))  (duration $([math]::Floor($RunDuration.TotalHours))h $($RunDuration.Minutes)m)"
Write-Log "  Tenant    : $TenantId"
Write-Log "  Overall   : $(if ($FailCount -gt 0) { "$FailCount FAILED" } else { 'ALL PASSED' })$(if ($WarnCount -gt 0) { ", $WarnCount warnings" }) of $($Verdicts.Count) areas | $($AllProblems.Count) problems | $($AllRetryEvents.Count) retry events | $($script:TokenRefreshCount) token refreshes"
Write-Log ""
Write-Log "  VERDICTS"
Write-Log "  --------"
foreach ($V in $Verdicts) { Write-Log "  $V" }
if ($ProblemsByType)
{
    Write-Log ""
    Write-Log "  PROBLEMS BY TYPE"
    Write-Log "  ----------------"
    foreach ($P in $ProblemsByType) { Write-Log ("  {0,5}  {1}" -f $P.Count, $P.Name) }
}
Write-Log ""
Write-Log "------------------------------------------"
Write-Log "  DETAIL"
Write-Log "------------------------------------------"

foreach ($R in $AllEndpointResults)
{
    Write-Log "`n  $($R.EndpointName)"
    Write-Log "    Items retrieved    : $($R.ItemCount)"
    Write-Log "    Pages fetched      : $($R.Pages)"
    Write-Log "    Effective page size: $($R.EffectivePageSize)"
    Write-Log "    Total time         : $($R.TotalMs)ms ($([math]::Round($R.TotalMs / 1000, 1))s)"
    Write-Log "    Avg time/page      : $([math]::Round($R.TotalMs / [math]::Max($R.Pages, 1), 1))ms"
    Write-Log "    Retry events       : $(($R.RetryLog).Count)"
    Write-Log "    Fatal error        : $(if ($R.FatalError) { 'YES' } else { 'No' })"

    if ($R.Results.Count -gt 0 -and $R.Results[0].'@odata.type')
    {
        $TypeBreakdown = $R.Results | Group-Object '@odata.type' | Sort-Object Count -Descending
        Write-Log "    Type breakdown:"
        foreach ($t in $TypeBreakdown)
        {
            Write-Log "      $($t.Count.ToString().PadLeft(6))  $($t.Name)"
        }
    }
}

# v3.4 — Expand-variant comparison across all collection passes
if ($AllEndpointResults.Count -gt 0)
{
    Write-Log "`n  Collection pass comparison (production vs variants)"
    Write-Log ("    {0,-38} {1,6} {2,6} {3,8} {4,10} {5,8}" -f 'Pass', 'Items', 'Pages', 'Retries', 'TotalSec', 'AvgSec')
    foreach ($ER in $AllEndpointResults)
    {
        $RetryCount = $ER.RetryLog.Count
        $TotSec = [math]::Round($ER.TotalMs / 1000)
        $AvgSec = if ($ER.Pages -gt 0) { [math]::Round(($ER.TotalMs / $ER.Pages) / 1000, 1) } else { 0 }
        Write-Log ("    {0,-38} {1,6} {2,6} {3,8} {4,10} {5,8}" -f $ER.EndpointName, $ER.ItemCount, $ER.Pages, $RetryCount, $TotSec, $AvgSec)
    }
    Write-Log "    (Retries on a production pass but not its variant = the removed expand content is implicated in the failures)"
}

# v3.0 — Export API results
if ($ExportResult -and $ExportResult.Results.Count -gt 0)
{
    Write-Log "`n  Export API (deviceManagement/reports/exportJobs)"
    foreach ($R in $ExportResult.Results)
    {
        Write-Log "    $($R.ReportName)"
        Write-Log "      Final status : $($R.FinalStatus)"
        Write-Log "      Create time  : $($R.CreateMs)ms"
        Write-Log "      Queue time   : $($R.QueueSec)s"
        Write-Log "      Process time : $($R.ProcessSec)s"
        Write-Log "      Polls        : $($R.PollCount)"
        Write-Log "      Download     : $([math]::Round($R.ZipBytes / 1KB, 1)) KB in $($R.DownloadMs)ms"
        Write-Log "      CSV rows     : $(if ($R.CsvRows -ge 0) { $R.CsvRows } else { 'n/a' })"
    }
}

# v3.1 — Export comparison results
if ($ComparisonResult -and $ComparisonResult.Reconciliation.Count -gt 0)
{
    # v4.4.1 — respect the bracketing re-verdict: mismatches reclassified as
    # DriftLikely by the second baseline must not trigger the DISAGREE verdict
    # (20260714 run: 35 drift-resolved mismatches wrongly reported as
    # disagreement here while the bracket correctly said 0 deterministic).
    $CmpMismatches = @($ComparisonResult.Reconciliation | Where-Object {
            $V = if ($_.PSObject.Properties['FinalVerdict']) { $_.FinalVerdict } else { $_.Verdict }
            $V -in @('Deterministic', 'FilteredExceedsBaseline', 'FilteredBelowBaseline', 'FilterNotHonored')
        })
    Write-Log "`n  Export Comparison (unfiltered vs per-$ComparisonKeyColumn filtered)"
    Write-Log "    Report               : $ComparisonReport"
    Write-Log "    Baseline rows        : $($ComparisonResult.Baseline.CsvRows)"
    Write-Log "    Settings tested      : $($ComparisonResult.Reconciliation.Count)"
    Write-Log "    Confirmed mismatches : $($CmpMismatches.Count)"
    if ($CmpMismatches.Count -gt 0)
    {
        Write-Log "    VERDICT: the two access patterns DISAGREE — see $($ComparisonResult.ReconciliationCsv)"
        foreach ($M in ($CmpMismatches | Select-Object -First 10))
        {
            Write-Log "      $($M.KeyValue)$(if ($M.KeyName) { " ($($M.KeyName))" }): baseline=$($M.BaselineRows) filtered=$($M.FilteredRows)$(if ($null -ne $M.RetestRows) { " retest=$($M.RetestRows)" }) [$($M.Verdict)]"
        }
        if ($CmpMismatches.Count -gt 10)
        {
            Write-Log "      ... and $($CmpMismatches.Count - 10) more in the reconciliation CSV"
        }
    }
    else
    {
        Write-Log "    VERDICT: all filtered jobs matched the unfiltered baseline"
    }
}

# v3.9 — Remediation run-state results
if ($RemediationResult -and $RemediationResult.Results.Count -gt 0)
{
    Write-Log "`n  Remediation run states (export vs paged vs runSummary)"
    Write-Log ("    {0,-40} {1,10} {2,10} {3,10} {4,-16}" -f 'Script', 'RunSummary', 'Export', 'Paged', 'Verdict')
    foreach ($RR in $RemediationResult.Results)
    {
        Write-Log ("    {0,-40} {1,10} {2,10} {3,10} {4,-16}" -f $RR.ScriptName.Substring(0, [math]::Min(40, $RR.ScriptName.Length)), $RR.ExpectedApprox, $RR.ExportRows, $RR.PagedRows, $RR.Verdict)
    }
}

# Retry event detail
if ($AllRetryEvents.Count -gt 0)
{
    Write-Log "`n------------------------------------------"
    Write-Log "  RETRY EVENTS"
    Write-Log "------------------------------------------"
    $AllRetryEvents | Format-Table Endpoint, Page, Attempt, Status, ElapsedMs, WaitedSec, Error -AutoSize |
        Out-String | ForEach-Object { Write-Log $_ }
}

# v2.0 — Problems (succeeded HTTP-wise but result is suspicious)
Write-Log "`n------------------------------------------"
Write-Log "  PROBLEMS DETECTED"
Write-Log "  (HTTP 200 OK but Graph returned a partial page while claiming more data exists)"
Write-Log "------------------------------------------"
if ($AllProblems.Count -gt 0)
{
    Write-Log "  Total Problems flagged: $($AllProblems.Count)"
    $AllProblems | Format-Table Type, Endpoint, Page, Requested, Returned, Description -AutoSize |
        Out-String | ForEach-Object { Write-Log $_ }
}
else
{
    Write-Log "  No Problems flagged. Either the bug did not surface during this run,"
    Write-Log "  or all paged responses returned the requested page size."
}

# v4.4 — tabular evidence goes to real CSV artifact files (attachable to the
# escalation package), not embedded in the log.
Write-Log "`n------------------------------------------"
Write-Log "  EVIDENCE ARTIFACTS"
Write-Log "------------------------------------------"
if ($AllRetryEvents.Count -gt 0)
{
    $RetryCsvPath = Join-Path $LogDir "RetryEvents_$RunTimestamp.csv"
    $AllRetryEvents | Export-Csv -Path $RetryCsvPath -NoTypeInformation
    Write-Log "  Retry events : $RetryCsvPath ($($AllRetryEvents.Count) events)"
}
else
{
    Write-Log "  Retry events : none recorded"
}
if ($AllProblems.Count -gt 0)
{
    $ProblemsCsvPath = Join-Path $LogDir "Problems_$RunTimestamp.csv"
    $AllProblems | Export-Csv -Path $ProblemsCsvPath -NoTypeInformation
    Write-Log "  Problems     : $ProblemsCsvPath ($($AllProblems.Count) flagged)"
}
else
{
    Write-Log "  Problems     : none flagged"
}
if ($ExportResult -and $ExportResult.Results.Count -gt 0)
{
    $ExportCsvPath = Join-Path $LogDir "ExportDiagnostic_$RunTimestamp.csv"
    $ExportResult.Results | Select-Object ReportName, JobId, FinalStatus, CreateMs, QueueSec, ProcessSec, PollCount, TotalSec, DownloadMs, ZipBytes, CsvRows |
        Export-Csv -Path $ExportCsvPath -NoTypeInformation
    Write-Log "  Export tests : $ExportCsvPath"
}
if ($doScaleTest -and $AllScaleDiagnostics -and $AllScaleDiagnostics.Count -gt 0)
{
    $ScaleCsvPath = Join-Path $LogDir "ScaleDiagnostic_$RunTimestamp.csv"
    $AllScaleDiagnostics | Export-Csv -Path $ScaleCsvPath -NoTypeInformation
    Write-Log "  Scale test   : $ScaleCsvPath"
}
if ($ComparisonResult -and $ComparisonResult.ReconciliationCsv)
{
    Write-Log "  Comparison   : $($ComparisonResult.ReconciliationCsv)"
}
Write-Log "`n  Log file: $($script:LogPath)"
Write-Log "  Done."
#endregion
