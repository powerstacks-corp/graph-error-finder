<#
.SYNOPSIS
    Graph API diagnostic script for mobileApps endpoint.
.DESCRIPTION
    Retrieves all mobile apps from Intune via Graph API with enhanced
    diagnostic output for troubleshooting pagination, throttling, and
    response anomalies.
.NOTES
    Author  : John Marcum (PJM)
    Version : 2.0
    Requires: TenantId, ClientId, ClientSecret variables to be set before execution

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


#region --- Configuration ---
$TenantId = ""
$ClientId = ""
$ClientSecret = "" # <------Removed to protect privacy
$PageSize     = 100
$MaxRetries   = 7
$LogDir       = "C:\Temp"
$doScaleTest = $False
$doComplianceTest = $True   # v2.0 — exercise the deviceComplianceSettingStates endpoint that Microsoft acknowledges returns small result sets without erroring

$Endpoints = @(
    [PSCustomObject]@{
        Name         = 'mobileApps'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps'
        Expand       = 'assignments,categories'
        PerItemUrl   = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{id}/assignments'
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'deviceManagementScripts'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
        Expand       = 'assignments'
        PerItemUrl   = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/{id}/assignments'
        RunDiscovery = $false
    },
    [PSCustomObject]@{
        Name         = 'deviceHealthScripts'
        BaseUrl      = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'
        Expand       = 'assignments'
        PerItemUrl   = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/{id}/assignments'
        RunDiscovery = $true   # Auto-discover working page size — demonstrates threshold to MSFT
    }
)
#endregion

#region --- Logging ---
# Initialize log file — all output goes here AND to console simultaneously
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$RunTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogPath = "$LogDir\GraphDiag_$RunTimestamp.log"

function Write-Log {
    param([string]$Message)
    [Console]::WriteLine($Message)
    Add-Content -Path $script:LogPath -Value $Message
}

Write-Log "=========================================="
Write-Log "  Graph API Diagnostic Script"
Write-Log "  Run timestamp : $RunTimestamp"
Write-Log "  Log file      : $($script:LogPath)"
Write-Log "=========================================="
#endregion

#region --- Token Acquisition ---
Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] Acquiring token..."

$TokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $ClientId
    Client_Secret = $ClientSecret
}

try {
    $TokenResponse = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $TokenBody -ErrorAction Stop

    $AccessToken  = $TokenResponse.access_token
    $TokenExpires = (Get-Date).AddSeconds($TokenResponse.expires_in)

    # Decode JWT for diagnostic visibility
    $TokenParts  = $AccessToken.Split('.')
    $Padded      = $TokenParts[1].PadRight($TokenParts[1].Length + (4 - $TokenParts[1].Length % 4) % 4, '=')
    $TokenClaims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Padded)) | ConvertFrom-Json

    Write-Log "  Token acquired successfully"
    Write-Log "  Expires      : $($TokenExpires.ToString('HH:mm:ss')) (in $($TokenResponse.expires_in)s)"
    Write-Log "  Token type   : $($TokenResponse.token_type)"
    Write-Log "  App ID (oid) : $($TokenClaims.oid)"
    Write-Log "  Tenant       : $($TokenClaims.tid)"
    Write-Log "  Roles        : $($TokenClaims.roles -join ', ')"
}
catch {
    Write-Log "  [FATAL] Token acquisition failed: $_"
    exit 1
}

$Headers = @{ Authorization = "Bearer $AccessToken" }
#endregion

#region --- Functions ---
function Invoke-GraphRequestWithRetry {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [int]$MaxRetries  = 7,
        [int]$PageNumber  = 1,
        [string]$Endpoint = '',
        [int]$TimeoutSec  = 60
    )

    $Attempt        = 0
    $RetryLog       = [System.Collections.Generic.List[object]]::new()
    $TotalElapsedMs = 0

    do {
        $Attempt++
        $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $Response = Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers `
                -TimeoutSec $TimeoutSec -ErrorAction Stop
            $StopWatch.Stop()
            $TotalElapsedMs += $StopWatch.ElapsedMilliseconds

            Write-Log "    Attempt $Attempt succeeded in $($StopWatch.ElapsedMilliseconds)ms ($([math]::Round($StopWatch.ElapsedMilliseconds / 1000, 1))s)"

            return [PSCustomObject]@{
                Response       = $Response
                RetryLog       = $RetryLog
                ElapsedMs      = $StopWatch.ElapsedMilliseconds
                TotalElapsedMs = $TotalElapsedMs
                Attempts       = $Attempt
            }
        }
        catch {
            $StopWatch.Stop()
            $TotalElapsedMs += $StopWatch.ElapsedMilliseconds

            $StatusCode   = $null
            $RetryAfter   = $null
            $ExceptionMsg = $_.Exception.Message

            if ($_.Exception.Response) {
                $StatusCode = $_.Exception.Response.StatusCode.value__
                $RetryAfter = $_.Exception.Response.Headers['Retry-After']
            }

            if ($_.Exception.InnerException) {
                $ExceptionMsg += " | Inner: $($_.Exception.InnerException.Message)"
            }

            Write-Log "    Attempt $Attempt FAILED — HTTP $StatusCode | $($StopWatch.ElapsedMilliseconds)ms ($([math]::Round($StopWatch.ElapsedMilliseconds / 1000, 1))s)"
            Write-Log "    Error: $ExceptionMsg"

            # Retryable: 429, 500, 503, 504, or null status (gateway timeout before HTTP response)
            $IsRetryable = ($StatusCode -in @(429, 500, 503, 504)) -or ($null -eq $StatusCode)

            if ($IsRetryable -and $Attempt -lt $MaxRetries) {

                if ($RetryAfter) {
                    $WaitSeconds = [int]$RetryAfter
                    Write-Log "    Retry-After header: ${WaitSeconds}s"
                } else {
                    # Aggressive backoff: 15s, 30s, 60s, 120s, 240s, 300s (capped)
                    $WaitSeconds = [math]::Min([math]::Pow(2, $Attempt) * 7.5, 300)
                    Write-Log "    No Retry-After — exponential backoff: ${WaitSeconds}s"
                }

                $RetryLog.Add([PSCustomObject]@{
                    Endpoint  = $Endpoint
                    Page      = $PageNumber
                    Attempt   = $Attempt
                    Status    = if ($StatusCode) { $StatusCode } else { 'No HTTP Response' }
                    ElapsedMs = $StopWatch.ElapsedMilliseconds
                    WaitedSec = $WaitSeconds
                    Error     = $ExceptionMsg
                })

                Write-Log "    Waiting ${WaitSeconds}s before retry..."
                Start-Sleep -Seconds $WaitSeconds
                $TotalElapsedMs += ($WaitSeconds * 1000)

            } else {
                Write-Log "    Giving up on $Endpoint page $PageNumber after $Attempt attempts"

                $RetryLog.Add([PSCustomObject]@{
                    Endpoint  = $Endpoint
                    Page      = $PageNumber
                    Attempt   = $Attempt
                    Status    = if ($StatusCode) { $StatusCode } else { 'No HTTP Response' }
                    ElapsedMs = $StopWatch.ElapsedMilliseconds
                    WaitedSec = 0
                    Error     = "FATAL: $ExceptionMsg"
                })

                throw
            }
        }

    } while ($Attempt -le $MaxRetries)
}

function Invoke-EndpointCollection {
    param(
        [PSCustomObject]$Endpoint,
        [hashtable]$Headers,
        [int]$MaxRetries = 7,
        [int]$TimeoutSec = 60
    )

    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] ===== $($Endpoint.Name) ====="

    $Results    = [System.Collections.Generic.List[object]]::new()
    $RetryLog   = [System.Collections.Generic.List[object]]::new()
    $Problems   = [System.Collections.Generic.List[object]]::new()
    $Page       = 0
    $TotalMs    = 0
    $FatalError = $false

    #region Page Size Discovery
    if ($Endpoint.RunDiscovery) {
        Write-Log "`n  Running page size discovery for $($Endpoint.Name)..."
        Write-Log "  (This demonstrates the failure threshold to MSFT)"

        $EffectivePageSize = $PageSize

        while ($EffectivePageSize -ge 1) {
            $TestUrl   = "$($Endpoint.BaseUrl)?`$expand=$($Endpoint.Expand)&`$top=$EffectivePageSize"
            $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            try {
                $TestResponse = Invoke-RestMethod -Method Get -Uri $TestUrl -Headers $Headers `
                    -TimeoutSec $TimeoutSec -ErrorAction Stop
                $StopWatch.Stop()
                Write-Log "  Page size $($EffectivePageSize.ToString().PadLeft(4)) : SUCCESS in $($StopWatch.ElapsedMilliseconds)ms ($([math]::Round($StopWatch.ElapsedMilliseconds / 1000, 1))s) — using this for collection"
                break
            }
            catch {
                $StopWatch.Stop()
                $StatusCode        = $_.Exception.Response.StatusCode.value__
                $PreviousPageSize  = $EffectivePageSize
                $EffectivePageSize = [math]::Floor($EffectivePageSize / 2)
                Write-Log "  Page size $($PreviousPageSize.ToString().PadLeft(4)) : FAILED HTTP $StatusCode in $($StopWatch.ElapsedMilliseconds)ms ($([math]::Round($StopWatch.ElapsedMilliseconds / 1000, 1))s) — trying $EffectivePageSize"

                if ($EffectivePageSize -lt 1) {
                    Write-Log "  [FATAL] No working page size found — endpoint unusable with expand"
                    $FatalError = $true
                    return [PSCustomObject]@{
                        EndpointName       = $Endpoint.Name
                        Results            = $Results
                        RetryLog           = $RetryLog
                        Pages              = 0
                        TotalMs            = 0
                        FatalError         = $true
                        ItemCount          = 0
                        EffectivePageSize  = 0
                    }
                }
            }
        }
    } else {
        $EffectivePageSize = $PageSize
        Write-Log "  Using page size: $EffectivePageSize"
    }
    #endregion

    $Url = "$($Endpoint.BaseUrl)?`$expand=$($Endpoint.Expand)&`$top=$EffectivePageSize"
    Write-Log "  URL: $Url"

    do {
        $Page++
        $RequestedUrl = $Url   # capture before reassignment for Problem tracking
        Write-Log "`n  [Page $Page] GET $Url"

        try {
            $Result   = Invoke-GraphRequestWithRetry -Uri $Url -Headers $Headers `
                            -MaxRetries $MaxRetries -PageNumber $Page -Endpoint $Endpoint.Name `
                            -TimeoutSec $TimeoutSec
            $Response = $Result.Response

            foreach ($entry in $Result.RetryLog) { $RetryLog.Add($entry) }

            $PageCount = $Response.value.Count
            $Results.AddRange($Response.value)
            $TotalMs  += $Result.TotalElapsedMs

            Write-Log "    Records this page : $PageCount"
            Write-Log "    Running total     : $($Results.Count)"
            Write-Log "    Last attempt time : $($Result.ElapsedMs)ms ($([math]::Round($Result.ElapsedMs / 1000, 1))s)"
            Write-Log "    Total page time   : $($Result.TotalElapsedMs)ms ($([math]::Round($Result.TotalElapsedMs / 1000, 1))s) — inc. retries and waits"
            Write-Log "    Attempts required : $($Result.Attempts)"

            if ($Response.'@odata.count') {
                Write-Log "    @odata.count      : $($Response.'@odata.count')"
            }

            $Url = $Response.'@odata.nextLink'
            if ($Url) { Write-Log "    nextLink present  : YES" }

            # Small-result-set detector (Problem, not Error):
            # If we got fewer rows than $top AND nextLink claims more exists,
            # Graph returned a partial page silently. Microsoft has acknowledged
            # this behavior and says "not a bug" (per BI for Intune team, 2026-05-20).
            if (($PageCount -lt $EffectivePageSize) -and ($Url)) {
                Write-Log "    [PROBLEM] Small result set — got $PageCount, requested $EffectivePageSize, but nextLink present"
                $Problems.Add([PSCustomObject]@{
                    Type        = 'SmallResultSet'
                    Endpoint    = $Endpoint.Name
                    Page        = $Page
                    RequestedUrl= $RequestedUrl
                    Requested   = $EffectivePageSize
                    Returned    = $PageCount
                    NextLink    = $Url
                    Timestamp   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                    Description = "Got $PageCount of $EffectivePageSize requested, but nextLink present — Graph claims more data exists"
                })
            }
        }
        catch {
            Write-Log "    [FATAL] $($Endpoint.Name) page $Page failed all retries"
            Write-Log "    Last error: $($_.Exception.Message)"
            $FatalError = $true
            break
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

function Get-AssignmentScaleDiagnostic {
    param(
        [PSCustomObject]$Endpoint,
        [hashtable]$Headers,
        [int]$TimeoutSec   = 60,
        [int]$ItemPageSize = 100   # Page size for the no-expand ID collection pass
    )

    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] Assignment scale diagnostic — $($Endpoint.Name)"
    Write-Log "  Collecting all items without expand first..."

    # Collect all item IDs without expand — should be fast and reliable
    $AllItems = [System.Collections.Generic.List[object]]::new()
    $BaseUrl  = "$($Endpoint.BaseUrl)?`$select=id,displayName&`$top=$ItemPageSize"

    try {
        do {
            $Response = Invoke-RestMethod -Method Get -Uri $BaseUrl -Headers $Headers `
                -TimeoutSec $TimeoutSec -ErrorAction Stop
            $AllItems.AddRange($Response.value)
            $BaseUrl = $Response.'@odata.nextLink'
            Write-Log "  Collected $($AllItems.Count) items so far..."
        } while ($BaseUrl)
    }
    catch {
        Write-Log "  [ERROR] Failed to collect item list: $($_.Exception.Message)"
        return $null
    }

    Write-Log "  Total items found : $($AllItems.Count)"
    Write-Log "  Testing assignments per item individually...`n"

    $Results = [System.Collections.Generic.List[object]]::new()
    $Tested  = 0
    $Failed  = 0

    foreach ($Item in $AllItems) {
        $Tested++
        $AssignUrl      = $Endpoint.PerItemUrl -replace '\{id\}', $Item.id
        $StopWatch      = [System.Diagnostics.Stopwatch]::StartNew()
        $Status         = 'OK'
        $AssignCount    = 0
        $HasAllDevices  = $false
        $HasAllUsers    = $false
        $AssignTargets  = ''
        $AssignResponse = $null

        try {
            $AssignResponse = Invoke-RestMethod -Method Get -Uri $AssignUrl -Headers $Headers `
                -TimeoutSec $TimeoutSec -ErrorAction Stop
            $StopWatch.Stop()
            $AssignCount   = $AssignResponse.value.Count
            $HasAllDevices = ($AssignResponse.value.target.'@odata.type' -contains '#microsoft.graph.allDevicesAssignmentTarget')
            $HasAllUsers   = ($AssignResponse.value.target.'@odata.type' -contains '#microsoft.graph.allLicensedUsersAssignmentTarget')

            # Build readable assignment target summary
            $AssignTargets = ($AssignResponse.value | ForEach-Object {
                "$($_.intent):$($_.target.'@odata.type' -replace '#microsoft.graph.','')"
            }) -join '; '
        }
        catch {
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

        $Flag = if ($HasAllDevices) { ' <-- ALL DEVICES' } elseif ($HasAllUsers) { ' <-- ALL USERS' } else { '' }
        Write-Log "  [$Status] $($Item.displayName)$Flag | Assignments: $AssignCount | $($StopWatch.ElapsedMilliseconds)ms"

        if ($Tested % 25 -eq 0) {
            Write-Log "  --- Progress: $Tested / $($AllItems.Count) tested, $Failed failed ---"
        }
    }

    Write-Log "`n  Scale diagnostic summary — $($Endpoint.Name):"
    Write-Log "    Items tested        : $($Results.Count)"
    Write-Log "    Failed requests     : $Failed"
    Write-Log "    All Devices scope   : $(($Results | Where-Object HasAllDevices).Count) items"
    Write-Log "    All Users scope     : $(($Results | Where-Object HasAllUsers).Count) items"
    Write-Log "    Unassigned items    : $(($Results | Where-Object { $_.AssignCount -eq 0 }).Count) items"

    if ($Results.Count -gt 0) {
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

function Invoke-CompliancePolicyDiagnostic {
    <#
    .SYNOPSIS
        Exercises the deviceComplianceSettingStates endpoint family that Microsoft
        has acknowledged returns small result sets without erroring.
    .DESCRIPTION
        Two-phase test:
        1. List all deviceCompliancePolicySettingStateSummaries (parent collection).
        2. For each summary, fetch deviceComplianceSettingStates per device.
        Applies the small-result-set detector on every paged response.

        Per Julien (BI for Intune team) 2026-05-20: this is THE endpoint family
        exhibiting the silent partial-page behavior. Pattern: requesting $top=100
        may return anywhere from 1 to 100 items, plus an @odata.nextLink claiming
        more data exists. Microsoft has classified this as "by design."

        NOTE: This test can take 5-15 minutes depending on the number of
        compliance settings configured in the tenant. Each summary requires its
        own paginated GET against /deviceComplianceSettingStates.
    #>
    param(
        [hashtable]$Headers,
        [int]$MaxRetries = 7,
        [int]$TimeoutSec = 60,
        [int]$PageSize   = 100
    )

    Write-Log "`n[$(Get-Date -Format 'HH:mm:ss')] ===== Compliance Policy Setting States Diagnostic ====="
    Write-Log "  Per Julien 2026-05-20: this is the endpoint family that returns small"
    Write-Log "  result sets silently. Detection rule: rows < `$top AND nextLink present."
    Write-Log "  This may take several minutes depending on the tenant's compliance config."

    $Problems = [System.Collections.Generic.List[object]]::new()
    $RetryLog = [System.Collections.Generic.List[object]]::new()
    $Summaries = [System.Collections.Generic.List[object]]::new()

    # Phase 1 — list all setting summaries
    Write-Log "`n  Phase 1: List deviceCompliancePolicySettingStateSummaries"
    $Url = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries?`$top=$PageSize"
    $Page = 0

    do {
        $Page++
        $RequestedUrl = $Url
        Write-Log "    [Page $Page] GET $Url"

        try {
            $Result = Invoke-GraphRequestWithRetry -Uri $Url -Headers $Headers `
                -MaxRetries $MaxRetries -PageNumber $Page `
                -Endpoint 'deviceCompliancePolicySettingStateSummaries' `
                -TimeoutSec $TimeoutSec
            $Response = $Result.Response
            foreach ($entry in $Result.RetryLog) { $RetryLog.Add($entry) }

            $PageCount = $Response.value.Count
            $Summaries.AddRange($Response.value)
            $Url = $Response.'@odata.nextLink'

            Write-Log "      Returned $PageCount items, nextLink: $(if ($Url) { 'YES' } else { 'no' })"

            if (($PageCount -lt $PageSize) -and ($Url)) {
                Write-Log "      [PROBLEM] Small result set on summaries — got $PageCount, requested $PageSize, nextLink present"
                $Problems.Add([PSCustomObject]@{
                    Type        = 'SmallResultSet'
                    Endpoint    = 'deviceCompliancePolicySettingStateSummaries'
                    Page        = $Page
                    RequestedUrl= $RequestedUrl
                    Requested   = $PageSize
                    Returned    = $PageCount
                    NextLink    = $Url
                    Timestamp   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                    Description = "Got $PageCount of $PageSize requested, but nextLink present"
                })
            }
        }
        catch {
            Write-Log "    [FATAL] Failed to retrieve summaries page $Page : $($_.Exception.Message)"
            break
        }
    } while ($Url)

    Write-Log "  Total summaries retrieved: $($Summaries.Count)"

    # Phase 2 — per-summary drill-down into deviceComplianceSettingStates
    Write-Log "`n  Phase 2: Fetch deviceComplianceSettingStates per summary"
    Write-Log "  (Iterating $($Summaries.Count) summaries — this is where the bug surfaces)"

    $Tested = 0
    $WithProblems = 0

    foreach ($Summary in $Summaries) {
        $Tested++
        $SummaryId = $Summary.id
        $SettingName = if ($Summary.settingName) { $Summary.settingName } else { '(no settingName)' }
        $SummaryStateCount = if ($Summary.state) { $Summary.state } else { '?' }

        $StateUrl = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries/$SummaryId/deviceComplianceSettingStates?`$top=$PageSize"
        $StatePage = 0
        $TotalStateRows = 0
        $SummaryHadProblem = $false

        Write-Log "`n  [$Tested/$($Summaries.Count)] $SettingName ($SummaryId)"

        do {
            $StatePage++
            $StateRequestedUrl = $StateUrl

            try {
                $StateResult = Invoke-GraphRequestWithRetry -Uri $StateUrl -Headers $Headers `
                    -MaxRetries $MaxRetries -PageNumber $StatePage `
                    -Endpoint "deviceComplianceSettingStates/$SettingName" `
                    -TimeoutSec $TimeoutSec
                $StateResponse = $StateResult.Response
                foreach ($entry in $StateResult.RetryLog) { $RetryLog.Add($entry) }

                $StateCount = $StateResponse.value.Count
                $TotalStateRows += $StateCount
                $StateUrl = $StateResponse.'@odata.nextLink'

                Write-Log "      Page $StatePage : $StateCount items, nextLink: $(if ($StateUrl) { 'YES' } else { 'no' })"

                if (($StateCount -lt $PageSize) -and ($StateUrl)) {
                    Write-Log "      [PROBLEM] Small result set — got $StateCount, requested $PageSize, nextLink present"
                    $SummaryHadProblem = $true
                    $Problems.Add([PSCustomObject]@{
                        Type        = 'SmallResultSet'
                        Endpoint    = "deviceComplianceSettingStates/$SettingName"
                        Page        = $StatePage
                        RequestedUrl= $StateRequestedUrl
                        Requested   = $PageSize
                        Returned    = $StateCount
                        NextLink    = $StateUrl
                        Timestamp   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                        Description = "Setting '$SettingName' — got $StateCount of $PageSize requested, but nextLink present"
                    })
                }
            }
            catch {
                Write-Log "      [ERROR] Page $StatePage failed: $($_.Exception.Message)"
                break
            }
        } while ($StateUrl)

        if ($SummaryHadProblem) { $WithProblems++ }
        Write-Log "    Total rows across all pages: $TotalStateRows"
    }

    Write-Log "`n  Compliance diagnostic summary:"
    Write-Log "    Summaries tested              : $Tested"
    Write-Log "    Summaries with small-set bug  : $WithProblems"
    Write-Log "    Total Problems flagged        : $($Problems.Count)"
    Write-Log "    Retry events                  : $($RetryLog.Count)"

    return [PSCustomObject]@{
        Summaries     = $Summaries
        Problems      = $Problems
        RetryLog      = $RetryLog
        TestedCount   = $Tested
        ProblemCount  = $Problems.Count
    }
}
#endregion

#region --- Main Execution ---
$AllEndpointResults  = [System.Collections.Generic.List[object]]::new()
$AllRetryEvents      = [System.Collections.Generic.List[object]]::new()
$AllScaleDiagnostics = [System.Collections.Generic.List[object]]::new()
$AllProblems         = [System.Collections.Generic.List[object]]::new()
$ComplianceResult    = $null

foreach ($Endpoint in $Endpoints) {

    # Bulk collection with retry
    $EndpointResult = Invoke-EndpointCollection -Endpoint $Endpoint -Headers $Headers `
        -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
    $AllEndpointResults.Add($EndpointResult)
    foreach ($entry in $EndpointResult.RetryLog) { $AllRetryEvents.Add($entry) }
    foreach ($p in $EndpointResult.Problems)     { $AllProblems.Add($p) }

    # Per-item assignment scale diagnostic
  if ($doScaleTest){
       $ScaleResults = Get-AssignmentScaleDiagnostic -Endpoint $Endpoint -Headers $Headers `
            -TimeoutSec $TimeoutSec
        if ($ScaleResults) {
            foreach ($r in $ScaleResults) { $AllScaleDiagnostics.Add($r) }
        }
    }
}

# v2.0 — Compliance policy setting states diagnostic (small-result-set focus)
if ($doComplianceTest) {
    $ComplianceResult = Invoke-CompliancePolicyDiagnostic -Headers $Headers `
        -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec -PageSize $PageSize
    if ($ComplianceResult) {
        foreach ($entry in $ComplianceResult.RetryLog) { $AllRetryEvents.Add($entry) }
        foreach ($p in $ComplianceResult.Problems)     { $AllProblems.Add($p) }
    }
}
#endregion

#region --- Final Summary ---
Write-Log "`n`n=========================================="
Write-Log "  FINAL DIAGNOSTIC SUMMARY"
Write-Log "  Run timestamp : $RunTimestamp"
Write-Log "  Token valid   : $(if ((Get-Date) -lt $TokenExpires) { 'YES' } else { 'NO - EXPIRED' })"
Write-Log "=========================================="

foreach ($R in $AllEndpointResults) {
    Write-Log "`n  $($R.EndpointName)"
    Write-Log "    Items retrieved    : $($R.ItemCount)"
    Write-Log "    Pages fetched      : $($R.Pages)"
    Write-Log "    Effective page size: $($R.EffectivePageSize)"
    Write-Log "    Total time         : $($R.TotalMs)ms ($([math]::Round($R.TotalMs / 1000, 1))s)"
    Write-Log "    Avg time/page      : $([math]::Round($R.TotalMs / [math]::Max($R.Pages, 1), 1))ms"
    Write-Log "    Retry events       : $(($R.RetryLog).Count)"
    Write-Log "    Fatal error        : $(if ($R.FatalError) { 'YES' } else { 'No' })"

    if ($R.Results.Count -gt 0 -and $R.Results[0].'@odata.type') {
        $TypeBreakdown = $R.Results | Group-Object '@odata.type' | Sort-Object Count -Descending
        Write-Log "    Type breakdown:"
        foreach ($t in $TypeBreakdown) {
            Write-Log "      $($t.Count.ToString().PadLeft(6))  $($t.Name)"
        }
    }
}

# Retry event detail
if ($AllRetryEvents.Count -gt 0) {
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
if ($AllProblems.Count -gt 0) {
    Write-Log "  Total Problems flagged: $($AllProblems.Count)"
    $AllProblems | Format-Table Type, Endpoint, Page, Requested, Returned, Description -AutoSize |
        Out-String | ForEach-Object { Write-Log $_ }
} else {
    Write-Log "  No Problems flagged. Either the bug did not surface during this run,"
    Write-Log "  or all paged responses returned the requested page size."
}

# Append CSV data inline to log file for single-file delivery
Write-Log "`n------------------------------------------"
Write-Log "  RETRY EVENTS (CSV)"
Write-Log "------------------------------------------"
if ($AllRetryEvents.Count -gt 0) {
    $AllRetryEvents | ConvertTo-Csv -NoTypeInformation | ForEach-Object { Add-Content -Path $script:LogPath -Value $_ }
} else {
    Add-Content -Path $script:LogPath -Value "No retry events recorded."
}

Write-Log "`n------------------------------------------"
Write-Log "  PROBLEMS (CSV)"
Write-Log "------------------------------------------"
if ($AllProblems.Count -gt 0) {
    $AllProblems | ConvertTo-Csv -NoTypeInformation | ForEach-Object { Add-Content -Path $script:LogPath -Value $_ }
} else {
    Add-Content -Path $script:LogPath -Value "No Problems flagged."
}

if ($doScaleTest){
    Write-Log "`n------------------------------------------"
    Write-Log "  ASSIGNMENT SCALE DIAGNOSTIC (CSV)"
    Write-Log "------------------------------------------"
    if ($AllScaleDiagnostics -and $AllScaleDiagnostics.Count -gt 0) {
        $AllScaleDiagnostics | ConvertTo-Csv -NoTypeInformation | ForEach-Object { Add-Content -Path $script:LogPath -Value $_ }
    } else {
        Add-Content -Path $script:LogPath -Value "No scale diagnostic data recorded."
    }
}
Write-Log "`n  Log file: $($script:LogPath)"
Write-Log "  Done."
#endregion