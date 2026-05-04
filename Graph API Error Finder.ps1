<#
.SYNOPSIS
    Graph API diagnostic script for mobileApps endpoint.
.DESCRIPTION
    Retrieves all mobile apps from Intune via Graph API with enhanced
    diagnostic output for troubleshooting pagination, throttling, and
    response anomalies.
.NOTES
    Author  : John Marcum (PJM)
    Version : 1.0
    Requires: TenantId, ClientId, ClientSecret variables to be set before execution
#>


#region --- Configuration ---
$TenantId = ""
$ClientId = ""
$ClientSecret = "" # <------Removed to protect privacy
$PageSize     = 100
$MaxRetries   = 7
$LogDir       = "C:\Temp"
$doScaleTest = $False

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
#endregion

#region --- Main Execution ---
$AllEndpointResults  = [System.Collections.Generic.List[object]]::new()
$AllRetryEvents      = [System.Collections.Generic.List[object]]::new()
$AllScaleDiagnostics = [System.Collections.Generic.List[object]]::new()

foreach ($Endpoint in $Endpoints) {

    # Bulk collection with retry
    $EndpointResult = Invoke-EndpointCollection -Endpoint $Endpoint -Headers $Headers `
        -MaxRetries $MaxRetries -TimeoutSec $TimeoutSec
    $AllEndpointResults.Add($EndpointResult)
    foreach ($entry in $EndpointResult.RetryLog) { $AllRetryEvents.Add($entry) }

    # Per-item assignment scale diagnostic
  if ($doScaleTest){
       $ScaleResults = Get-AssignmentScaleDiagnostic -Endpoint $Endpoint -Headers $Headers `
            -TimeoutSec $TimeoutSec
        if ($ScaleResults) {
            foreach ($r in $ScaleResults) { $AllScaleDiagnostics.Add($r) }
        } 
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

# Append CSV data inline to log file for single-file delivery
Write-Log "`n------------------------------------------"
Write-Log "  RETRY EVENTS (CSV)"
Write-Log "------------------------------------------"
if ($AllRetryEvents.Count -gt 0) {
    $AllRetryEvents | ConvertTo-Csv -NoTypeInformation | ForEach-Object { Add-Content -Path $script:LogPath -Value $_ }
} else {
    Add-Content -Path $script:LogPath -Value "No retry events recorded."
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