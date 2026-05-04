# Graph API Error Finder

A PowerShell diagnostic script that collects Microsoft Graph API request data — including pagination behavior, throttling responses, retry timings, and per-item assignment scale — so customers can share concrete evidence with Microsoft Support when troubleshooting slow syncs or sync failures with Microsoft Intune.

This script is published by **PowerStacks** for use by **BI for Intune** customers (and anyone else integrating with Intune-related Graph endpoints) who need to gather diagnostic data for a Microsoft Support case.

> **Use this script when:** your Intune sync into BI for Intune (or any direct Graph API integration) is slow, intermittently failing, or returning HTTP 429 / 500 / 503 / 504, and Microsoft Support has asked for repro details.

---

## What the script does

The script authenticates to the Microsoft Graph API as a service principal and runs a controlled diagnostic against three endpoints that historically exhibit scale issues:

| Endpoint | What it queries |
|----------|-----------------|
| `deviceAppManagement/mobileApps` | All mobile apps with `assignments` and `categories` expanded |
| `deviceManagement/deviceManagementScripts` | All platform scripts with `assignments` expanded |
| `deviceManagement/deviceHealthScripts` | All proactive remediations (with auto page-size discovery) |

For each endpoint it captures:

- HTTP status codes per attempt (success, 429, 500, 503, 504, gateway timeouts)
- Response time per attempt and per page (in milliseconds)
- `Retry-After` headers (when present) and the exponential backoff applied when not
- Number of retries needed before a successful page
- Pagination behavior (`@odata.nextLink` chain length)
- Total items returned per endpoint and per `@odata.type` breakdown

For `deviceHealthScripts`, the script auto-discovers the largest page size that succeeds (starting at 100 and halving on failure) — useful for showing Microsoft the threshold at which their endpoint begins returning errors.

Optionally (set `$doScaleTest = $true`), the script also iterates every item per endpoint and queries `/assignments` individually, capturing per-item response times, assignment counts, "All Devices" / "All Users" scope flags, and the slowest items. This data helps Microsoft identify whether a single noisy item is causing backend pressure.

All output is written to console **and** to a single timestamped log file under `C:\Temp` (configurable). The log includes a CSV-formatted retry-event table at the bottom so it can be opened directly in Excel.

---

## Prerequisites

### PowerShell
- Windows PowerShell 5.1 or PowerShell 7+ (script uses `Invoke-RestMethod` and standard cmdlets only — no external modules required)

### Microsoft Entra ID (Azure AD) app registration
You need an app registration with **client-credentials** authentication and the right Graph permissions.

1. Create or reuse an app registration in **Microsoft Entra admin center → Identity → Applications → App registrations → New registration**.
2. Generate a client secret under **Certificates & secrets → Client secrets**.
3. Under **API permissions**, add the following **application** (not delegated) permissions and grant admin consent:

| Permission | Why |
|------------|-----|
| `DeviceManagementApps.Read.All` | Read mobile apps and their assignments |
| `DeviceManagementConfiguration.Read.All` | Read platform scripts and their assignments |
| `DeviceManagementManagedDevices.Read.All` | Required for proactive remediations / device health scripts |

> If you're already running BI for Intune, the existing app registration likely has these permissions and can be reused. Check with your administrator before creating a new one.

4. Note the **Tenant ID**, **Application (client) ID**, and **client secret value** from the app registration overview and certificates pages.

---

## Configuration

Open `Graph API Error Finder.ps1` and set the values at the top of the **Configuration** region:

```powershell
$TenantId     = "<your-tenant-guid>"
$ClientId     = "<your-app-registration-client-id>"
$ClientSecret = "<your-client-secret>"
$PageSize     = 100      # Default page size for each endpoint
$MaxRetries   = 7        # Per-page retry ceiling
$LogDir       = "C:\Temp"
$doScaleTest  = $False   # Set $True for per-item assignment diagnostic (slower)
```

### Handling the client secret

The script reads the secret as a plain string for simplicity, but **never commit a real secret** to source control or share it. Recommended patterns:

- Set the value in your local copy of the script and don't push the change.
- Or replace the literal with `$ClientSecret = $env:GRAPH_CLIENT_SECRET` and set the environment variable in your shell:

  ```powershell
  $env:GRAPH_CLIENT_SECRET = 'paste-secret-here'
  ```

- Or read from a credential store (`Get-Secret` from `Microsoft.PowerShell.SecretManagement`).

After the support case is closed, **rotate the client secret** in Entra ID. Treat any secret that has been pasted into a script file as compromised.

---

## Running the script

```powershell
.\"Graph API Error Finder.ps1"
```

You'll see live progress in the console:

```
==========================================
  Graph API Diagnostic Script
  Run timestamp : 20260504_120300
  Log file      : C:\Temp\GraphDiag_20260504_120300.log
==========================================

[12:03:00] Acquiring token...
  Token acquired successfully
  Expires      : 13:03:00 (in 3600s)
  ...

[12:03:01] ===== mobileApps =====
  Using page size: 100
  URL: https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$expand=assignments,categories&$top=100

  [Page 1] GET ...
    Attempt 1 succeeded in 2840ms (2.8s)
    Records this page : 100
    Running total     : 100
    ...
```

A typical run takes 1–10 minutes depending on tenant size. The scale test (`$doScaleTest = $True`) can take significantly longer because it hits each item individually.

---

## What to send to Microsoft Support

After the run finishes, the entire log is in `C:\Temp\GraphDiag_<timestamp>.log` (or your configured `$LogDir`). That single file is what you attach to the support case — it contains:

- The end-to-end timing for every page request
- Every retry event with HTTP status and wait time
- A type breakdown so Microsoft can see whether the slow endpoint is dominated by a particular app type
- A CSV-formatted retry table at the bottom that Microsoft can paste directly into Excel
- (If `$doScaleTest = $True`) a CSV listing the slowest items and any "All Devices" / "All Users" assignments

Before sharing, scan the log for any sensitive values you'd like to redact — the script does not log secrets, but it does include your tenant ID and app registration object ID, which is usually fine for a support case.

---

## Security notes

- **Read-only.** The script never writes to or modifies your Intune tenant. It only issues `GET` requests.
- **Application permissions.** The script uses client-credentials authentication, which means it acts as the application — not as a user. The granted Graph permissions limit what it can read.
- **Credential hygiene.** Never commit your client secret. Rotate the secret after use. Limit the app registration to read-only Graph permissions and remove the assignment when you're done diagnosing.
- **Network access.** The script reaches `https://login.microsoftonline.com` and `https://graph.microsoft.com`. No data leaves your machine other than to those Microsoft endpoints.

---

## License

[MIT](LICENSE) — use, modify, and share freely.

## Maintainer

Maintained by **PowerStacks**. Issues and pull requests welcome on the [issue tracker](../../issues).
