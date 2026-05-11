# S1 Coverage Gap Remediation

A PowerShell automation script that identifies Windows endpoints present in Active Directory but missing from SentinelOne (S1), then remotely installs the S1 agent on those machines.

---

## Overview

This script solves a common EDR coverage gap problem: machines that are active in AD but have fallen out of (or were never enrolled in) your SentinelOne deployment. It:

1. Queries Active Directory for computers that have logged in within the last 5 days
2. Pulls the full SentinelOne agent inventory via the S1 API
3. Diffs the two lists to find machines missing S1 coverage
4. Applies an exclusion list and regex filters to remove expected gaps
5. Authenticates using a YubiKey-derived credential
6. Remotely copies and installs the S1 agent on each uncovered machine
7. Logs installation results with human-readable exit code translation

---

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell 5.1+ | Tested on Windows |
| Active Directory module | `Import-Module ActiveDirectory` |
| [ykman](https://developers.yubico.com/yubikey-manager/) | YubiKey Manager CLI, must be in PATH |
| YubiKey (slot 2 configured) | Used for remote session authentication |
| Network access to SentinelOne API | `usea1-s1sy.sentinelone.net` |
| [Thycotic Secret Server](https://docs.delinea.com/online-help/secret-server/) | Stores the S1 API key; requires an API service account |
| S1 installer on a network share | Path configured in script |
| WinRM enabled on target machines | Required for `New-PSSession` / `Invoke-Command` |
| `C:\Temp` writable on targets | Installer is staged here; script prompts to create if missing |

---

## Configuration

Several values are redacted in the script and must be set before use. Search for `<redacted>` placeholders:

| Placeholder | Description |
|---|---|
| Secret Server username | API service account username |
| Secret Server token URL | `/oauth2/token` endpoint of your SS instance |
| Environment variable name | Local env var storing the SS service account password |
| Secret Server secret URL | API URL for the specific secret holding the S1 API key |
| S1 installer network path | UNC path to `SentinelOneInstaller.exe` |
| Site token | Your SentinelOne site token, passed as `-t` to the installer |
| Exclusion list path | Path to a plaintext file with one hostname per line |
| Regex exclusion pattern | Inline regex to filter additional hostnames |
| Output file path | Where the final gap list is written |

---

## How It Works

### 1. `adGrab`
Queries AD for enabled computers whose `LastLogonDate` is within the last 5 days. The 5-day window accounts for users who are on PTO or out sick but still expected to be active.

### 2. `ssToken`
Authenticates to Secret Server using OAuth2 (password grant) and retrieves the SentinelOne API key. The service account password is stored as a local environment variable — never hardcoded.

### 3. `s1Grab`
Pages through the SentinelOne `/agents` endpoint (1,000 results per page, cursor-based pagination) and returns a flat list of all enrolled computer names.

### 4. Gap Analysis
Uses `Compare-Object` to find machines in AD but not in S1. Applies two layers of exclusions:
- A plaintext exclusion file (e.g., servers, kiosks, known exceptions)
- An inline regex filter for pattern-based exclusions

### 5. `yubiSecret`
Derives a credential by computing the HMAC-SHA1 of a username string using the YubiKey's slot 2 OTP secret via `ykman`. Retries in a loop until the key is inserted. The result is used as the password for remote PS sessions.

### 6. `s1InstallTest`
For each machine in the gap list:
- Pings the host; skips if unreachable
- Opens a PS remoting session using the YubiKey-derived credential
- Copies the S1 installer to `C:\Temp` on the remote machine
- Runs the installer silently with a 10-minute timeout watchdog
- Maps the exit code to a human-readable description using a lookup table
- Records results as a `PSCustomObject` array

Results are written to `C:\Temp\s1Scan.txt`.

---

## Exit Code Reference

The script includes a full translation table for SentinelOne installer exit codes. Common ones:

| Code | Meaning |
|---|---|
| `0` | Success |
| `100` | Previous agent uninstalled — reboot required before new install |
| `1000` | Same or higher version already installed |
| `2000` | General failure |
| `2008` | Missing site token |
| `2020` | Insufficient disk space |
| `2034` | Management connectivity check failed |

See the `$s1Table` hashtable in the script for the full list.

---

## Output

The script produces two files:

- **Gap list** (path configured via redacted variable): Newline-delimited list of hostnames missing S1 coverage after exclusions
- **`C:\Temp\s1Scan.txt`**: Per-machine install results with columns `Computer`, `Status`, and `S1_Install`

---

## Security Notes

- The S1 API key is never stored on disk — it is retrieved at runtime from Secret Server and held only in memory
- The remote session password is derived from a physical YubiKey, requiring possession of the hardware token to run the script
- Credentials are passed as `PSCredential` objects; the password is stored as a `SecureString`
- All API calls use TLS 1.2

---

## Limitations

- Targets must have WinRM enabled and reachable on the network
- The YubiKey must be physically inserted on the machine running the script
- The 5-day AD filter may miss machines that are active but haven't logged on recently (e.g., servers)
- Install attempts time out after 10 minutes per machine; timed-out machines are logged but not retried
