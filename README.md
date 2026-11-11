# EndpointLens — Automated IT Security Audit System for Windows Endpoints

A portable Windows agent collects read-only asset and security evidence. A central ASP.NET Core service validates it, evaluates it against a versioned rule set, and presents findings, severity, recommendations and reports in an authenticated dashboard.

```
Windows evidence collection ─► validated snapshot (HTTPS) ─► rule evaluation & scoring ─► SQLite ─► dashboard, HTML/CSV/JSON reports
        (Agent, WPF)               Bearer endpoint credential      (Core rule engine)        (EF Core)    (Razor Pages, cookie login)
                 └─ local outbox / JSON export ─► manual import (idempotent by snapshotId)
```

## Solution layout

| Project | Purpose |
|---|---|
| `src/EndpointLens.Core` | Snapshot contract, validator, rule engine, 11 baseline rules, scoring |
| `src/EndpointLens.Agent` | Portable .NET 9 WPF agent (3-step window: Ready, Collecting, Results): collectors (CIM/WMI, registry, netapi32), DPAPI-protected settings, HTTPS submission, outbox/retry, JSON export, CLI `--collect` |
| `src/EndpointLens.Server` | ASP.NET Core API + Razor Pages dashboard, SQLite via EF Core, HTML report, CSV/JSON export, manual import |
| `tests/EndpointLens.Tests` | xUnit: ≥4 controlled cases per rule (53 total), scoring/validation, API security, dashboard end-to-end |
| `docs/RULES.md` | Rule catalogue, outcomes, scoring and versioning |

## Evidence categories (7)

1. **Computer specifications** — manufacturer, model, serial, chassis, OS caption/edition/build, CPU, memory, disks, Secure Boot, last boot, last hotfix
2. **Installed applications** — uninstall registry entries (HKLM 64/32-bit, HKCU)
3. **Current user** — interactive console user, separately from the (possibly elevated) agent process account
4. **Local accounts** — accounts, Administrators group members (by well-known SID, language-independent), password/lockout policy
5. **Antivirus** — Windows Security Center products + Microsoft Defender status
6. **Firewall** — effective state per profile (Group Policy overrides local), firewall service state
7. **Security configuration** — UAC, SMBv1, RDP/NLA, BitLocker on the system drive

Each category carries an explicit status (`Collected`, `Partial`, `AccessDenied`, `NotSupported`, `TimedOut`, `Failed`) and duration; each collector has a timeout. Nothing is written to the endpoint except the agent's own files under `%LOCALAPPDATA%\EndpointLens`. No passwords, documents, browser history or keys are read.

## Requirements

* Windows 10/11, .NET 9 SDK (development), Visual Studio 2022 17.12+ or `dotnet` CLI
* A TLS certificate the endpoints trust (see below)

## Run it

```bash
dotnet test
```

```bash
dotnet run --project src/EndpointLens.Server --launch-profile https
```

1. Open https://localhost:5443. On first run you are sent to **Create administrator** (min. 12-character password). This page closes once an admin exists.
2. **Enroll endpoint** → copy the one-time credential (`el_<id>_<secret>`; only its SHA-256 hash is stored).
3. On the endpoint, run `EndpointLens.Agent.exe`. Click **Connect to dashboard**, enter the server address and credential, click **Test connection**, then **Save**. Use **Restart as administrator** for full coverage (BitLocker needs elevation).
4. Click **Start audit**. The agent goes through three steps — **Ready → Collecting → Results** — and uploads the result automatically.
5. On the dashboard, **Overview** lists every computer (worst first) and the most common failures. Open a computer for its findings, hardware, software, accounts, security settings and history; **Findings** compares all computers; each audit has an **HTML report** and **CSV / JSON** export.

If the upload fails, the audit stays in `%LOCALAPPDATA%\EndpointLens\outbox`; the agent offers **Upload now** next time, or use **Save a copy** and the dashboard's **Import audit file** page. Uploading the same audit twice never creates a duplicate.

Command-line collection (no window, nothing sent):

```bash
EndpointLens.Agent.exe --collect snapshot.json
```

### Build the portable agent

```bash
dotnet publish src/EndpointLens.Agent -c Release -o publish
```

Produces a single self-contained `EndpointLens.Agent.exe` (~48 MB) that runs without installing .NET.

### HTTPS certificate

The agent keeps certificate validation on. For a demo on the development PC, trust the ASP.NET Core development certificate once:

```bash
dotnet dev-certs https --trust
```

For other lab VMs, create a certificate whose SAN matches the server's host name or IP, install its issuing certificate in each VM's *Trusted Root Certification Authorities*, and configure Kestrel in `appsettings.json`:

```json
"Kestrel": { "Endpoints": { "Https": { "Url": "https://0.0.0.0:5443",
  "Certificate": { "Path": "certs/endpointlens.pfx", "Password": "<from user-secrets or env var>" } } } }
```

Keep the certificate password out of source control (e.g. environment variable `Kestrel__Endpoints__Https__Certificate__Password`).

## Security design

* **Separate credentials**: endpoint credentials only authorize `POST /api/v1/snapshots` for that endpoint (credential ID must match its hash; constant-time compare). They give no dashboard access. Rotate or revoke per endpoint.
* **Dashboard**: cookie auth (HttpOnly, Secure, SameSite=Strict, 8 h sliding), passwords hashed with ASP.NET Core Identity `PasswordHasher` (PBKDF2), lockout after 5 failures for 15 min, antiforgery on all forms, every page requires sign-in by default (fallback policy).
* **Input validation**: HTTPS required, 5 MB body limit, JSON depth limit, schema version, plausible timestamps, list and string length bounds.
* **Output encoding**: all endpoint-supplied strings are HTML-encoded by Razor; CSV cells are quoted and prefixed against formula injection; strict security headers (CSP, `X-Frame-Options: DENY`, `nosniff`).
* **Privacy**: credentials are stored on the endpoint with DPAPI and never logged. Collected fields are limited to those listed above.
* **Honest results**: missing evidence → UNKNOWN (never PASS), rule exceptions → UNKNOWN, coverage is shown next to every score.

## Database

SQLite file `endpointlens.db` in the server's working directory, created automatically (`EnsureCreated`). Tables: `AdminUsers`, `Endpoints`, `Audits` (full snapshot JSON kept verbatim as evidence + summary columns), `Findings` (rule text and version copied at evaluation time). For schema evolution, switch to EF Core migrations (`dotnet ef migrations add Initial`).

## Scope limits

Windows 10/11 client endpoints in an authorised test environment; on-demand audits only. Out of scope: backup checks, Windows Server/macOS/Linux, AD/GPO assessment, scheduling, alerts, remediation, malware/CVE detection, SIEM/EDR, CIS/NIST certification.
