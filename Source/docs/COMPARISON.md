# Review of the four EndpointLens versions

| Version | What the source provides | Integration decision |
| --- | --- | --- |
| V1 — Windows Security Audit starter | A WPF window, PowerShell configuration checks and an offline HTML report. Includes a backup check. | Keep the offline audit-to-report workflow. The final baseline follows the current proposal's scope. |
| V2 — Proposal Aligned | A WPF collector and Razor/SQLite dashboard with inventory, ten checks and HTML/JSON export. Ingestion uses one server-configured submission key. | Keep the split between read-only collection and central reporting. Use V4's scoped credentials and rule metadata in the combined project. |
| V3 — GPT | An embedded PowerShell script for inventory and ten checks, local HTML/JSON export, Basic-auth dashboard and shared upload key. The server stores findings sent by the collector. | Keep self-contained delivery. Use structured Windows probes and server-side evaluation from the V4 foundation. |
| V4 — EndpointLens | Seven evidence categories, physical disk and RAM-module details, versioned rules, SQLite, scoped HTTPS submission, import, structured reports and tests. The collector starts in a separate WPF window. | Use this foundation. Move collection into the dashboard executable, so the same Windows build opens the local dashboard and can also host the central dashboard in server mode. |

## Changes in the integrated build

- One self-contained Windows x64 executable and one codebase. A regular launch opens the browser-based local dashboard. The central mode exposes the existing authenticated views, API and report history.
- Local collection is started through an authenticated POST and stored locally before automatic upload on an enrolled EXE. Each enrolled package contains its own destination and upload credential.
- A report JSON includes findings and score. An independently exportable raw snapshot can be submitted again or imported.
- Registered product name and verified antivirus health are presented separately. The Windows Security Center raw product state is kept as evidence and does not set third-party health.
- The shared rule engine evaluates eleven baseline controls with separate score and coverage. The documentation identifies which results need verification on physical Windows devices or VMs.
