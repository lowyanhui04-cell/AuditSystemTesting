# EndpointLens rule catalogue — rule set 2026.1

Project baseline of 11 focused checks. Motivated by CIS Controls 1, 2, 4 and 5 and NIST SP 800-128; this is **not** a CIS Benchmark or NIST compliance assessment. The live catalogue is also shown in the dashboard under **Rule catalogue**, generated from `src/EndpointLens.Core/Rules/BaselineRules.cs`.

## Outcomes

| Outcome | Meaning |
|---|---|
| PASS | Evidence meets the expected value |
| FAIL | Evidence shows a non-compliant configuration |
| WARNING | Policy-dependent; may be acceptable, needs review |
| UNKNOWN | Evidence missing / not collectable. **Never counted as a pass.** |
| N/A | Rule does not apply (reason recorded in the evidence text) |

## Rules

| ID | Severity | Title | Expected | Evidence | Applicability |
|---|---|---|---|---|---|
| FW-001 | High | Windows Defender Firewall enabled for all profiles | Domain, Private, Public enabled | `firewall.profiles[].enabled` (Group Policy value overrides local; stopped MpsSvc = off) | All |
| AV-001 | High | Antivirus registered and enabled | ≥1 Security Center product enabled, or Defender real-time on | `antivirus.products[]`, `antivirus.defender` | All |
| UAC-001 | High | UAC enabled and prompts admins | `EnableLUA=1`; `ConsentPromptBehaviorAdmin=0` → WARNING | `securityConfig.uac*` | All |
| SMB-001 | High | SMBv1 server disabled | SMB1 disabled / not installed | `securityConfig.smb1ServerEnabled` | All |
| UPD-001 | High | OS updates installed recently | Latest hotfix ≤ 45 days before collection | `system.lastHotfixInstalledUtc` | All |
| AV-002 | Medium | Antivirus signatures up to date | Defender ≤ 7 days, or product reports up to date | `antivirus.defender.signatureAgeDays`, `products[].signaturesUpToDate` | N/A if no enabled AV |
| ACC-001 | Medium | Built-in Guest disabled | Account SID `*-501` disabled | `localAccounts.accounts[]` | All |
| PWD-001 | Medium | Minimum password length ≥ 8 | `MinimumLength ≥ 8` | `localAccounts.passwordPolicy` | All |
| RDP-001 | Medium | RDP disabled or NLA required | `fDenyTSConnections=1` or `UserAuthentication=1` | `securityConfig.rdp*` | N/A on Home editions |
| ENC-001 | Medium | System drive BitLocker on | ProtectionStatus = On | `securityConfig.systemDriveBitLocker` | Needs elevation; N/A on Home without the interface |
| ACC-002 | Low | Local Administrators limited | ≤ 2 active members, else **WARNING** (policy-dependent) | `localAccounts.administrators[]` | All |

## Scoring

* Weights: High = 10, Medium = 5, Low = 2.
* **Score** = 100 × (Σ weight of PASS + ½ Σ weight of WARNING) ÷ Σ weight of evaluated rules (PASS/FAIL/WARNING).
* **Coverage** = evaluated rules ÷ applicable rules (all except N/A). UNKNOWN lowers coverage and is excluded from the score, so missing evidence can never raise it.
* **Risk level**: any High FAIL → High; else any Medium FAIL → Medium; else any FAIL/WARNING → Low; else any UNKNOWN → Incomplete; else Minimal.

## Versioning

Bump `RuleEngine.RuleSetVersion` and the affected rule's `Version` whenever logic or thresholds change. Each stored finding copies the rule ID, version, title, expected value and recommendation at evaluation time, so historical audits keep the wording that produced them.

## Known evidence caveats

* `AntiVirusProduct.productState` is undocumented by Microsoft. The decoding used (bit `0x1000` = enabled, bit `0x10` = signatures out of date) is the widely used community interpretation; verify per supported product during testing.
* `Win32_QuickFixEngineering.InstalledOn` lists hotfixes only, not every update type.
* Application inventory covers uninstall registry entries (HKLM 64/32-bit and the agent user's HKCU); portable apps are not included.
