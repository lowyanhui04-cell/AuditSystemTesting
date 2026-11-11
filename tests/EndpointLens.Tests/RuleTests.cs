using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;
using static EndpointLens.Tests.TestSnapshots;

namespace EndpointLens.Tests;

/// <summary>
/// Controlled expected-result cases: at least four per rule, covering pass, non-compliant,
/// policy-dependent / not-applicable and missing-evidence outcomes.
/// </summary>
public class RuleTests
{
    public static IEnumerable<object[]> Cases()
    {
        // ---- FW-001 Firewall ----
        yield return Case<FirewallEnabledRule>("all profiles on", Compliant(), Outcome.Pass);
        yield return Case<FirewallEnabledRule>("public profile off", With(s => s.Firewall.Data!.Profiles[2].Enabled = false), Outcome.Fail);
        yield return Case<FirewallEnabledRule>("one profile unreadable", With(s => s.Firewall.Data!.Profiles[0].Enabled = null), Outcome.Unknown);
        yield return Case<FirewallEnabledRule>("section access denied", With(s => s.Firewall = Failed<FirewallInfo>()), Outcome.Unknown);
        yield return Case<FirewallEnabledRule>("no profiles reported", With(s => s.Firewall.Data!.Profiles.Clear()), Outcome.Unknown);

        // ---- AV-001 Antivirus enabled ----
        yield return Case<AntivirusEnabledRule>("defender active", Compliant(), Outcome.Pass);
        yield return Case<AntivirusEnabledRule>("third-party enabled, defender passive", With(s =>
        {
            s.Antivirus.Data!.Products.Add(new AntivirusProduct { DisplayName = "Avira Security", Enabled = true, SignaturesUpToDate = true });
            s.Antivirus.Data.Products[0].Enabled = false;
            s.Antivirus.Data.Defender!.RealTimeProtectionEnabled = false;
        }), Outcome.Pass);
        yield return Case<AntivirusEnabledRule>("all disabled", With(s =>
        {
            s.Antivirus.Data!.Products[0].Enabled = false;
            s.Antivirus.Data.Defender!.RealTimeProtectionEnabled = false;
        }), Outcome.Fail);
        yield return Case<AntivirusEnabledRule>("nothing registered, defender present but off", With(s =>
        {
            s.Antivirus.Data!.Products.Clear();
            s.Antivirus.Data.Defender!.RealTimeProtectionEnabled = false;
        }), Outcome.Fail);
        yield return Case<AntivirusEnabledRule>("no AV data at all", With(s => { s.Antivirus.Data!.Products.Clear(); s.Antivirus.Data.Defender = null; }), Outcome.Unknown);
        yield return Case<AntivirusEnabledRule>("section failed", With(s => s.Antivirus = Failed<AntivirusInfo>()), Outcome.Unknown);

        // ---- AV-002 Signatures ----
        yield return Case<AntivirusSignaturesRule>("defender 1 day old", Compliant(), Outcome.Pass);
        yield return Case<AntivirusSignaturesRule>("defender 8 days old", With(s => s.Antivirus.Data!.Defender!.SignatureAgeDays = 8), Outcome.Fail);
        yield return Case<AntivirusSignaturesRule>("defender exactly 7 days (boundary)", With(s => s.Antivirus.Data!.Defender!.SignatureAgeDays = 7), Outcome.Pass);
        yield return Case<AntivirusSignaturesRule>("defender age unreadable", With(s => s.Antivirus.Data!.Defender!.SignatureAgeDays = null), Outcome.Unknown);
        yield return Case<AntivirusSignaturesRule>("third-party out of date", With(s =>
        {
            s.Antivirus.Data!.Defender!.RealTimeProtectionEnabled = false;
            s.Antivirus.Data.Products[0].Enabled = false;
            s.Antivirus.Data.Products.Add(new AntivirusProduct { DisplayName = "Avira Security", Enabled = true, SignaturesUpToDate = false });
        }), Outcome.Fail);
        yield return Case<AntivirusSignaturesRule>("no enabled AV", With(s =>
        {
            s.Antivirus.Data!.Defender!.RealTimeProtectionEnabled = false;
            s.Antivirus.Data.Products[0].Enabled = false;
        }), Outcome.NotApplicable);

        // ---- UAC-001 ----
        yield return Case<UacEnabledRule>("enabled with prompt", Compliant(), Outcome.Pass);
        yield return Case<UacEnabledRule>("EnableLUA = 0", With(s => s.SecurityConfig.Data!.UacEnabled = false), Outcome.Fail);
        yield return Case<UacEnabledRule>("elevate without prompting", With(s => s.SecurityConfig.Data!.UacConsentPromptBehaviorAdmin = 0), Outcome.Warning);
        yield return Case<UacEnabledRule>("EnableLUA missing", With(s => s.SecurityConfig.Data!.UacEnabled = null), Outcome.Unknown);
        yield return Case<UacEnabledRule>("section failed", With(s => s.SecurityConfig = Failed<SecurityConfigInfo>()), Outcome.Unknown);

        // ---- SMB-001 ----
        yield return Case<Smb1DisabledRule>("disabled", Compliant(), Outcome.Pass);
        yield return Case<Smb1DisabledRule>("enabled", With(s => s.SecurityConfig.Data!.Smb1ServerEnabled = true), Outcome.Fail);
        yield return Case<Smb1DisabledRule>("not determinable", With(s => s.SecurityConfig.Data!.Smb1ServerEnabled = null), Outcome.Unknown);
        yield return Case<Smb1DisabledRule>("section timed out", With(s => s.SecurityConfig = EvidenceSection<SecurityConfigInfo>.Missing(EvidenceStatus.TimedOut, "timeout")), Outcome.Unknown);

        // ---- UPD-001 ----
        yield return Case<OsUpdateRecencyRule>("10 days ago", Compliant(), Outcome.Pass);
        yield return Case<OsUpdateRecencyRule>("45 days (boundary)", With(s => s.System.Data!.LastHotfixInstalledUtc = CollectedAt.AddDays(-45)), Outcome.Pass);
        yield return Case<OsUpdateRecencyRule>("90 days ago", With(s => s.System.Data!.LastHotfixInstalledUtc = CollectedAt.AddDays(-90)), Outcome.Fail);
        yield return Case<OsUpdateRecencyRule>("no hotfix date", With(s => s.System.Data!.LastHotfixInstalledUtc = null), Outcome.Unknown);
        yield return Case<OsUpdateRecencyRule>("system section failed", With(s => s.System = Failed<SystemInfo>()), Outcome.Unknown);

        // ---- ACC-001 Guest ----
        yield return Case<GuestAccountDisabledRule>("guest disabled", Compliant(), Outcome.Pass);
        yield return Case<GuestAccountDisabledRule>("guest enabled", With(s => s.LocalAccounts.Data!.Accounts[1].Enabled = true), Outcome.Fail);
        yield return Case<GuestAccountDisabledRule>("renamed guest still detected by SID", With(s =>
        {
            s.LocalAccounts.Data!.Accounts[1].Name = "Visitor";
            s.LocalAccounts.Data.Accounts[1].Enabled = true;
        }), Outcome.Fail);
        yield return Case<GuestAccountDisabledRule>("guest not in list", With(s => s.LocalAccounts.Data!.Accounts.RemoveAt(1)), Outcome.Unknown);
        yield return Case<GuestAccountDisabledRule>("guest state unknown", With(s => s.LocalAccounts.Data!.Accounts[1].Enabled = null), Outcome.Unknown);

        // ---- PWD-001 ----
        yield return Case<PasswordLengthRule>("length 12", Compliant(), Outcome.Pass);
        yield return Case<PasswordLengthRule>("length 8 (boundary)", With(s => s.LocalAccounts.Data!.PasswordPolicy!.MinimumLength = 8), Outcome.Pass);
        yield return Case<PasswordLengthRule>("length 0 (Windows default)", With(s => s.LocalAccounts.Data!.PasswordPolicy!.MinimumLength = 0), Outcome.Fail);
        yield return Case<PasswordLengthRule>("policy unreadable", With(s => s.LocalAccounts.Data!.PasswordPolicy = null), Outcome.Unknown);
        yield return Case<PasswordLengthRule>("accounts section failed", With(s => s.LocalAccounts = Failed<LocalAccountsInfo>()), Outcome.Unknown);

        // ---- RDP-001 ----
        yield return Case<RdpSecureRule>("RDP disabled", Compliant(), Outcome.Pass);
        yield return Case<RdpSecureRule>("RDP on with NLA", With(s => s.SecurityConfig.Data!.RdpEnabled = true), Outcome.Pass);
        yield return Case<RdpSecureRule>("RDP on without NLA", With(s => { s.SecurityConfig.Data!.RdpEnabled = true; s.SecurityConfig.Data.RdpNlaRequired = false; }), Outcome.Fail);
        yield return Case<RdpSecureRule>("Home edition", With(s => { s.System.Data!.OsEditionId = "Core"; s.SecurityConfig.Data!.RdpEnabled = true; s.SecurityConfig.Data.RdpNlaRequired = false; }), Outcome.NotApplicable);
        yield return Case<RdpSecureRule>("RDP setting unreadable", With(s => s.SecurityConfig.Data!.RdpEnabled = null), Outcome.Unknown);

        // ---- ENC-001 ----
        yield return Case<BitLockerRule>("protection on", Compliant(), Outcome.Pass);
        yield return Case<BitLockerRule>("protection off", With(s => s.SecurityConfig.Data!.SystemDriveBitLocker = "Off"), Outcome.Fail);
        yield return Case<BitLockerRule>("not elevated", With(s => { s.IsElevated = false; s.SecurityConfig.Data!.SystemDriveBitLocker = null; }), Outcome.Unknown);
        yield return Case<BitLockerRule>("Home without BitLocker interface", With(s => { s.System.Data!.OsEditionId = "Core"; s.SecurityConfig.Data!.SystemDriveBitLocker = "NotSupported"; }), Outcome.NotApplicable);
        yield return Case<BitLockerRule>("Pro without interface is not N/A", With(s => s.SecurityConfig.Data!.SystemDriveBitLocker = "NotSupported"), Outcome.Unknown);

        // ---- ACC-002 Administrators ----
        yield return Case<LocalAdministratorsRule>("disabled built-in + 1 user", Compliant(), Outcome.Pass);
        yield return Case<LocalAdministratorsRule>("four active admins", With(s =>
        {
            s.LocalAccounts.Data!.Accounts[0].Enabled = true;
            s.LocalAccounts.Data.Administrators!.Add(new GroupMember { Name = "bob", Sid = "S-1-5-21-1-2-3-1002" });
            s.LocalAccounts.Data.Administrators.Add(new GroupMember { Name = "carol", Sid = "S-1-5-21-1-2-3-1003" });
        }), Outcome.Warning);
        yield return Case<LocalAdministratorsRule>("exactly two active (boundary)", With(s =>
            s.LocalAccounts.Data!.Administrators!.Add(new GroupMember { Name = "bob", Sid = "S-1-5-21-1-2-3-1002" })), Outcome.Pass);
        yield return Case<LocalAdministratorsRule>("membership unreadable", With(s => s.LocalAccounts.Data!.Administrators = null), Outcome.Unknown);
    }

    private static object[] Case<TRule>(string name, AuditSnapshot snapshot, Outcome expected) where TRule : AuditRule, new() =>
        new object[] { $"{new TRule().Id}: {name}", new TRule(), snapshot, expected };

    [Theory]
    [MemberData(nameof(Cases))]
    public void Rule_produces_expected_outcome(string name, AuditRule rule, AuditSnapshot snapshot, Outcome expected)
    {
        var result = rule.Evaluate(snapshot);
        Assert.True(expected == result.Outcome, $"{name}: expected {expected}, got {result.Outcome} ({result.Observed})");
        Assert.False(string.IsNullOrWhiteSpace(result.Observed));
    }

    [Fact]
    public void Every_rule_has_at_least_four_cases()
    {
        var counts = Cases().GroupBy(c => ((AuditRule)c[1]).Id).ToDictionary(g => g.Key, g => g.Count());
        foreach (var rule in RuleEngine.DefaultRules)
            Assert.True(counts.GetValueOrDefault(rule.Id) >= 4, $"{rule.Id} has {counts.GetValueOrDefault(rule.Id)} cases");
        Assert.True(Cases().Count() >= 40);
    }

    [Fact]
    public void Rule_ids_are_unique_and_documented()
    {
        var rules = RuleEngine.DefaultRules;
        Assert.True(rules.Count >= 10);
        Assert.Equal(rules.Count, rules.Select(r => r.Id).Distinct().Count());
        Assert.All(rules, r =>
        {
            Assert.False(string.IsNullOrWhiteSpace(r.Expected));
            Assert.False(string.IsNullOrWhiteSpace(r.Rationale));
            Assert.False(string.IsNullOrWhiteSpace(r.Recommendation));
            Assert.False(string.IsNullOrWhiteSpace(r.EvidenceRef));
        });
        Assert.Equal(3, rules.Select(r => r.Severity).Distinct().Count());
    }

    [Fact]
    public void Missing_evidence_never_produces_pass()
    {
        var empty = new AuditSnapshot
        {
            SnapshotId = Guid.NewGuid(),
            CollectedAtUtc = CollectedAt,
            System = Failed<SystemInfo>(),
            Applications = Failed<List<InstalledApplication>>(),
            CurrentUser = Failed<CurrentUserInfo>(),
            LocalAccounts = Failed<LocalAccountsInfo>(),
            Antivirus = Failed<AntivirusInfo>(),
            Firewall = Failed<FirewallInfo>(),
            SecurityConfig = Failed<SecurityConfigInfo>()
        };
        var eval = new RuleEngine().Evaluate(empty);
        Assert.All(eval.Results, r => Assert.Equal(Outcome.Unknown, r.Outcome));
        Assert.Null(eval.Score);
        Assert.Equal(0, eval.Coverage);
        Assert.Equal("Incomplete", eval.RiskLevel);
    }

    [Fact]
    public void Partial_section_with_data_is_still_evaluated()
    {
        var s = With(x => { x.SecurityConfig.Status = EvidenceStatus.Partial; x.SecurityConfig.Error = "BitLocker: requires administrator"; });
        Assert.Equal(Outcome.Pass, new UacEnabledRule().Evaluate(s).Outcome);
    }

    [Fact]
    public void Section_with_data_but_failed_status_is_not_trusted()
    {
        var s = With(x => x.Firewall.Status = EvidenceStatus.Failed);
        Assert.Equal(Outcome.Unknown, new FirewallEnabledRule().Evaluate(s).Outcome);
    }
}
