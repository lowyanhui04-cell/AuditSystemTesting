using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;
using EndpointLens.Server.Services;
using static EndpointLens.Tests.TestSnapshots;

namespace EndpointLens.Tests;

public class ScoringTests
{
    [Fact]
    public void Compliant_endpoint_scores_100_with_full_coverage()
    {
        var eval = new RuleEngine().Evaluate(Compliant());
        Assert.Equal(100, eval.Score);
        Assert.Equal(1, eval.Coverage);
        Assert.Equal("Minimal", eval.RiskLevel);
    }

    [Fact]
    public void High_severity_failure_sets_high_risk_and_lowers_score()
    {
        var eval = new RuleEngine().Evaluate(With(s => s.Firewall.Data!.Profiles[0].Enabled = false));
        Assert.Equal("High", eval.RiskLevel);
        Assert.True(eval.Score < 100);
        Assert.Equal(Outcome.Fail, eval.Results[0].Outcome); // failures are sorted first
    }

    [Fact]
    public void Unknown_lowers_coverage_but_does_not_raise_score()
    {
        var baseline = new RuleEngine().Evaluate(With(s => s.SecurityConfig.Data!.Smb1ServerEnabled = true));
        var withUnknown = new RuleEngine().Evaluate(With(s =>
        {
            s.SecurityConfig.Data!.Smb1ServerEnabled = true;
            s.SecurityConfig.Data.SystemDriveBitLocker = null;
        }));
        Assert.True(withUnknown.Coverage < baseline.Coverage);
        Assert.True(withUnknown.Score <= baseline.Score);
    }

    [Fact]
    public void Warning_earns_half_credit()
    {
        var results = new List<RuleResult>
        {
            new("A", "1", "", "", Severity.Low, Outcome.Warning, "", "", "", ""),
            new("B", "1", "", "", Severity.Low, Outcome.Pass, "", "", "", "")
        };
        Assert.Equal(75, Scoring.Compute(results).Score);
        Assert.Equal("Low", Scoring.RiskLevel(results));
    }

    [Fact]
    public void Not_applicable_rules_are_excluded_from_coverage()
    {
        var eval = new RuleEngine().Evaluate(With(s => s.System.Data!.OsEditionId = "Core"));
        Assert.Contains(eval.Results, r => r.RuleId == "RDP-001" && r.Outcome == Outcome.NotApplicable);
        Assert.Equal(1, eval.Coverage);
    }

    [Fact]
    public void Rule_exception_becomes_unknown_not_pass()
    {
        var eval = new RuleEngine(new AuditRule[] { new ThrowingRule() }).Evaluate(Compliant());
        Assert.Equal(Outcome.Unknown, eval.Results.Single().Outcome);
    }

    private sealed class ThrowingRule : AuditRule
    {
        public override string Id => "T-1";
        public override string Version => "1";
        public override string Title => "throws";
        public override string Category => "test";
        public override Severity Severity => Severity.High;
        public override string Expected => "-";
        public override string Rationale => "-";
        public override string Recommendation => "-";
        public override string EvidenceRef => "-";
        protected override RuleVerdict Check(AuditSnapshot s) => throw new InvalidOperationException("boom");
    }
}

public class ValidationTests
{
    private static readonly DateTimeOffset Now = CollectedAt.AddMinutes(5);

    [Fact]
    public void Valid_snapshot_has_no_errors() => Assert.Empty(SnapshotValidator.Validate(Compliant(), Now));

    [Fact]
    public void Null_payload_is_rejected() => Assert.NotEmpty(SnapshotValidator.Validate(null, Now));

    [Fact]
    public void Missing_snapshot_id_is_rejected() =>
        Assert.Contains(SnapshotValidator.Validate(With(s => s.SnapshotId = Guid.Empty), Now), e => e.Contains("snapshotId"));

    [Fact]
    public void Future_timestamp_is_rejected() =>
        Assert.Contains(SnapshotValidator.Validate(With(s => s.CollectedAtUtc = Now.AddHours(2)), Now), e => e.Contains("future"));

    [Fact]
    public void Wrong_schema_version_is_rejected() =>
        Assert.NotEmpty(SnapshotValidator.Validate(With(s => s.SchemaVersion = "9.9"), Now));

    [Fact]
    public void Missing_section_is_rejected() =>
        Assert.NotEmpty(SnapshotValidator.Validate(With(s => s.Firewall = null!), Now));

    [Fact]
    public void Oversized_string_is_rejected() =>
        Assert.NotEmpty(SnapshotValidator.Validate(With(s => s.Applications.Data![0].Name = new string('x', 5000)), Now));

    [Fact]
    public void Json_round_trip_preserves_evidence()
    {
        var s = Compliant();
        var back = SnapshotJson.Deserialize(SnapshotJson.Serialize(s))!;
        Assert.Equal(s.SnapshotId, back.SnapshotId);
        Assert.Equal(EvidenceStatus.Collected, back.Firewall.Status);
        Assert.Equal(3, back.Firewall.Data!.Profiles.Count);
        Assert.Equal(s.LocalAccounts.Data!.PasswordPolicy!.MinimumLength, back.LocalAccounts.Data!.PasswordPolicy!.MinimumLength);
    }

    [Theory]
    [InlineData("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0")]
    [InlineData("+1", "'+1")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("plain", "plain")]
    public void Csv_cells_are_quoted_and_formula_safe(string input, string expected) =>
        Assert.Equal(expected, Exports.Cell(input));
}
