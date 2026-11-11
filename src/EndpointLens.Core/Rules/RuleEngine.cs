using EndpointLens.Core.Snapshot;

namespace EndpointLens.Core.Rules;

public sealed record AuditEvaluation(
    string RuleSetVersion,
    IReadOnlyList<RuleResult> Results,
    double? Score,
    double Coverage,
    string RiskLevel)
{
    public int Count(Outcome o) => Results.Count(r => r.Outcome == o);
    public int Count(Outcome o, Severity s) => Results.Count(r => r.Outcome == o && r.Severity == s);
}

public sealed class RuleEngine
{
    /// <summary>Bump whenever a rule is added, removed, or its logic/thresholds change.</summary>
    public const string RuleSetVersion = "2026.1";

    public static IReadOnlyList<AuditRule> DefaultRules { get; } = new AuditRule[]
    {
        new FirewallEnabledRule(),
        new AntivirusEnabledRule(),
        new AntivirusSignaturesRule(),
        new UacEnabledRule(),
        new Smb1DisabledRule(),
        new OsUpdateRecencyRule(),
        new GuestAccountDisabledRule(),
        new PasswordLengthRule(),
        new RdpSecureRule(),
        new BitLockerRule(),
        new LocalAdministratorsRule(),
    };

    public IReadOnlyList<AuditRule> Rules { get; }

    public RuleEngine() : this(DefaultRules) { }
    public RuleEngine(IReadOnlyList<AuditRule> rules) => Rules = rules;

    public AuditEvaluation Evaluate(AuditSnapshot snapshot)
    {
        var results = Rules.Select(r => r.Evaluate(snapshot))
            .OrderByDescending(r => Rank(r.Outcome))
            .ThenByDescending(r => r.Severity)
            .ToList();
        var (score, coverage) = Scoring.Compute(results);
        return new AuditEvaluation(RuleSetVersion, results, score, coverage, Scoring.RiskLevel(results));
    }

    private static int Rank(Outcome o) => o switch
    {
        Outcome.Fail => 4,
        Outcome.Warning => 3,
        Outcome.Unknown => 2,
        Outcome.Pass => 1,
        _ => 0
    };
}

public static class Scoring
{
    public static int Weight(Severity s) => s switch
    {
        Severity.High => 10,
        Severity.Medium => 5,
        _ => 2
    };

    /// <summary>
    /// Score = weighted share of evaluated rules that passed (warnings earn half credit).
    /// UNKNOWN results are excluded from the score but reduce coverage, so missing evidence
    /// can never raise the score. Coverage = evaluated / applicable rules.
    /// </summary>
    public static (double? Score, double Coverage) Compute(IReadOnlyCollection<RuleResult> results)
    {
        var applicable = results.Where(r => r.Outcome != Outcome.NotApplicable).ToList();
        var evaluated = applicable.Where(r => r.Outcome is Outcome.Pass or Outcome.Fail or Outcome.Warning).ToList();

        double coverage = applicable.Count == 0 ? 0 : (double)evaluated.Count / applicable.Count;
        if (evaluated.Count == 0) return (null, coverage);

        double total = evaluated.Sum(r => Weight(r.Severity));
        double earned = evaluated.Sum(r => r.Outcome switch
        {
            Outcome.Pass => Weight(r.Severity),
            Outcome.Warning => Weight(r.Severity) / 2.0,
            _ => 0
        });
        return (Math.Round(100 * earned / total, 1), Math.Round(coverage, 3));
    }

    public static string RiskLevel(IReadOnlyCollection<RuleResult> results)
    {
        if (results.Any(r => r.Outcome == Outcome.Fail && r.Severity == Severity.High)) return "High";
        if (results.Any(r => r.Outcome == Outcome.Fail && r.Severity == Severity.Medium)) return "Medium";
        if (results.Any(r => r.Outcome is Outcome.Fail or Outcome.Warning)) return "Low";
        if (results.Any(r => r.Outcome == Outcome.Unknown)) return "Incomplete";
        return "Minimal";
    }
}
