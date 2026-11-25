using EndpointLens.Core.Snapshot;

namespace EndpointLens.Core.Rules;

public enum Severity { Low = 1, Medium = 2, High = 3 }

public enum Outcome
{
    /// <summary>Evidence meets the expected value.</summary>
    Pass,
    /// <summary>Evidence shows a non-compliant configuration.</summary>
    Fail,
    /// <summary>Policy-dependent: may be acceptable, needs human review.</summary>
    Warning,
    /// <summary>Evidence is missing or could not be collected. Never treated as a pass.</summary>
    Unknown,
    /// <summary>The rule does not apply to this endpoint (justified in the evidence text).</summary>
    NotApplicable
}

public sealed record RuleVerdict(Outcome Outcome, string Observed);

public sealed record RuleResult(
    string RuleId,
    string RuleVersion,
    string Title,
    string Category,
    Severity Severity,
    Outcome Outcome,
    string Expected,
    string Observed,
    string EvidenceRef,
    string Recommendation);

/// <summary>
/// A deterministic baseline check. Each rule documents what it expects, why, which evidence it reads,
/// and what to do when it fails. Rules must return Unknown whenever their evidence is unavailable.
/// </summary>
public abstract class AuditRule
{
    public abstract string Id { get; }
    public abstract string Version { get; }
    public abstract string Title { get; }
    public abstract string Category { get; }
    public abstract Severity Severity { get; }
    public abstract string Expected { get; }
    public abstract string Rationale { get; }
    public abstract string Recommendation { get; }
    public abstract string EvidenceRef { get; }
    public virtual string Applicability => "All Windows 10/11 endpoints.";

    protected abstract RuleVerdict Check(AuditSnapshot s);

    public RuleResult Evaluate(AuditSnapshot s)
    {
        RuleVerdict verdict;
        try
        {
            verdict = Check(s);
        }
        catch (Exception ex)
        {
            // A rule bug must surface as missing coverage, not a silent pass.
            verdict = new RuleVerdict(Outcome.Unknown, $"Rule evaluation error: {ex.Message}");
        }
        return new RuleResult(Id, Version, Title, Category, Severity, verdict.Outcome, Expected, verdict.Observed, EvidenceRef, Recommendation);
    }

    protected static RuleVerdict Pass(string observed) => new(Outcome.Pass, observed);
    protected static RuleVerdict Fail(string observed) => new(Outcome.Fail, observed);
    protected static RuleVerdict Warn(string observed) => new(Outcome.Warning, observed);
    protected static RuleVerdict Unknown(string observed) => new(Outcome.Unknown, observed);
    protected static RuleVerdict NotApplicable(string observed) => new(Outcome.NotApplicable, observed);

    protected static RuleVerdict MissingSection<T>(string name, EvidenceSection<T> section) where T : class =>
        Unknown($"{name} evidence unavailable ({section.Status}{(section.Error is null ? "" : ": " + section.Error)}).");

    protected static bool IsHomeEdition(AuditSnapshot s)
    {
        var sys = s.System.Data;
        if (sys is null) return false;
        return (sys.OsEditionId?.StartsWith("Core", StringComparison.OrdinalIgnoreCase) ?? false)
            || (sys.OsCaption?.Contains("Home", StringComparison.OrdinalIgnoreCase) ?? false);
    }
}
