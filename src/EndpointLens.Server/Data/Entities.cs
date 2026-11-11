using EndpointLens.Core.Rules;

namespace EndpointLens.Server.Data;

public sealed class AdminUser
{
    public int Id { get; set; }
    public string UserName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public int FailedLogins { get; set; }
    public DateTimeOffset? LockedUntilUtc { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
}

/// <summary>An enrolled Windows endpoint. Only a SHA-256 hash of its submission credential is stored.</summary>
public sealed class Endpoint
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string? Notes { get; set; }
    public string TokenHash { get; set; } = "";
    public bool Revoked { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset? LastSubmissionUtc { get; set; }
    public List<Audit> Audits { get; set; } = new();
}

public sealed class Audit
{
    public int Id { get; set; }
    public Guid SnapshotId { get; set; }
    public int EndpointId { get; set; }
    public Endpoint? Endpoint { get; set; }

    public DateTimeOffset CollectedAtUtc { get; set; }
    public DateTimeOffset ReceivedAtUtc { get; set; }
    public string Source { get; set; } = "";          // "agent" or "import"
    public string AgentVersion { get; set; } = "";
    public bool AgentElevated { get; set; }

    public string? Hostname { get; set; }
    public string? OsCaption { get; set; }
    public string? OsBuild { get; set; }
    public string? InteractiveUser { get; set; }

    public string RuleSetVersion { get; set; } = "";
    public double? Score { get; set; }
    public double Coverage { get; set; }
    public string RiskLevel { get; set; } = "";
    public int FailCount { get; set; }
    public int WarningCount { get; set; }
    public int UnknownCount { get; set; }
    public int HighFailCount { get; set; }

    /// <summary>The full submitted snapshot, kept verbatim as audit evidence.</summary>
    public string SnapshotJson { get; set; } = "";
    public List<Finding> Findings { get; set; } = new();
}

/// <summary>
/// One rule result. Rule text is copied at evaluation time so historical audits keep the
/// wording and version that produced them even after the rule set changes.
/// </summary>
public sealed class Finding
{
    public int Id { get; set; }
    public int AuditId { get; set; }
    public Audit? Audit { get; set; }

    public string RuleId { get; set; } = "";
    public string RuleVersion { get; set; } = "";
    public string Title { get; set; } = "";
    public string Category { get; set; } = "";
    public Severity Severity { get; set; }
    public Outcome Outcome { get; set; }
    public string Expected { get; set; } = "";
    public string Observed { get; set; } = "";
    public string EvidenceRef { get; set; } = "";
    public string Recommendation { get; set; } = "";
}
