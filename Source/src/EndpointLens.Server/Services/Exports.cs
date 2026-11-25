using System.Text;
using System.Text.Json;
using EndpointLens.Core.Snapshot;
using EndpointLens.Server.Data;

namespace EndpointLens.Server.Services;

public static class Exports
{
    public static string FindingsCsv(Audit audit)
    {
        var sb = new StringBuilder();
        sb.AppendLine("endpoint,hostname,collected_at_utc,rule_set_version,score,coverage,rule_id,rule_version,title,category,severity,outcome,expected,observed,recommendation");
        foreach (var f in audit.Findings.OrderBy(f => f.RuleId))
        {
            sb.AppendJoin(',', new[]
            {
                audit.Endpoint?.Name, audit.Hostname, audit.CollectedAtUtc.ToString("u"), audit.RuleSetVersion,
                audit.Score?.ToString("0.0"), audit.Coverage.ToString("0.000"), f.RuleId, f.RuleVersion, f.Title, f.Category,
                f.Severity.ToString().ToUpperInvariant(), f.Outcome.ToString().ToUpperInvariant(), f.Expected, f.Observed, f.Recommendation
            }.Select(Cell));
            sb.AppendLine();
        }
        return sb.ToString();
    }

    public static string AuditJson(Audit audit)
    {
        var payload = new
        {
            endpoint = audit.Endpoint?.Name,
            audit.Id,
            audit.SnapshotId,
            audit.CollectedAtUtc,
            audit.ReceivedAtUtc,
            audit.RuleSetVersion,
            audit.Score,
            audit.Coverage,
            audit.RiskLevel,
            findings = audit.Findings.OrderBy(f => f.RuleId).Select(f => new
            {
                f.RuleId, f.RuleVersion, f.Title, f.Category, f.Severity, f.Outcome, f.Expected, f.Observed, f.EvidenceRef, f.Recommendation
            }),
            snapshot = JsonSerializer.Deserialize<JsonElement>(audit.SnapshotJson)
        };
        return JsonSerializer.Serialize(payload, SnapshotJson.Options);
    }

    /// <summary>RFC 4180 quoting plus a guard against spreadsheet formula injection from endpoint-supplied text.</summary>
    public static string Cell(string? value)
    {
        var v = value ?? "";
        if (v.Length > 0 && "=+-@\t\r".Contains(v[0])) v = "'" + v;
        return v.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
    }
}
