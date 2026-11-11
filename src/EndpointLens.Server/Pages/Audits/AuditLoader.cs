using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;
using EndpointLens.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages.Audits;

public sealed record LoadedAudit(Audit Audit, AuditSnapshot? Snapshot, List<Finding> Findings);

internal static class AuditLoader
{
    public static async Task<LoadedAudit?> LoadAsync(AppDbContext db, int id)
    {
        var audit = await db.Audits.AsNoTracking().Include(a => a.Endpoint).Include(a => a.Findings).FirstOrDefaultAsync(a => a.Id == id);
        if (audit is null) return null;
        var ordered = audit.Findings
            .OrderBy(f => f.Outcome switch { Outcome.Fail => 0, Outcome.Warning => 1, Outcome.Unknown => 2, Outcome.Pass => 3, _ => 4 })
            .ThenByDescending(f => f.Severity)
            .ThenBy(f => f.RuleId)
            .ToList();
        return new LoadedAudit(audit, SnapshotJson.Deserialize(audit.SnapshotJson), ordered);
    }
}
