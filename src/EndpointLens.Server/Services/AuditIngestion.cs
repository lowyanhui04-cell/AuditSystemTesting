using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;
using EndpointLens.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Services;

public enum IngestStatus { Created, Duplicate, Conflict, Invalid }

public sealed record IngestResult(IngestStatus Status, int? AuditId = null, IReadOnlyList<string>? Errors = null, AuditEvaluation? Evaluation = null);

/// <summary>
/// Validates a snapshot, evaluates it with the current rule set and stores audit + findings.
/// Shared by the HTTPS API and the dashboard's manual JSON import.
/// </summary>
public sealed class AuditIngestion(AppDbContext db, RuleEngine engine, TimeProvider clock, ILogger<AuditIngestion> log)
{
    public async Task<IngestResult> IngestAsync(Data.Endpoint endpoint, AuditSnapshot? snapshot, string source, CancellationToken ct = default)
    {
        var now = clock.GetUtcNow();
        var errors = SnapshotValidator.Validate(snapshot, now);
        if (errors.Count > 0) return new IngestResult(IngestStatus.Invalid, Errors: errors);

        var existing = await db.Audits.AsNoTracking()
            .Where(a => a.SnapshotId == snapshot!.SnapshotId)
            .Select(a => new { a.Id, a.EndpointId })
            .FirstOrDefaultAsync(ct);
        if (existing is not null)
            return existing.EndpointId == endpoint.Id
                ? new IngestResult(IngestStatus.Duplicate, existing.Id)
                : new IngestResult(IngestStatus.Conflict, Errors: new[] { "snapshotId already belongs to another endpoint." });

        var eval = engine.Evaluate(snapshot!);
        var audit = new Audit
        {
            SnapshotId = snapshot!.SnapshotId,
            EndpointId = endpoint.Id,
            CollectedAtUtc = snapshot.CollectedAtUtc.ToUniversalTime(),
            ReceivedAtUtc = now,
            Source = source,
            AgentVersion = snapshot.AgentVersion,
            AgentElevated = snapshot.IsElevated,
            Hostname = snapshot.System.Data?.Hostname,
            OsCaption = snapshot.System.Data?.OsCaption,
            OsBuild = snapshot.System.Data?.OsBuild,
            InteractiveUser = snapshot.CurrentUser.Data?.InteractiveUser,
            RuleSetVersion = eval.RuleSetVersion,
            Score = eval.Score,
            Coverage = eval.Coverage,
            RiskLevel = eval.RiskLevel,
            FailCount = eval.Count(Outcome.Fail),
            WarningCount = eval.Count(Outcome.Warning),
            UnknownCount = eval.Count(Outcome.Unknown),
            HighFailCount = eval.Count(Outcome.Fail, Severity.High),
            SnapshotJson = SnapshotJson.Serialize(snapshot),
            Findings = eval.Results.Select(r => new Finding
            {
                RuleId = r.RuleId,
                RuleVersion = r.RuleVersion,
                Title = r.Title,
                Category = r.Category,
                Severity = r.Severity,
                Outcome = r.Outcome,
                Expected = r.Expected,
                Observed = r.Observed,
                EvidenceRef = r.EvidenceRef,
                Recommendation = r.Recommendation
            }).ToList()
        };

        db.Audits.Add(audit);
        var tracked = await db.Endpoints.FindAsync(new object[] { endpoint.Id }, ct);
        if (tracked is not null) tracked.LastSubmissionUtc = now;

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // A concurrent retry of the same snapshot won the race on the unique index.
            db.ChangeTracker.Clear();
            var winner = await db.Audits.AsNoTracking().FirstOrDefaultAsync(a => a.SnapshotId == snapshot.SnapshotId, ct);
            if (winner?.EndpointId == endpoint.Id) return new IngestResult(IngestStatus.Duplicate, winner.Id);
            throw;
        }

        log.LogInformation("Stored audit {AuditId} for endpoint {EndpointId} (snapshot {SnapshotId}, source {Source}, score {Score})",
            audit.Id, endpoint.Id, audit.SnapshotId, source, audit.Score);
        return new IngestResult(IngestStatus.Created, audit.Id, Evaluation: eval);
    }
}
