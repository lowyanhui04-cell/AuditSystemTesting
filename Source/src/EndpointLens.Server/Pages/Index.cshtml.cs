using EndpointLens.Core.Rules;
using EndpointLens.Server.Data;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages;

public sealed record AuditSummary(int Id, DateTimeOffset CollectedAtUtc, string? Hostname, string? OsCaption, string? OsBuild,
    string? InteractiveUser, string RuleSetVersion, double? Score, double Coverage, string RiskLevel,
    int FailCount, int WarningCount, int UnknownCount, int HighFailCount, bool AgentElevated, string Source);

public sealed record EndpointRow(int Id, string Name, bool Revoked, DateTimeOffset CreatedAtUtc, int AuditCount, AuditSummary? Latest);

public sealed record CommonIssue(string RuleId, string Title, Severity Severity, int Endpoints);

public sealed class IndexModel(AppDbContext db, TimeProvider clock) : PageModel
{
    public const int StaleAfterDays = 30;

    public List<EndpointRow> Endpoints { get; private set; } = new();
    public List<CommonIssue> CommonIssues { get; private set; } = new();
    public DateTimeOffset Now { get; private set; }

    public List<AuditSummary> Latest => Endpoints.Where(e => e.Latest is not null).Select(e => e.Latest!).ToList();
    public double? AverageScore
    {
        get
        {
            var scores = Latest.Where(a => a.Score is not null).Select(a => a.Score!.Value).ToList();
            return scores.Count == 0 ? null : Math.Round(scores.Average(), 1);
        }
    }

    public async Task OnGetAsync()
    {
        Now = clock.GetUtcNow();
        Endpoints = await db.Endpoints.AsNoTracking()
            .OrderBy(e => e.Name)
            .Select(e => new EndpointRow(e.Id, e.Name, e.Revoked, e.CreatedAtUtc, e.Audits.Count,
                e.Audits.OrderByDescending(a => a.CollectedAtUtc)
                    .Select(a => new AuditSummary(a.Id, a.CollectedAtUtc, a.Hostname, a.OsCaption, a.OsBuild, a.InteractiveUser,
                        a.RuleSetVersion, a.Score, a.Coverage, a.RiskLevel, a.FailCount, a.WarningCount, a.UnknownCount,
                        a.HighFailCount, a.AgentElevated, a.Source))
                    .FirstOrDefault()))
            .ToListAsync();

        // Endpoints sorted so the ones needing attention come first.
        Endpoints = Endpoints
            .OrderBy(e => e.Latest is null ? 1 : 0)
            .ThenByDescending(e => e.Latest?.HighFailCount ?? 0)
            .ThenBy(e => e.Latest?.Score ?? 101)
            .ThenBy(e => e.Name)
            .ToList();

        var latestIds = Latest.Select(a => a.Id).ToList();
        var fails = await db.Findings.AsNoTracking()
            .Where(f => latestIds.Contains(f.AuditId) && f.Outcome == Outcome.Fail)
            .Select(f => new { f.RuleId, f.Title, f.Severity })
            .ToListAsync();
        CommonIssues = fails
            .GroupBy(f => f.RuleId)
            .Select(g => new CommonIssue(g.Key, g.First().Title, g.First().Severity, g.Count()))
            .OrderByDescending(i => i.Endpoints).ThenByDescending(i => i.Severity)
            .Take(6)
            .ToList();
    }
}
