using EndpointLens.Core.Rules;
using EndpointLens.Server.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages;

public sealed record FindingRow(int AuditId, int EndpointId, string EndpointName, DateTimeOffset CollectedAtUtc, Finding Finding);

/// <summary>Findings from the latest audit of every endpoint, for cross-endpoint comparison and prioritisation.</summary>
public sealed class FindingsModel(AppDbContext db) : PageModel
{
    public static readonly (string Key, string Label, Outcome? Outcome)[] Views =
    {
        ("fail", "Fail", Core.Rules.Outcome.Fail),
        ("warning", "Warning", Core.Rules.Outcome.Warning),
        ("unknown", "Unknown", Core.Rules.Outcome.Unknown),
        ("all", "All results", null),
    };

    /// <summary>Which outcome to show; defaults to failures.</summary>
    [BindProperty(SupportsGet = true)] public string Show { get; set; } = "fail";
    [BindProperty(SupportsGet = true)] public Severity? Severity { get; set; }
    [BindProperty(SupportsGet = true)] public string? RuleId { get; set; }

    public List<FindingRow> Rows { get; private set; } = new();
    public Dictionary<string, int> Counts { get; private set; } = new();
    public IReadOnlyList<AuditRule> Rules => RuleEngine.DefaultRules;

    public async Task OnGetAsync()
    {
        var latestIds = await db.Endpoints.AsNoTracking()
            .Select(e => e.Audits.OrderByDescending(a => a.CollectedAtUtc).Select(a => (int?)a.Id).FirstOrDefault())
            .Where(id => id != null)
            .ToListAsync();

        var query = db.Findings.AsNoTracking().Include(f => f.Audit).ThenInclude(a => a!.Endpoint)
            .Where(f => latestIds.Contains(f.AuditId));
        if (Severity is { } s) query = query.Where(f => f.Severity == s);
        if (!string.IsNullOrEmpty(RuleId)) query = query.Where(f => f.RuleId == RuleId);
        var findings = await query.ToListAsync();

        Counts = Views.ToDictionary(v => v.Key, v => v.Outcome is null ? findings.Count : findings.Count(f => f.Outcome == v.Outcome));
        var outcome = Views.FirstOrDefault(v => v.Key == Show).Outcome;
        if (Views.All(v => v.Key != Show)) { Show = "fail"; outcome = Core.Rules.Outcome.Fail; }

        Rows = findings
            .Where(f => outcome is null || f.Outcome == outcome)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.RuleId)
            .ThenBy(f => f.Audit!.Endpoint!.Name)
            .Select(f => new FindingRow(f.AuditId, f.Audit!.EndpointId, f.Audit.Endpoint!.Name, f.Audit.CollectedAtUtc, f))
            .ToList();
    }
}
