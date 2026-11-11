using EndpointLens.Server.Data;
using EndpointLens.Server.Pages.Audits;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages.Endpoints;

public sealed class DetailsModel(AppDbContext db, TimeProvider clock) : PageModel
{
    public Data.Endpoint Endpoint { get; private set; } = null!;
    public List<AuditSummary> History { get; private set; } = new();
    public LoadedAudit? Latest { get; private set; }
    public string? IssuedToken { get; private set; }
    public DateTimeOffset Now { get; private set; }

    [BindProperty(SupportsGet = true)] public string Tab { get; set; } = "findings";

    public async Task<IActionResult> OnGetAsync(int id)
    {
        if (!await LoadAsync(id)) return NotFound();
        return Page();
    }

    public async Task<IActionResult> OnPostRotateAsync(int id)
    {
        var endpoint = await db.Endpoints.FindAsync(id);
        if (endpoint is null) return NotFound();
        var (token, hash) = EndpointCredentials.Generate(endpoint.Id);
        endpoint.TokenHash = hash;
        endpoint.Revoked = false;
        await db.SaveChangesAsync();
        Tab = "settings";
        await LoadAsync(id);
        IssuedToken = token;
        return Page();
    }

    public async Task<IActionResult> OnPostRevokeAsync(int id)
    {
        var endpoint = await db.Endpoints.FindAsync(id);
        if (endpoint is null) return NotFound();
        endpoint.Revoked = true;
        await db.SaveChangesAsync();
        TempData["Message"] = $"The credential for {endpoint.Name} was revoked. Its audits are kept.";
        return RedirectToPage(new { id, tab = "settings" });
    }

    private async Task<bool> LoadAsync(int id)
    {
        Now = clock.GetUtcNow();
        var endpoint = await db.Endpoints.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id);
        if (endpoint is null) return false;
        Endpoint = endpoint;

        History = await db.Audits.AsNoTracking()
            .Where(a => a.EndpointId == id)
            .OrderByDescending(a => a.CollectedAtUtc)
            .Select(a => new AuditSummary(a.Id, a.CollectedAtUtc, a.Hostname, a.OsCaption, a.OsBuild, a.InteractiveUser,
                a.RuleSetVersion, a.Score, a.Coverage, a.RiskLevel, a.FailCount, a.WarningCount, a.UnknownCount,
                a.HighFailCount, a.AgentElevated, a.Source))
            .ToListAsync();

        if (History.Count > 0) Latest = await AuditLoader.LoadAsync(db, History[0].Id);
        return true;
    }
}
