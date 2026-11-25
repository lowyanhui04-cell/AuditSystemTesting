using EndpointLens.Server.Data;
using EndpointLens.Server.Pages.Audits;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages.Endpoints;

public sealed class DetailsModel(AppDbContext db, TimeProvider clock, AgentPackage agent) : PageModel
{
    public bool AgentAvailable => agent.IsAvailable;
    public string AgentServerUrl => agent.ServerUrl(Request);
    public bool AgentUrlIsLoopback => AgentPackage.IsLoopback(AgentServerUrl);

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

    /// <summary>
    /// Downloads the agent already connected to this endpoint. A fresh credential is issued for every
    /// download, so an older copy of the zip stops working.
    /// </summary>
    public async Task<IActionResult> OnPostDownloadAgentAsync(int id, CancellationToken ct)
    {
        var endpoint = await db.Endpoints.FindAsync(new object[] { id }, ct);
        if (endpoint is null) return NotFound();
        if (!agent.IsAvailable)
        {
            TempData["Message"] = "The agent file is not on the server yet. See the Download agent tab for how to add it.";
            return RedirectToPage(new { id, tab = "agent" });
        }

        var (token, hash) = EndpointCredentials.Generate(endpoint.Id);
        var zip = await agent.BuildAsync(endpoint.Name, agent.ServerUrl(Request), token, ct);
        endpoint.TokenHash = hash;
        endpoint.Revoked = false;
        await db.SaveChangesAsync(ct);

        var safeName = string.Concat(endpoint.Name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_'));
        return File(zip, "application/zip", $"EndpointLens-Agent-{safeName}.zip");
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
