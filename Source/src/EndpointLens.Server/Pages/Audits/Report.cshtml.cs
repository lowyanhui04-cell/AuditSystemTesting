using EndpointLens.Server.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Net.Http.Headers;

namespace EndpointLens.Server.Pages.Audits;

/// <summary>
/// Self-contained HTML audit report. All endpoint-supplied strings are HTML-encoded by Razor.
/// </summary>
public sealed class ReportModel(AppDbContext db, TimeProvider clock) : PageModel
{
    public LoadedAudit Data { get; private set; } = null!;
    public DateTimeOffset GeneratedAtUtc { get; private set; }

    public async Task<IActionResult> OnGetAsync(int id, bool download = false)
    {
        var loaded = await AuditLoader.LoadAsync(db, id);
        if (loaded is null) return NotFound();
        Data = loaded;
        GeneratedAtUtc = clock.GetUtcNow();

        if (download)
        {
            var name = $"EndpointLens_Report_{loaded.Audit.Endpoint?.Name}_{loaded.Audit.CollectedAtUtc:yyyyMMdd_HHmmss}.html";
            Response.Headers[HeaderNames.ContentDisposition] = new ContentDispositionHeaderValue("attachment") { FileNameStar = name }.ToString();
        }
        Response.Headers[HeaderNames.CacheControl] = "no-store";
        return Page();
    }
}
