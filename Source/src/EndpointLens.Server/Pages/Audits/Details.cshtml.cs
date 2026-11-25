using EndpointLens.Core.Rules;
using EndpointLens.Server.Data;
using EndpointLens.Server.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace EndpointLens.Server.Pages.Audits;

public sealed class DetailsModel(AppDbContext db, LocalDashboard mode) : PageModel
{
    public string? UploadStatus { get; private set; }
    public LoadedAudit Data { get; private set; } = null!;
    public List<Finding> Shown { get; private set; } = new();

    [BindProperty(SupportsGet = true)] public string Tab { get; set; } = "findings";
    [BindProperty(SupportsGet = true)] public Outcome? Outcome { get; set; }

    public async Task<IActionResult> OnGetAsync(int id)
    {
        var loaded = await AuditLoader.LoadAsync(db, id);
        if (loaded is null) return NotFound();
        Data = loaded;
        Shown = loaded.Findings.Where(f => Outcome is null || f.Outcome == Outcome).ToList();
        if (mode.Enabled && loaded.Audit.Source == "local")
        {
            var upload = await db.AuditUploads.AsNoTracking().SingleOrDefaultAsync(row => row.AuditId == id);
            UploadStatus = upload switch
            {
                { Uploaded: true } => "Uploaded to central dashboard",
                { Attempted: true } => "Pending upload. EndpointLens will retry automatically.",
                not null => "Pending upload. Saved on this computer.",
                _ => "Saved on this computer."
            };
            if (upload is { Uploaded: false, Attempted: false })
                Response.Headers["Refresh"] = "5";
        }

        return Page();
    }
}
