using EndpointLens.Core.Rules;
using EndpointLens.Server.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace EndpointLens.Server.Pages.Audits;

public sealed class DetailsModel(AppDbContext db) : PageModel
{
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
        return Page();
    }
}
