using Microsoft.AspNetCore.Authorization;
using EndpointLens.Server.Data;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages.Endpoints;

[Authorize(Roles = "SuperAdmin")]
public sealed class DeleteModel(AppDbContext db, LocalDashboard mode) : PageModel
{
    public Data.Endpoint Computer { get; private set; } = null!;

    public async Task<IActionResult> OnGetAsync(int id, CancellationToken ct)
    {
        if (mode.Enabled) return NotFound();
        var computer = await db.Endpoints.AsNoTracking().SingleOrDefaultAsync(e => e.Id == id, ct);
        if (computer is null) return NotFound();
        Computer = computer;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(int id, CancellationToken ct)
    {
        if (mode.Enabled) return NotFound();
        var deleted = await db.Endpoints.Where(e => e.Id == id).ExecuteDeleteAsync(ct);
        if (deleted == 0) return NotFound();
        TempData["Message"] = "Endpoint and its audit history deleted.";
        return RedirectToPage("/Index");
    }
}
