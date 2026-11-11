using System.Text.Json;
using EndpointLens.Core.Snapshot;
using EndpointLens.Server.Data;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages;

/// <summary>Manual import of a JSON snapshot exported by the agent when HTTPS submission was unavailable.</summary>
[RequestSizeLimit(MaxFileBytes + 64 * 1024)]
public sealed class ImportModel(AppDbContext db, AuditIngestion ingestion) : PageModel
{
    private const long MaxFileBytes = 5 * 1024 * 1024;

    [BindProperty] public int EndpointId { get; set; }
    [BindProperty] public IFormFile? Upload { get; set; }
    public List<SelectListItem> Endpoints { get; private set; } = new();
    public List<string> Errors { get; private set; } = new();

    public async Task OnGetAsync() => await LoadEndpointsAsync();

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        await LoadEndpointsAsync();
        var endpoint = await db.Endpoints.AsNoTracking().FirstOrDefaultAsync(e => e.Id == EndpointId, ct);
        if (endpoint is null) Errors.Add("Select an endpoint.");
        if (Upload is null || Upload.Length == 0) Errors.Add("Choose a JSON snapshot file.");
        else if (Upload.Length > MaxFileBytes) Errors.Add("File is larger than 5 MB.");
        if (Errors.Count > 0) return Page();

        AuditSnapshot? snapshot;
        try
        {
            await using var stream = Upload!.OpenReadStream();
            snapshot = await SnapshotJson.DeserializeAsync(stream, ct);
        }
        catch (JsonException ex)
        {
            Errors.Add("The file is not a valid EndpointLens snapshot: " + ex.Message);
            return Page();
        }

        var result = await ingestion.IngestAsync(endpoint!, snapshot, "import", ct);
        switch (result.Status)
        {
            case IngestStatus.Created:
                TempData["Message"] = "Snapshot imported and evaluated.";
                return RedirectToPage("/Audits/Details", new { id = result.AuditId });
            case IngestStatus.Duplicate:
                TempData["Message"] = "This snapshot was already received; showing the existing audit.";
                return RedirectToPage("/Audits/Details", new { id = result.AuditId });
            default:
                Errors.AddRange(result.Errors ?? Array.Empty<string>());
                return Page();
        }
    }

    private async Task LoadEndpointsAsync() =>
        Endpoints = await db.Endpoints.AsNoTracking().OrderBy(e => e.Name)
            .Select(e => new SelectListItem(e.Name, e.Id.ToString())).ToListAsync();
}
