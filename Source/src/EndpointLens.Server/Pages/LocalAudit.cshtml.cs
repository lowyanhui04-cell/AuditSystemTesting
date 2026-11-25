using EndpointLens.Core.Snapshot;
using EndpointLens.Server.Collection;
using EndpointLens.Server.Data;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Pages;

public sealed class LocalAuditModel(
    LocalDashboard mode, LocalEnrollment enrollment, AppDbContext db, AuditIngestion ingestion,
    TimeProvider clock, ILogger<LocalAuditModel> logger) : PageModel
{
    public string ComputerName => Environment.MachineName;
    public bool IsElevated => OperatingSystem.IsWindows() && SnapshotCollector.IsElevated();
    public string? Error { get; private set; }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static AuditSnapshot CollectWindowsSnapshot() => SnapshotCollector.Collect();

    public IActionResult OnGet() => mode.Enabled && OperatingSystem.IsWindows() ? Page() : NotFound();

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        if (!mode.Enabled || !OperatingSystem.IsWindows()) return NotFound();
        if (enrollment.Managed && (enrollment.Current is null || !User.IsInRole("Admin"))) return RedirectToPage("/Account/Login");
        if (!await mode.AuditGate.WaitAsync(0, ct))
        {
            Error = "An audit is already running. Wait for its results before starting another.";
            return Page();
        }

        try
        {
            // Finish and persist collection even if the operator closes the browser tab.
            var snapshot = await Task.Run(CollectWindowsSnapshot);
            var errors = SnapshotValidator.Validate(snapshot, clock.GetUtcNow());
            if (errors.Count > 0)
            {
                Error = string.Join(" ", errors);
                return Page();
            }

            await using var transaction = await db.Database.BeginTransactionAsync();
            var name = ComputerName;
            var endpoint = await db.Endpoints.SingleOrDefaultAsync(e => e.Name == name);
            if (endpoint is null)
            {
                endpoint = new Data.Endpoint
                {
                    Name = name,
                    CreatedAtUtc = clock.GetUtcNow(),
                    TokenHash = EndpointCredentials.Generate(0).Hash
                };
                db.Endpoints.Add(endpoint);
                await db.SaveChangesAsync();
            }

            var result = await ingestion.IngestAsync(endpoint, snapshot, "local");
            if (result.AuditId is not { } id)
            {
                Error = string.Join(" ", result.Errors ?? ["The audit could not be saved."]);
                return Page();
            }

            var setup = enrollment.Current;
            if (setup is not null)
            {
                db.AuditUploads.Add(new AuditUpload { AuditId = id, Destination = setup.Destination });
                await db.SaveChangesAsync();
            }

            await transaction.CommitAsync();
            HttpContext.RequestServices.GetService<AutomaticUpload>()?.Wake();
            return RedirectToPage("/Audits/Details", new { id });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Local audit failed.");
            Error = "The audit could not be saved. Check the EndpointLens window for details and try again.";
            return Page();
        }
        finally
        {
            mode.AuditGate.Release();
        }
    }
}
