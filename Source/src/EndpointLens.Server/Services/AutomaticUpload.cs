using System.Net.Http.Headers;
using System.Text.Json;
using EndpointLens.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Services;

internal sealed record UploadSetup(string Address, string Credential, string Destination)
{
    public static UploadSetup? Load(string directory)
    {
        try
        {
            var file = new FileInfo(Path.Combine(directory, AgentPackage.SetupFileName));
            if (!file.Exists || file.Length > 8192) return null;
            var setup = JsonSerializer.Deserialize<AgentPackage.SetupFile>(
                File.ReadAllText(file.FullName), new JsonSerializerOptions(JsonSerializerDefaults.Web));
            if (setup is not { Version: 1, Credential.Length: > 0 and <= 256, ServerUrl.Length: > 0 and <= 2048 } ||
                !Uri.TryCreate(setup.ServerUrl, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 ||
                !AuthenticationHeaderValue.TryParse("Bearer " + setup.Credential, out var auth) ||
                auth.Parameter != setup.Credential)
                return null;

            var parts = setup.Credential.Split('_', 3);
            if (parts.Length != 3 || parts[0] != "el" || !int.TryParse(parts[1], out var endpointId) || endpointId <= 0 ||
                parts[2].Length == 0 || !parts[2].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                return null;
            var address = uri.GetLeftPart(UriPartial.Authority);
            return new UploadSetup(address, setup.Credential, $"{address}/{endpointId}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }
}

internal sealed class AutomaticUpload(
    LocalEnrollment enrollment, IServiceScopeFactory scopes, ILogger<AutomaticUpload> logger) : BackgroundService
{
    private readonly SemaphoreSlim _wake = new(0, 1);

    public void Wake()
    {
        lock (_wake)
        {
            if (_wake.CurrentCount == 0) _wake.Release();
        }
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var client = new SubmissionClient();
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await SendPendingAsync(client, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                logger.LogWarning(ex, "The local upload queue will be retried.");
            }
            await _wake.WaitAsync(TimeSpan.FromMinutes(1), ct);
        }
    }

    private async Task SendPendingAsync(SubmissionClient client, CancellationToken ct)
    {
        if (enrollment.Current is not { } setup) return;
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var pending = await db.AuditUploads.AsNoTracking()
            .Where(upload => upload.Destination == setup.Destination && !upload.Uploaded)
            .OrderBy(upload => upload.AuditId).Select(upload => upload.AuditId).ToListAsync(ct);

        foreach (var id in pending)
        {
            if (!ReferenceEquals(enrollment.Current, setup)) break;
            var snapshot = await db.Audits.Where(a => a.Id == id)
                .Select(a => a.SnapshotJson).SingleAsync(ct);
            var result = await client.SubmitAsync(setup.Address, setup.Credential, snapshot, ct);
            // Store generic status only. A server response can contain endpoint data.
            await db.AuditUploads.Where(upload => upload.AuditId == id && !upload.Uploaded)
                .ExecuteUpdateAsync(update => update
                    .SetProperty(upload => upload.Uploaded, result.Success)
                    .SetProperty(upload => upload.Attempted, true), ct);
            if (!result.Success && result.Retryable) break;
        }
    }
}
