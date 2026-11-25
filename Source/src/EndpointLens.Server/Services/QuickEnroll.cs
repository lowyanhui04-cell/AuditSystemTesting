using System.Text.RegularExpressions;
using EndpointLens.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Services;

/// <summary>
/// One-click "Download agent": the computer is added with a temporary name and takes its real
/// Windows computer name from its first audit, so the admin does not have to know it in advance.
/// </summary>
public static partial class QuickEnroll
{
    public const string Marker = "Added by Download agent; named after its first audit.";

    [GeneratedRegex(@"^New computer \d+$")]
    private static partial Regex PlaceholderName();

    public static bool IsPlaceholder(Data.Endpoint e) => e.Notes == Marker && PlaceholderName().IsMatch(e.Name);

    public static async Task<Data.Endpoint> CreateAsync(AppDbContext db, DateTimeOffset now, CancellationToken ct)
    {
        var endpoint = new Data.Endpoint { Name = $"pending-{Guid.NewGuid():N}", Notes = Marker, CreatedAtUtc = now, TokenHash = "pending" };
        db.Endpoints.Add(endpoint);
        await db.SaveChangesAsync(ct);
        endpoint.Name = $"New computer {endpoint.Id}";
        return endpoint;
    }

    /// <summary>Renames a placeholder computer to the hostname from its first audit (made unique if needed).</summary>
    public static async Task RenameFromHostnameAsync(AppDbContext db, Data.Endpoint tracked, string? hostname, CancellationToken ct)
    {
        if (!IsPlaceholder(tracked) || string.IsNullOrWhiteSpace(hostname)) return;
        var baseName = hostname.Trim();
        if (baseName.Length > 60) baseName = baseName[..60];
        var name = baseName;
        for (var i = 2; await db.Endpoints.AnyAsync(e => e.Name == name && e.Id != tracked.Id, ct); i++)
            name = $"{baseName} ({i})";
        tracked.Name = name;
        tracked.Notes = null;
    }
}
