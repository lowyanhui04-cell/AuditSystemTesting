using System.Management;

namespace EndpointLens.Agent.Collection;

/// <summary>Thin read-only wrapper over CIM/WMI queries with a per-query timeout.</summary>
internal static class Wmi
{
    public const string Cimv2 = @"root\cimv2";
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);

    public static List<ManagementBaseObject> Query(string scope, string wql, TimeSpan? timeout = null)
    {
        var ms = new ManagementScope(scope, new ConnectionOptions { Timeout = timeout ?? DefaultTimeout });
        ms.Connect();
        // Rewindable must stay true: on .NET 9 a forward-only enumeration enumerated via LINQ silently yields no rows.
        var options = new System.Management.EnumerationOptions { Timeout = timeout ?? DefaultTimeout, ReturnImmediately = true, Rewindable = true };
        using var searcher = new ManagementObjectSearcher(ms, new ObjectQuery(wql), options);
        return searcher.Get().Cast<ManagementBaseObject>().ToList();
    }

    public static ManagementBaseObject? First(string scope, string wql) => Query(scope, wql).FirstOrDefault();

    public static string? Str(this ManagementBaseObject o, string prop) => o[prop]?.ToString()?.Trim();

    public static bool? Bool(this ManagementBaseObject o, string prop) => o[prop] is bool b ? b : null;

    public static long? Long(this ManagementBaseObject o, string prop) =>
        o[prop] is { } v && long.TryParse(v.ToString(), out var l) ? l : null;

    public static int? Int(this ManagementBaseObject o, string prop) =>
        o[prop] is { } v && int.TryParse(v.ToString(), out var i) ? i : null;

    public static DateTimeOffset? Date(this ManagementBaseObject o, string prop)
    {
        if (o[prop] is not string s || string.IsNullOrWhiteSpace(s)) return null;
        try { return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(s)).ToUniversalTime(); }
        catch { return null; }
    }

    public static bool IsAccessDenied(Exception ex) => ex switch
    {
        UnauthorizedAccessException => true,
        ManagementException me => me.ErrorCode == ManagementStatus.AccessDenied,
        _ => false
    };

    public static bool IsNotSupported(Exception ex) =>
        ex is ManagementException me && me.ErrorCode is ManagementStatus.InvalidNamespace or ManagementStatus.InvalidClass or ManagementStatus.NotSupported;
}
