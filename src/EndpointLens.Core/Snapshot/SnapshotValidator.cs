namespace EndpointLens.Core.Snapshot;

/// <summary>
/// Server-side structural validation of a submitted snapshot. Endpoint-supplied data is untrusted:
/// sizes are bounded and timestamps must be plausible.
/// </summary>
public static class SnapshotValidator
{
    public const int MaxStringLength = 1024;
    public const int MaxApplications = 5000;
    public const int MaxAccounts = 500;

    public static List<string> Validate(AuditSnapshot? s, DateTimeOffset now)
    {
        var errors = new List<string>();
        if (s is null)
        {
            errors.Add("Payload is empty.");
            return errors;
        }

        if (s.SchemaVersion != AuditSnapshot.CurrentSchemaVersion)
            errors.Add($"Unsupported schemaVersion '{s.SchemaVersion}'. Expected '{AuditSnapshot.CurrentSchemaVersion}'.");
        if (s.SnapshotId == Guid.Empty)
            errors.Add("snapshotId is required.");
        if (s.CollectedAtUtc == default)
            errors.Add("collectedAtUtc is required.");
        else if (s.CollectedAtUtc > now.AddMinutes(10))
            errors.Add("collectedAtUtc is in the future.");
        else if (s.CollectedAtUtc < now.AddDays(-365))
            errors.Add("collectedAtUtc is older than one year.");

        if (s.System is null || s.Applications is null || s.CurrentUser is null || s.LocalAccounts is null ||
            s.Antivirus is null || s.Firewall is null || s.SecurityConfig is null)
        {
            errors.Add("All seven evidence sections must be present (they may report a failure status).");
            return errors;
        }

        if (s.System.HasData && string.IsNullOrWhiteSpace(s.System.Data!.Hostname))
            errors.Add("system.data.hostname is required when system evidence was collected.");
        if (s.Applications.Data?.Count > MaxApplications)
            errors.Add($"Too many applications (max {MaxApplications}).");
        if (s.LocalAccounts.Data?.Accounts.Count > MaxAccounts)
            errors.Add($"Too many local accounts (max {MaxAccounts}).");

        CheckStrings(s, errors);
        return errors;
    }

    private static void CheckStrings(AuditSnapshot s, List<string> errors)
    {
        IEnumerable<string?> all = new[]
        {
            s.AgentVersion, s.System.Error, s.Applications.Error, s.CurrentUser.Error, s.LocalAccounts.Error,
            s.Antivirus.Error, s.Firewall.Error, s.SecurityConfig.Error
        };
        if (s.System.Data is { } sys)
            all = all.Concat(new[] { sys.Hostname, sys.Manufacturer, sys.Model, sys.SerialNumber, sys.OsCaption, sys.OsBuild, sys.CpuName, sys.Domain });
        if (s.Applications.Data is { } apps)
            all = all.Concat(apps.SelectMany(a => new[] { a.Name, a.Version, a.Publisher, a.InstallDate, a.Source }));
        if (s.CurrentUser.Data is { } cu)
            all = all.Concat(new[] { cu.InteractiveUser, cu.ProcessAccount });
        if (s.LocalAccounts.Data is { } la)
        {
            all = all.Concat(la.Accounts.SelectMany(a => new[] { a.Name, a.Sid }));
            if (la.Administrators is { } admins) all = all.Concat(admins.SelectMany(m => new[] { m.Name, m.Sid, m.Type }));
        }
        if (s.Antivirus.Data is { } av)
            all = all.Concat(av.Products.Select(p => p.DisplayName));

        if (all.Any(v => v?.Length > MaxStringLength))
            errors.Add($"A string field exceeds {MaxStringLength} characters.");
    }
}
