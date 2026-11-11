using System.Reflection;
using System.Security.Principal;
using EndpointLens.Core.Snapshot;

namespace EndpointLens.Agent.Collection;

/// <summary>One evidence category as shown to the user.</summary>
internal sealed record Category(int Index, string Title, string Description);

/// <summary>Progress of one category: Status is null while it is still running.</summary>
internal sealed record CategoryProgress(Category Category, EvidenceStatus? Status, long DurationMs, string? Detail);

internal static class SnapshotCollector
{
    private static readonly TimeSpan SectionTimeout = TimeSpan.FromSeconds(90);

    public static readonly IReadOnlyList<Category> Categories = new Category[]
    {
        new(0, "Hardware & Windows", "Model, CPU, memory, disks, Windows version and updates"),
        new(1, "Installed software", "Programs listed in Apps & features"),
        new(2, "Signed-in user", "Who is using this PC right now"),
        new(3, "Local accounts", "User accounts, administrators and password policy"),
        new(4, "Antivirus", "Registered antivirus and Microsoft Defender status"),
        new(5, "Firewall", "Windows Firewall for Domain, Private and Public networks"),
        new(6, "Security settings", "UAC, SMBv1, Remote Desktop and BitLocker"),
    };

    public static string AgentVersion =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static AuditSnapshot Collect(IProgress<CategoryProgress>? progress = null)
    {
        var elevated = IsElevated();
        var s = new AuditSnapshot
        {
            SnapshotId = Guid.NewGuid(),
            AgentVersion = AgentVersion,
            CollectedAtUtc = DateTimeOffset.UtcNow,
            IsElevated = elevated
        };

        EvidenceSection<T> Step<T>(int index, Func<Action<string>, T> collector, Func<T, string>? describe = null) where T : class
        {
            var category = Categories[index];
            progress?.Report(new CategoryProgress(category, null, 0, null));
            var section = CollectorRunner.Run(collector, SectionTimeout);
            var detail = section.Error ?? (section.Data is { } d && describe is not null ? describe(d) : null);
            progress?.Report(new CategoryProgress(category, section.Status, section.DurationMs, detail));
            return section;
        }

        s.System = Step(0, Collectors.System, d => $"{d.OsCaption} · {d.Manufacturer} {d.Model}".Trim(' ', '·'));
        s.Applications = Step(1, Collectors.Applications, d => $"{d.Count} programs found");
        s.CurrentUser = Step(2, Collectors.CurrentUser, d => d.InteractiveUser ?? "No one signed in");
        s.LocalAccounts = Step(3, Collectors.LocalAccounts, d => $"{d.Accounts.Count} accounts, {d.Administrators?.Count.ToString() ?? "?"} administrators");
        s.Antivirus = Step(4, Collectors.Antivirus, d => d.Products.Count == 0 ? "No antivirus registered" : string.Join(", ", d.Products.Select(p => p.DisplayName)));
        s.Firewall = Step(5, Collectors.Firewall, d => string.Join(" · ", d.Profiles.Select(p => $"{p.Name} {(p.Enabled == true ? "on" : p.Enabled == false ? "off" : "?")}")));
        s.SecurityConfig = Step(6, w => Collectors.SecurityConfig(w, elevated), _ => "UAC, SMBv1, Remote Desktop, BitLocker read");
        return s;
    }
}
