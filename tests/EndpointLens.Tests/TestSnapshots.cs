using EndpointLens.Core.Snapshot;

namespace EndpointLens.Tests;

/// <summary>Synthetic snapshots. <see cref="Compliant"/> passes every rule; tests mutate one control at a time.</summary>
public static class TestSnapshots
{
    public static readonly DateTimeOffset CollectedAt = new(2026, 10, 20, 9, 0, 0, TimeSpan.Zero);

    public static AuditSnapshot Compliant() => new()
    {
        SnapshotId = Guid.NewGuid(),
        AgentVersion = "1.0.0",
        CollectedAtUtc = CollectedAt,
        IsElevated = true,
        System = Ok(new SystemInfo
        {
            Hostname = "LAB-PC-01", OsCaption = "Microsoft Windows 11 Pro", OsEditionId = "Professional", OsBuild = "22631.4317",
            LastHotfixInstalledUtc = CollectedAt.AddDays(-10)
        }),
        Applications = Ok(new List<InstalledApplication> { new() { Name = "7-Zip", Version = "24.08", Source = "HKLM (64-bit)" } }),
        CurrentUser = Ok(new CurrentUserInfo { InteractiveUser = @"LAB-PC-01\alice", ProcessAccount = @"LAB-PC-01\alice", ProcessIsElevated = true }),
        LocalAccounts = Ok(new LocalAccountsInfo
        {
            Accounts =
            {
                new() { Name = "Administrator", Sid = "S-1-5-21-1-2-3-500", Enabled = false },
                new() { Name = "Guest", Sid = "S-1-5-21-1-2-3-501", Enabled = false },
                new() { Name = "alice", Sid = "S-1-5-21-1-2-3-1001", Enabled = true }
            },
            Administrators = new()
            {
                new() { Name = @"LAB-PC-01\Administrator", Sid = "S-1-5-21-1-2-3-500", Type = "User" },
                new() { Name = @"LAB-PC-01\alice", Sid = "S-1-5-21-1-2-3-1001", Type = "User" }
            },
            PasswordPolicy = new PasswordPolicy { MinimumLength = 12, LockoutThreshold = 10 }
        }),
        Antivirus = Ok(new AntivirusInfo
        {
            Products = { new() { DisplayName = "Windows Defender", ProductState = 397568, Enabled = true, SignaturesUpToDate = true } },
            Defender = new DefenderStatus { RunningMode = "Normal", AntivirusEnabled = true, RealTimeProtectionEnabled = true, SignatureAgeDays = 1 }
        }),
        Firewall = Ok(new FirewallInfo
        {
            ServiceRunning = true,
            Profiles =
            {
                new() { Name = "Domain", Enabled = true, Source = "Local" },
                new() { Name = "Private", Enabled = true, Source = "Local" },
                new() { Name = "Public", Enabled = true, Source = "Local" }
            }
        }),
        SecurityConfig = Ok(new SecurityConfigInfo
        {
            UacEnabled = true, UacConsentPromptBehaviorAdmin = 5, Smb1ServerEnabled = false, Smb1Source = "test",
            RdpEnabled = false, RdpNlaRequired = true, SystemDrive = "C:", SystemDriveBitLocker = "On"
        })
    };

    public static AuditSnapshot With(Action<AuditSnapshot> mutate)
    {
        var s = Compliant();
        mutate(s);
        return s;
    }

    public static EvidenceSection<T> Ok<T>(T data) where T : class => new() { Status = EvidenceStatus.Collected, Data = data };

    public static EvidenceSection<T> Failed<T>() where T : class => EvidenceSection<T>.Missing(EvidenceStatus.AccessDenied, "Access denied (test)");
}
