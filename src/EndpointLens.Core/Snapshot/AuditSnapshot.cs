namespace EndpointLens.Core.Snapshot;

/// <summary>
/// How a single evidence category was obtained. Anything other than Collected/Partial
/// means the data is missing and rules that depend on it must report UNKNOWN, never PASS.
/// </summary>
public enum EvidenceStatus
{
    Collected,
    Partial,
    AccessDenied,
    NotSupported,
    TimedOut,
    Failed
}

public sealed class EvidenceSection<T> where T : class
{
    public EvidenceStatus Status { get; set; }
    public string? Error { get; set; }
    public long DurationMs { get; set; }
    public T? Data { get; set; }

    [System.Text.Json.Serialization.JsonIgnore]
    public bool HasData => Data is not null && Status is EvidenceStatus.Collected or EvidenceStatus.Partial;

    public static EvidenceSection<T> Missing(EvidenceStatus status, string error) => new() { Status = status, Error = error };
}

/// <summary>
/// A point-in-time, read-only snapshot of one Windows endpoint. Produced by the agent,
/// submitted to the server (or exported as JSON), and evaluated by the rule engine.
/// </summary>
public sealed class AuditSnapshot
{
    public const string CurrentSchemaVersion = "1.0";

    public string SchemaVersion { get; set; } = CurrentSchemaVersion;
    public Guid SnapshotId { get; set; }
    public string AgentVersion { get; set; } = "";
    public DateTimeOffset CollectedAtUtc { get; set; }
    public bool IsElevated { get; set; }

    public EvidenceSection<SystemInfo> System { get; set; } = new();
    public EvidenceSection<List<InstalledApplication>> Applications { get; set; } = new();
    public EvidenceSection<CurrentUserInfo> CurrentUser { get; set; } = new();
    public EvidenceSection<LocalAccountsInfo> LocalAccounts { get; set; } = new();
    public EvidenceSection<AntivirusInfo> Antivirus { get; set; } = new();
    public EvidenceSection<FirewallInfo> Firewall { get; set; } = new();
    public EvidenceSection<SecurityConfigInfo> SecurityConfig { get; set; } = new();
}

// 1. Computer specifications
public sealed class SystemInfo
{
    public string? Hostname { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? SerialNumber { get; set; }
    public string? ChassisType { get; set; }
    public string? OsCaption { get; set; }
    public string? OsEditionId { get; set; }
    public string? OsVersion { get; set; }
    public string? OsBuild { get; set; }
    public string? OsDisplayVersion { get; set; }
    public string? OsArchitecture { get; set; }
    public DateTimeOffset? OsInstallDateUtc { get; set; }
    public DateTimeOffset? LastBootUtc { get; set; }
    public string? Domain { get; set; }
    public bool? PartOfDomain { get; set; }
    public string? CpuName { get; set; }
    public int? CpuCores { get; set; }
    public int? CpuLogicalProcessors { get; set; }
    public long? TotalMemoryBytes { get; set; }
    public bool? SecureBootEnabled { get; set; }
    public DateTimeOffset? LastHotfixInstalledUtc { get; set; }
    public List<DiskInfo> Disks { get; set; } = new();
}

public sealed class DiskInfo
{
    public string? DeviceId { get; set; }
    public string? FileSystem { get; set; }
    public long? SizeBytes { get; set; }
    public long? FreeBytes { get; set; }
}

// 2. Installed applications (uninstall registry entries only)
public sealed class InstalledApplication
{
    public string Name { get; set; } = "";
    public string? Version { get; set; }
    public string? Publisher { get; set; }
    public string? InstallDate { get; set; }
    public string Source { get; set; } = "";
}

// 3. Current interactive user (session snapshot, not proof of ownership)
public sealed class CurrentUserInfo
{
    public string? InteractiveUser { get; set; }
    public string? ProcessAccount { get; set; }
    public bool ProcessIsElevated { get; set; }
}

// 4. Local accounts and policy
public sealed class LocalAccountsInfo
{
    public List<LocalAccount> Accounts { get; set; } = new();
    public List<GroupMember>? Administrators { get; set; }
    public PasswordPolicy? PasswordPolicy { get; set; }
}

public sealed class LocalAccount
{
    public string Name { get; set; } = "";
    public string? Sid { get; set; }
    public bool? Enabled { get; set; }
    public bool? PasswordRequired { get; set; }
    public bool? PasswordExpires { get; set; }
    public bool? LockedOut { get; set; }

    public bool IsBuiltInGuest => Sid?.EndsWith("-501", StringComparison.Ordinal) == true;
    public bool IsBuiltInAdministrator => Sid?.EndsWith("-500", StringComparison.Ordinal) == true;
}

public sealed class GroupMember
{
    public string Name { get; set; } = "";
    public string? Sid { get; set; }
    public string? Type { get; set; }
}

public sealed class PasswordPolicy
{
    public int? MinimumLength { get; set; }
    public int? MaximumAgeDays { get; set; }
    public int? HistoryLength { get; set; }
    public int? LockoutThreshold { get; set; }
}

// 5. Antivirus
public sealed class AntivirusInfo
{
    /// <summary>Products registered with Windows Security Center (root\SecurityCenter2).</summary>
    public List<AntivirusProduct> Products { get; set; } = new();
    /// <summary>Microsoft Defender status (root\Microsoft\Windows\Defender), when available.</summary>
    public DefenderStatus? Defender { get; set; }
}

public sealed class AntivirusProduct
{
    public string DisplayName { get; set; } = "";
    public int? ProductState { get; set; }
    public bool? Enabled { get; set; }
    public bool? SignaturesUpToDate { get; set; }
    public bool IsMicrosoftDefender => DisplayName.Contains("Defender", StringComparison.OrdinalIgnoreCase);
}

public sealed class DefenderStatus
{
    public string? RunningMode { get; set; }
    public bool? AntivirusEnabled { get; set; }
    public bool? RealTimeProtectionEnabled { get; set; }
    public DateTimeOffset? SignatureLastUpdatedUtc { get; set; }
    public int? SignatureAgeDays { get; set; }
}

// 6. Firewall
public sealed class FirewallInfo
{
    public bool? ServiceRunning { get; set; }
    public List<FirewallProfile> Profiles { get; set; } = new();
}

public sealed class FirewallProfile
{
    public string Name { get; set; } = "";
    public bool? Enabled { get; set; }
    /// <summary>"Policy" when a Group Policy value overrides the local setting, otherwise "Local".</summary>
    public string? Source { get; set; }
}

// 7. Selected security configuration
public sealed class SecurityConfigInfo
{
    public bool? UacEnabled { get; set; }
    public int? UacConsentPromptBehaviorAdmin { get; set; }
    public bool? Smb1ServerEnabled { get; set; }
    public string? Smb1Source { get; set; }
    public bool? RdpEnabled { get; set; }
    public bool? RdpNlaRequired { get; set; }
    public string? SystemDrive { get; set; }
    /// <summary>BitLocker ProtectionStatus of the system drive: "On", "Off" or "Unknown".</summary>
    public string? SystemDriveBitLocker { get; set; }
}
