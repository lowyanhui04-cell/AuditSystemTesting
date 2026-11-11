using System.Globalization;
using System.Security.Principal;
using EndpointLens.Core.Snapshot;
using Microsoft.Win32;
using static EndpointLens.Agent.Collection.CollectorRunner;

namespace EndpointLens.Agent.Collection;

/// <summary>
/// Read-only evidence collectors, one per category. Nothing here writes to the registry,
/// changes settings, or reads passwords, documents or browser data.
/// </summary>
internal static class Collectors
{
    // ---------- 1. Computer specifications ----------
    public static SystemInfo System(Action<string> warn)
    {
        var info = new SystemInfo { Hostname = Environment.MachineName };

        Probe("Win32_ComputerSystem", warn, () =>
        {
            var cs = Wmi.First(Wmi.Cimv2, "SELECT Manufacturer, Model, TotalPhysicalMemory, Domain, PartOfDomain FROM Win32_ComputerSystem");
            if (cs is null) return 0;
            info.Manufacturer = cs.Str("Manufacturer");
            info.Model = cs.Str("Model");
            info.TotalMemoryBytes = cs.Long("TotalPhysicalMemory");
            info.Domain = cs.Str("Domain");
            info.PartOfDomain = cs.Bool("PartOfDomain");
            return 0;
        });

        Probe("Win32_OperatingSystem", warn, () =>
        {
            var os = Wmi.First(Wmi.Cimv2, "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime FROM Win32_OperatingSystem");
            if (os is null) return 0;
            info.OsCaption = os.Str("Caption");
            info.OsVersion = os.Str("Version");
            info.OsBuild = os.Str("BuildNumber");
            info.OsArchitecture = os.Str("OSArchitecture");
            info.OsInstallDateUtc = os.Date("InstallDate");
            info.LastBootUtc = os.Date("LastBootUpTime");
            return 0;
        });

        Probe("CurrentVersion registry", warn, () =>
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            info.OsEditionId = key?.GetValue("EditionID") as string;
            info.OsDisplayVersion = key?.GetValue("DisplayVersion") as string;
            if (key?.GetValue("UBR") is int ubr && info.OsBuild is not null) info.OsBuild = $"{info.OsBuild}.{ubr}";
            return 0;
        });

        Probe("Win32_Processor", warn, () =>
        {
            var cpu = Wmi.First(Wmi.Cimv2, "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor");
            info.CpuName = cpu?.Str("Name");
            info.CpuCores = cpu?.Int("NumberOfCores");
            info.CpuLogicalProcessors = cpu?.Int("NumberOfLogicalProcessors");
            return 0;
        });

        Probe("Win32_BIOS", warn, () => info.SerialNumber = Wmi.First(Wmi.Cimv2, "SELECT SerialNumber FROM Win32_BIOS")?.Str("SerialNumber"));

        Probe("Win32_SystemEnclosure", warn, () =>
        {
            var enc = Wmi.First(Wmi.Cimv2, "SELECT ChassisTypes FROM Win32_SystemEnclosure");
            if (enc?["ChassisTypes"] is ushort[] { Length: > 0 } types) info.ChassisType = ChassisName(types[0]);
            return 0;
        });

        Probe("Win32_LogicalDisk", warn, () =>
        {
            foreach (var d in Wmi.Query(Wmi.Cimv2, "SELECT DeviceID, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3"))
                info.Disks.Add(new DiskInfo { DeviceId = d.Str("DeviceID"), FileSystem = d.Str("FileSystem"), SizeBytes = d.Long("Size"), FreeBytes = d.Long("FreeSpace") });
            return 0;
        });

        Probe("Secure Boot registry", warn, () =>
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            info.SecureBootEnabled = key?.GetValue("UEFISecureBootEnabled") is int v ? v == 1 : null;
            return 0;
        });

        Probe("Win32_QuickFixEngineering", warn, () =>
        {
            DateTimeOffset? latest = null;
            foreach (var qfe in Wmi.Query(Wmi.Cimv2, "SELECT InstalledOn FROM Win32_QuickFixEngineering", TimeSpan.FromSeconds(40)))
            {
                // InstalledOn is a locale-formatted string (often M/d/yyyy) or a hex FILETIME on old systems.
                var raw = qfe.Str("InstalledOn");
                if (raw is null) continue;
                if (DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var dt) ||
                    DateTime.TryParse(raw, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out dt))
                {
                    var d = new DateTimeOffset(dt).ToUniversalTime();
                    if (d <= DateTimeOffset.UtcNow.AddDays(1) && (latest is null || d > latest)) latest = d;
                }
            }
            info.LastHotfixInstalledUtc = latest;
            return 0;
        });

        return info;
    }

    private static string ChassisName(ushort t) => t switch
    {
        3 or 4 or 5 or 6 or 7 or 15 or 16 or 35 => "Desktop",
        8 or 9 or 10 or 14 or 30 or 31 or 32 => "Laptop",
        13 => "All-in-one",
        _ => $"Other ({t})"
    };

    // ---------- 2. Installed applications ----------
    public static List<InstalledApplication> Applications(Action<string> warn)
    {
        var apps = new Dictionary<string, InstalledApplication>(StringComparer.OrdinalIgnoreCase);
        const string path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

        void ReadHive(RegistryHive hive, RegistryView view, string source)
        {
            Probe(source, warn, () =>
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var uninstall = root.OpenSubKey(path);
                if (uninstall is null) return 0;
                foreach (var sub in uninstall.GetSubKeyNames())
                {
                    using var k = uninstall.OpenSubKey(sub);
                    if (k?.GetValue("DisplayName") is not string name || string.IsNullOrWhiteSpace(name)) continue;
                    if (k.GetValue("SystemComponent") is int sc && sc == 1) continue;
                    if (k.GetValue("ParentKeyName") is string) continue; // updates/patches of another product
                    var app = new InstalledApplication
                    {
                        Name = name.Trim(),
                        Version = (k.GetValue("DisplayVersion") as string)?.Trim(),
                        Publisher = (k.GetValue("Publisher") as string)?.Trim(),
                        InstallDate = k.GetValue("InstallDate") as string,
                        Source = source
                    };
                    apps.TryAdd($"{app.Name}|{app.Version}", app);
                }
                return 0;
            });
        }

        ReadHive(RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM (64-bit)");
        ReadHive(RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM (32-bit)");
        ReadHive(RegistryHive.CurrentUser, RegistryView.Default, "HKCU (process user)");

        return apps.Values.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ---------- 3. Current interactive user ----------
    public static CurrentUserInfo CurrentUser(Action<string> warn)
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new CurrentUserInfo
        {
            // The console session owner, which differs from the process account when elevated with other credentials.
            InteractiveUser = Probe("Win32_ComputerSystem.UserName", warn,
                () => Wmi.First(Wmi.Cimv2, "SELECT UserName FROM Win32_ComputerSystem")?.Str("UserName")),
            ProcessAccount = identity.Name,
            ProcessIsElevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)
        };
    }

    // ---------- 4. Local accounts ----------
    public static LocalAccountsInfo LocalAccounts(Action<string> warn)
    {
        var info = new LocalAccountsInfo();

        Probe("Win32_UserAccount", warn, () =>
        {
            foreach (var u in Wmi.Query(Wmi.Cimv2, "SELECT Name, SID, Disabled, PasswordRequired, PasswordExpires, Lockout FROM Win32_UserAccount WHERE LocalAccount = True"))
            {
                var disabled = u.Bool("Disabled");
                info.Accounts.Add(new LocalAccount
                {
                    Name = u.Str("Name") ?? "",
                    Sid = u.Str("SID"),
                    Enabled = disabled is null ? null : !disabled,
                    PasswordRequired = u.Bool("PasswordRequired"),
                    PasswordExpires = u.Bool("PasswordExpires"),
                    LockedOut = u.Bool("Lockout")
                });
            }
            return 0;
        });
        if (info.Accounts.Count == 0) throw new InvalidOperationException("No local accounts could be enumerated.");

        info.Administrators = Probe("Administrators group", warn, () =>
            NetApi.GetAdministratorsMembers().Select(m => new GroupMember { Name = m.Name, Sid = m.Sid, Type = m.Type }).ToList());

        info.PasswordPolicy = Probe("Password policy", warn, () =>
        {
            var (min, maxAge, history) = NetApi.GetPasswordPolicy();
            return new PasswordPolicy
            {
                MinimumLength = min,
                MaximumAgeDays = maxAge,
                HistoryLength = history,
                LockoutThreshold = Probe<int?>("Lockout policy", warn, () => NetApi.GetLockoutThreshold())
            };
        });

        return info;
    }

    // ---------- 5. Antivirus ----------
    public static AntivirusInfo Antivirus(Action<string> warn)
    {
        var info = new AntivirusInfo();
        bool securityCenterOk = Probe("SecurityCenter2", warn, () =>
        {
            foreach (var p in Wmi.Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
            {
                var state = p.Int("productState");
                info.Products.Add(new AntivirusProduct
                {
                    DisplayName = p.Str("displayName") ?? "(unnamed)",
                    ProductState = state,
                    // productState is undocumented; the widely used decoding is: bit 0x1000 = enabled, bit 0x10 = signatures out of date.
                    Enabled = state is null ? null : (state & 0x1000) != 0,
                    SignaturesUpToDate = state is null ? null : (state & 0x10) == 0
                });
            }
            return true;
        });

        info.Defender = Probe("Defender MSFT_MpComputerStatus", warn, () =>
        {
            var d = Wmi.First(@"root\Microsoft\Windows\Defender",
                "SELECT AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, AntivirusSignatureAge FROM MSFT_MpComputerStatus");
            if (d is null) return null;
            return new DefenderStatus
            {
                RunningMode = d.Str("AMRunningMode"),
                AntivirusEnabled = d.Bool("AntivirusEnabled"),
                RealTimeProtectionEnabled = d.Bool("RealTimeProtectionEnabled"),
                SignatureLastUpdatedUtc = d.Date("AntivirusSignatureLastUpdated"),
                SignatureAgeDays = d.Int("AntivirusSignatureAge")
            };
        });

        if (!securityCenterOk && info.Defender is null)
            throw new InvalidOperationException("Neither Windows Security Center nor Defender status could be read.");
        return info;
    }

    // ---------- 6. Firewall ----------
    public static FirewallInfo Firewall(Action<string> warn)
    {
        var info = new FirewallInfo
        {
            ServiceRunning = Probe<bool?>("MpsSvc service", warn, () =>
                Wmi.First(Wmi.Cimv2, "SELECT State FROM Win32_Service WHERE Name = 'MpsSvc'")?.Str("State") is { } state ? state == "Running" : null)
        };

        // Effective state: a Group Policy value overrides the local value.
        foreach (var (name, key) in new[] { ("Domain", "DomainProfile"), ("Private", "StandardProfile"), ("Public", "PublicProfile") })
        {
            var profile = new FirewallProfile { Name = name };
            Probe($"Firewall {name} profile", warn, () =>
            {
                using var policy = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{key}");
                if (policy?.GetValue("EnableFirewall") is int p)
                {
                    profile.Enabled = p == 1;
                    profile.Source = "Policy";
                    return 0;
                }
                using var local = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{key}");
                if (local?.GetValue("EnableFirewall") is int l)
                {
                    profile.Enabled = l == 1;
                    profile.Source = "Local";
                }
                else warn($"Firewall {name} profile: EnableFirewall value not present");
                return 0;
            });
            info.Profiles.Add(profile);
        }

        // If the firewall service is stopped, no profile is actually enforced.
        if (info.ServiceRunning == false)
            foreach (var p in info.Profiles) { p.Enabled = false; p.Source = "Service stopped"; }

        return info;
    }

    // ---------- 7. Selected security configuration ----------
    public static SecurityConfigInfo SecurityConfig(Action<string> warn, bool elevated)
    {
        var c = new SecurityConfigInfo { SystemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:" };

        Probe("UAC registry", warn, () =>
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            c.UacEnabled = k?.GetValue("EnableLUA") is int lua ? lua != 0 : null;
            c.UacConsentPromptBehaviorAdmin = k?.GetValue("ConsentPromptBehaviorAdmin") as int?;
            return 0;
        });

        Probe("RDP registry", warn, () =>
        {
            using var ts = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
            c.RdpEnabled = ts?.GetValue("fDenyTSConnections") is int deny ? deny == 0 : null;
            using var rdp = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            c.RdpNlaRequired = rdp?.GetValue("UserAuthentication") is int nla ? nla == 1 : null;
            return 0;
        });

        ProbeSmb1(c, warn);

        c.SystemDriveBitLocker = Probe("BitLocker", warn, () =>
        {
            try
            {
                var vol = Wmi.First(@"root\CIMV2\Security\MicrosoftVolumeEncryption",
                    $"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '{c.SystemDrive}'");
                return vol?.Int("ProtectionStatus") switch { 1 => "On", 0 => "Off", _ => "Unknown" };
            }
            catch (Exception ex) when (Wmi.IsNotSupported(ex)) { return "NotSupported"; }
            catch (Exception ex) when (Wmi.IsAccessDenied(ex) && !elevated)
            {
                warn("BitLocker: requires administrator");
                return null;
            }
        });

        return c;
    }

    private static void ProbeSmb1(SecurityConfigInfo c, Action<string> warn)
    {
        var errors = new List<string>();
        try
        {
            var smb = Wmi.First(@"root\Microsoft\Windows\SMB", "SELECT EnableSMB1Protocol FROM MSFT_SmbServerConfiguration");
            if (smb?.Bool("EnableSMB1Protocol") is bool b) { c.Smb1ServerEnabled = b; c.Smb1Source = "MSFT_SmbServerConfiguration"; return; }
        }
        catch (Exception ex) { errors.Add($"SmbServerConfiguration: {(Wmi.IsAccessDenied(ex) ? "access denied" : ex.Message)}"); }

        try
        {
            var feature = Wmi.First(Wmi.Cimv2, "SELECT InstallState FROM Win32_OptionalFeature WHERE Name = 'SMB1Protocol-Server'")
                       ?? Wmi.First(Wmi.Cimv2, "SELECT InstallState FROM Win32_OptionalFeature WHERE Name = 'SMB1Protocol'");
            // InstallState: 1 = Enabled, 2 = Disabled, 3 = Absent
            if (feature?.Int("InstallState") is int st) { c.Smb1ServerEnabled = st == 1; c.Smb1Source = "Win32_OptionalFeature"; return; }
        }
        catch (Exception ex) { errors.Add($"OptionalFeature: {ex.Message}"); }

        using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
        if (k?.GetValue("SMB1") is int reg) { c.Smb1ServerEnabled = reg != 0; c.Smb1Source = "LanmanServer\\Parameters\\SMB1"; return; }

        warn("SMBv1: " + (errors.Count > 0 ? string.Join("; ", errors) : "state not determinable"));
    }
}
