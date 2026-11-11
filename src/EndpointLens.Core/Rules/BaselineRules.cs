using EndpointLens.Core.Snapshot;

namespace EndpointLens.Core.Rules;

// Project baseline "EndpointLens 2026.1". These are focused checks motivated by CIS Controls 1, 2 and 4
// and NIST SP 800-128; they are NOT a CIS Benchmark or NIST compliance assessment.

public sealed class FirewallEnabledRule : AuditRule
{
    public override string Id => "FW-001";
    public override string Version => "1.0";
    public override string Title => "Windows Defender Firewall is enabled for all network profiles";
    public override string Category => "Firewall";
    public override Severity Severity => Severity.High;
    public override string Expected => "Domain, Private and Public profiles: Enabled = true";
    public override string Rationale => "A disabled host firewall exposes listening services to every reachable network (CIS Control 4).";
    public override string Recommendation => "Open Windows Security > Firewall & network protection and turn the firewall on for each disabled profile, or re-enable it through Group Policy.";
    public override string EvidenceRef => "firewall.profiles[].enabled";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.Firewall.HasData) return MissingSection("Firewall", s.Firewall);
        var profiles = s.Firewall.Data!.Profiles;
        if (profiles.Count == 0) return Unknown("No firewall profiles were reported.");

        var disabled = profiles.Where(p => p.Enabled == false).Select(p => p.Name).ToList();
        var unknown = profiles.Where(p => p.Enabled is null).Select(p => p.Name).ToList();
        var summary = string.Join(", ", profiles.Select(p => $"{p.Name}={(p.Enabled is null ? "unknown" : p.Enabled.Value ? "on" : "off")}"));

        if (disabled.Count > 0) return Fail($"Disabled profile(s): {string.Join(", ", disabled)}. ({summary})");
        if (unknown.Count > 0 || profiles.Count < 3) return Unknown($"Not all profiles could be read. ({summary})");
        return Pass(summary);
    }
}

public sealed class AntivirusEnabledRule : AuditRule
{
    public override string Id => "AV-001";
    public override string Version => "1.0";
    public override string Title => "Antivirus protection is registered and enabled";
    public override string Category => "Antivirus";
    public override Severity Severity => Severity.High;
    public override string Expected => "At least one antivirus product registered with Windows Security Center reports enabled (or Defender real-time protection is on)";
    public override string Rationale => "Endpoints without active malware protection are exposed to commodity malware.";
    public override string Recommendation => "Enable Microsoft Defender real-time protection or install and activate a supported antivirus product, then re-run the audit.";
    public override string EvidenceRef => "antivirus.products[], antivirus.defender";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.Antivirus.HasData) return MissingSection("Antivirus", s.Antivirus);
        var av = s.Antivirus.Data!;
        var names = av.Products.Count == 0 ? "none" : string.Join(", ", av.Products.Select(p => $"{p.DisplayName} (enabled={Fmt(p.Enabled)})"));
        var defender = av.Defender is null ? "Defender status unavailable" : $"Defender real-time={Fmt(av.Defender.RealTimeProtectionEnabled)}";

        if (av.Products.Any(p => p.Enabled == true) || av.Defender?.RealTimeProtectionEnabled == true)
            return Pass($"Registered: {names}; {defender}.");
        if (av.Products.Count == 0 && av.Defender is null)
            return Unknown("No antivirus registration or Defender status could be read.");
        if (av.Products.Any(p => p.Enabled is null) && av.Defender?.RealTimeProtectionEnabled is null)
            return Unknown($"Antivirus state could not be decoded. Registered: {names}; {defender}.");
        return Fail($"No enabled antivirus found. Registered: {names}; {defender}.");
    }

    private static string Fmt(bool? b) => b is null ? "unknown" : b.Value ? "yes" : "no";
}

public sealed class AntivirusSignaturesRule : AuditRule
{
    public const int MaxSignatureAgeDays = 7;

    public override string Id => "AV-002";
    public override string Version => "1.0";
    public override string Title => "Antivirus signatures are up to date";
    public override string Category => "Antivirus";
    public override Severity Severity => Severity.Medium;
    public override string Expected => $"Defender signature age <= {MaxSignatureAgeDays} days, or the active third-party product reports signatures up to date";
    public override string Rationale => "Outdated signatures reduce detection of recent malware.";
    public override string Recommendation => "Run Windows Update or the antivirus product's update function and confirm the endpoint can reach its update source.";
    public override string EvidenceRef => "antivirus.defender.signatureAgeDays, antivirus.products[].signaturesUpToDate";
    public override string Applicability => "Endpoints with an enabled antivirus product (otherwise covered by AV-001).";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.Antivirus.HasData) return MissingSection("Antivirus", s.Antivirus);
        var av = s.Antivirus.Data!;
        var defenderActive = av.Defender?.RealTimeProtectionEnabled == true
            && !string.Equals(av.Defender.RunningMode, "Passive Mode", StringComparison.OrdinalIgnoreCase);

        if (defenderActive)
        {
            var age = av.Defender!.SignatureAgeDays;
            if (age is null) return Unknown("Defender is active but signature age could not be read.");
            return age <= MaxSignatureAgeDays
                ? Pass($"Defender signatures are {age} day(s) old.")
                : Fail($"Defender signatures are {age} day(s) old.");
        }

        var enabled = av.Products.Where(p => p.Enabled == true && !p.IsMicrosoftDefender).ToList();
        if (enabled.Count == 0) enabled = av.Products.Where(p => p.Enabled == true).ToList();
        if (enabled.Count == 0) return NotApplicable("No enabled antivirus product; see AV-001.");

        var outdated = enabled.Where(p => p.SignaturesUpToDate == false).ToList();
        if (outdated.Count > 0) return Fail($"Out of date: {string.Join(", ", outdated.Select(p => p.DisplayName))}.");
        if (enabled.Any(p => p.SignaturesUpToDate is null)) return Unknown("Signature state of the enabled product could not be decoded.");
        return Pass($"Up to date: {string.Join(", ", enabled.Select(p => p.DisplayName))}.");
    }
}

public sealed class UacEnabledRule : AuditRule
{
    public override string Id => "UAC-001";
    public override string Version => "1.0";
    public override string Title => "User Account Control is enabled and prompts administrators";
    public override string Category => "Security configuration";
    public override Severity Severity => Severity.High;
    public override string Expected => "EnableLUA = 1 and ConsentPromptBehaviorAdmin != 0";
    public override string Rationale => "With UAC disabled, every process started by an administrator runs with full privileges.";
    public override string Recommendation => "Set 'User Account Control: Run all administrators in Admin Approval Mode' to Enabled and restore the default prompt behaviour (Control Panel > User Accounts > Change User Account Control settings).";
    public override string EvidenceRef => "securityConfig.uacEnabled, securityConfig.uacConsentPromptBehaviorAdmin";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.SecurityConfig.HasData) return MissingSection("Security configuration", s.SecurityConfig);
        var c = s.SecurityConfig.Data!;
        if (c.UacEnabled is null) return Unknown("EnableLUA could not be read.");
        if (c.UacEnabled == false) return Fail("EnableLUA = 0 (UAC disabled).");
        if (c.UacConsentPromptBehaviorAdmin == 0)
            return Warn("EnableLUA = 1 but ConsentPromptBehaviorAdmin = 0 (elevate without prompting).");
        return Pass($"EnableLUA = 1, ConsentPromptBehaviorAdmin = {c.UacConsentPromptBehaviorAdmin?.ToString() ?? "unknown"}.");
    }
}

public sealed class GuestAccountDisabledRule : AuditRule
{
    public override string Id => "ACC-001";
    public override string Version => "1.0";
    public override string Title => "Built-in Guest account is disabled";
    public override string Category => "Local accounts";
    public override Severity Severity => Severity.Medium;
    public override string Expected => "Account with SID *-501: Enabled = false";
    public override string Rationale => "An enabled Guest account allows unauthenticated-style access to the endpoint.";
    public override string Recommendation => "Disable the Guest account: Computer Management > Local Users and Groups > Users > Guest > Account is disabled (or 'net user guest /active:no').";
    public override string EvidenceRef => "localAccounts.accounts[sid=*-501].enabled";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.LocalAccounts.HasData) return MissingSection("Local accounts", s.LocalAccounts);
        var guest = s.LocalAccounts.Data!.Accounts.FirstOrDefault(a => a.IsBuiltInGuest);
        if (guest is null) return Unknown("Built-in Guest account (SID *-501) was not found in the account list.");
        return guest.Enabled switch
        {
            false => Pass($"'{guest.Name}' is disabled."),
            true => Fail($"'{guest.Name}' is enabled."),
            null => Unknown($"State of '{guest.Name}' could not be read.")
        };
    }
}

public sealed class LocalAdministratorsRule : AuditRule
{
    public const int MaxAdministrators = 2;

    public override string Id => "ACC-002";
    public override string Version => "1.0";
    public override string Title => "Local Administrators group membership is limited";
    public override string Category => "Local accounts";
    public override Severity Severity => Severity.Low;
    public override string Expected => $"<= {MaxAdministrators} members in the local Administrators group";
    public override string Rationale => "Every additional administrator increases the impact of a compromised account (CIS Control 5). The acceptable number is policy-dependent, so this rule warns rather than fails.";
    public override string Recommendation => "Review each member of the local Administrators group and remove accounts that do not need administrative rights; use a separate admin account for daily users.";
    public override string EvidenceRef => "localAccounts.administrators[]";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.LocalAccounts.HasData) return MissingSection("Local accounts", s.LocalAccounts);
        var admins = s.LocalAccounts.Data!.Administrators;
        if (admins is null) return Unknown("Administrators group membership could not be read.");

        // A disabled built-in Administrator is a dormant member and is not counted.
        var disabledBuiltIn = s.LocalAccounts.Data.Accounts
            .Where(a => a.IsBuiltInAdministrator && a.Enabled == false)
            .Select(a => a.Sid).ToHashSet();
        var active = admins.Where(m => m.Sid is null || !disabledBuiltIn.Contains(m.Sid)).ToList();
        var list = string.Join(", ", active.Select(m => m.Name));

        return active.Count <= MaxAdministrators
            ? Pass($"{active.Count} active member(s): {list}.")
            : Warn($"{active.Count} active member(s): {list}.");
    }
}

public sealed class PasswordLengthRule : AuditRule
{
    public const int MinLength = 8;

    public override string Id => "PWD-001";
    public override string Version => "1.0";
    public override string Title => "Minimum password length is at least 8 characters";
    public override string Category => "Local accounts";
    public override Severity Severity => Severity.Medium;
    public override string Expected => $"Minimum password length >= {MinLength}";
    public override string Rationale => "Short passwords are easily guessed or brute-forced (NIST SP 800-63B recommends at least 8).";
    public override string Recommendation => $"Set 'Minimum password length' to {MinLength} or more in Local Security Policy > Account Policies > Password Policy (or 'net accounts /minpwlen:{MinLength}').";
    public override string EvidenceRef => "localAccounts.passwordPolicy.minimumLength";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.LocalAccounts.HasData) return MissingSection("Local accounts", s.LocalAccounts);
        var len = s.LocalAccounts.Data!.PasswordPolicy?.MinimumLength;
        if (len is null) return Unknown("Password policy could not be read.");
        return len >= MinLength ? Pass($"Minimum length = {len}.") : Fail($"Minimum length = {len}.");
    }
}

public sealed class Smb1DisabledRule : AuditRule
{
    public override string Id => "SMB-001";
    public override string Version => "1.0";
    public override string Title => "SMBv1 server protocol is disabled";
    public override string Category => "Security configuration";
    public override Severity Severity => Severity.High;
    public override string Expected => "SMB1 server protocol disabled or not installed";
    public override string Rationale => "SMBv1 is deprecated and was exploited by WannaCry/EternalBlue.";
    public override string Recommendation => "Remove the 'SMB 1.0/CIFS File Sharing Support' Windows feature, or run 'Set-SmbServerConfiguration -EnableSMB1Protocol $false' as administrator.";
    public override string EvidenceRef => "securityConfig.smb1ServerEnabled";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.SecurityConfig.HasData) return MissingSection("Security configuration", s.SecurityConfig);
        var c = s.SecurityConfig.Data!;
        var src = c.Smb1Source is null ? "" : $" (source: {c.Smb1Source})";
        return c.Smb1ServerEnabled switch
        {
            false => Pass($"SMBv1 server disabled{src}."),
            true => Fail($"SMBv1 server enabled{src}."),
            null => Unknown("SMBv1 state could not be determined (try running the agent as administrator).")
        };
    }
}

public sealed class RdpSecureRule : AuditRule
{
    public override string Id => "RDP-001";
    public override string Version => "1.0";
    public override string Title => "Remote Desktop is disabled or requires Network Level Authentication";
    public override string Category => "Security configuration";
    public override Severity Severity => Severity.Medium;
    public override string Expected => "fDenyTSConnections = 1, or UserAuthentication (NLA) = 1";
    public override string Rationale => "RDP without NLA exposes the logon screen to unauthenticated network users and pre-authentication vulnerabilities.";
    public override string Recommendation => "Turn off Remote Desktop if it is not needed (Settings > System > Remote Desktop), otherwise enable 'Require devices to use Network Level Authentication to connect'.";
    public override string EvidenceRef => "securityConfig.rdpEnabled, securityConfig.rdpNlaRequired";
    public override string Applicability => "Windows Pro/Enterprise/Education. Home editions cannot host RDP sessions (NOT_APPLICABLE).";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.SecurityConfig.HasData) return MissingSection("Security configuration", s.SecurityConfig);
        if (IsHomeEdition(s)) return NotApplicable("Home edition cannot host Remote Desktop sessions.");
        var c = s.SecurityConfig.Data!;
        if (c.RdpEnabled is null) return Unknown("Remote Desktop setting could not be read.");
        if (c.RdpEnabled == false) return Pass("Remote Desktop is disabled.");
        return c.RdpNlaRequired switch
        {
            true => Pass("Remote Desktop is enabled with NLA required."),
            false => Fail("Remote Desktop is enabled WITHOUT Network Level Authentication."),
            null => Unknown("Remote Desktop is enabled; NLA setting could not be read.")
        };
    }
}

public sealed class BitLockerRule : AuditRule
{
    public override string Id => "ENC-001";
    public override string Version => "1.0";
    public override string Title => "System drive is protected by BitLocker";
    public override string Category => "Security configuration";
    public override Severity Severity => Severity.Medium;
    public override string Expected => "System drive BitLocker ProtectionStatus = On";
    public override string Rationale => "Without disk encryption, data on a lost or stolen device can be read directly from the disk.";
    public override string Recommendation => "Enable BitLocker (or Device Encryption) for the system drive and store the recovery key in an approved location.";
    public override string EvidenceRef => "securityConfig.systemDriveBitLocker";
    public override string Applicability => "All endpoints. Requires the agent to run elevated; otherwise UNKNOWN. Home editions without Device Encryption support report NOT_APPLICABLE.";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.SecurityConfig.HasData) return MissingSection("Security configuration", s.SecurityConfig);
        var c = s.SecurityConfig.Data!;
        var drive = c.SystemDrive ?? "system drive";
        return c.SystemDriveBitLocker switch
        {
            "On" => Pass($"Drive {drive} is protected (BitLocker on)."),
            "Off" => Fail($"Drive {drive} is not encrypted (BitLocker off)."),
            "NotSupported" when IsHomeEdition(s) => NotApplicable($"The BitLocker interface for drive {drive} is not available on this Home edition."),
            _ => Unknown(s.IsElevated
                ? $"The BitLocker status of drive {drive} could not be read ({c.SystemDriveBitLocker ?? "no value"})."
                : $"Reading BitLocker for drive {drive} needs the agent to run as administrator.")
        };
    }
}

public sealed class OsUpdateRecencyRule : AuditRule
{
    public const int MaxDaysSinceUpdate = 45;

    public override string Id => "UPD-001";
    public override string Version => "1.0";
    public override string Title => "Operating system updates were installed recently";
    public override string Category => "System";
    public override Severity Severity => Severity.High;
    public override string Expected => $"Most recent hotfix installed within {MaxDaysSinceUpdate} days of collection";
    public override string Rationale => "Monthly security updates fix actively exploited vulnerabilities; a long gap suggests patching has stopped.";
    public override string Recommendation => "Open Settings > Windows Update, install pending updates, and investigate why automatic updates are not being applied.";
    public override string EvidenceRef => "system.lastHotfixInstalledUtc";

    protected override RuleVerdict Check(AuditSnapshot s)
    {
        if (!s.System.HasData) return MissingSection("System", s.System);
        var last = s.System.Data!.LastHotfixInstalledUtc;
        if (last is null) return Unknown("No hotfix installation date could be read.");
        var days = (int)Math.Floor((s.CollectedAtUtc - last.Value).TotalDays);
        return days <= MaxDaysSinceUpdate
            ? Pass($"Last update installed {last:yyyy-MM-dd} ({days} day(s) before collection).")
            : Fail($"Last update installed {last:yyyy-MM-dd} ({days} day(s) before collection).");
    }
}
