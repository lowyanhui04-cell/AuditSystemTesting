using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace EndpointLens.Agent.Collection;

/// <summary>
/// netapi32 calls for local password policy and group membership. Used instead of parsing
/// 'net accounts' because its output is localized.
/// </summary>
internal static class NetApi
{
    private const int NERR_Success = 0;
    private const uint TIMEQ_FOREVER = uint.MaxValue;

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_0
    {
        public uint min_passwd_len;
        public uint max_passwd_age;
        public uint min_passwd_age;
        public uint force_logoff;
        public uint password_hist_len;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_3
    {
        public uint lockout_duration;
        public uint lockout_observation_window;
        public uint lockout_threshold;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_MEMBERS_INFO_2
    {
        public IntPtr lgrmi2_sid;
        public int lgrmi2_sidusage;
        public string lgrmi2_domainandname;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserModalsGet(string? server, int level, out IntPtr buf);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? server, string group, int level, out IntPtr buf,
        int prefmaxlen, out int entriesread, out int totalentries, IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buf);

    public static (int MinLength, int? MaxAgeDays, int HistoryLength) GetPasswordPolicy()
    {
        var info = Read<USER_MODALS_INFO_0>(0);
        int? maxAge = info.max_passwd_age == TIMEQ_FOREVER ? null : (int)(info.max_passwd_age / 86400);
        return ((int)info.min_passwd_len, maxAge, (int)info.password_hist_len);
    }

    public static int GetLockoutThreshold() => (int)Read<USER_MODALS_INFO_3>(3).lockout_threshold;

    public static List<(string Name, string Sid, string Type)> GetAdministratorsMembers()
    {
        // Resolve the localized group name from the well-known SID S-1-5-32-544.
        var account = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Translate(typeof(NTAccount)).Value;
        var groupName = account[(account.IndexOf('\\') + 1)..];

        int rc = NetLocalGroupGetMembers(null, groupName, 2, out var buf, -1, out var read, out _, IntPtr.Zero);
        if (rc != NERR_Success) throw new Win32Exception(rc);
        try
        {
            var result = new List<(string, string, string)>();
            int size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_2>();
            for (int i = 0; i < read; i++)
            {
                var m = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(buf + i * size);
                var sid = new SecurityIdentifier(m.lgrmi2_sid).Value;
                var type = m.lgrmi2_sidusage switch { 1 => "User", 2 => "Group", 4 => "WellKnownGroup", 5 => "Group", 6 => "Deleted", _ => "Other" };
                result.Add((m.lgrmi2_domainandname ?? sid, sid, type));
            }
            return result;
        }
        finally { NetApiBufferFree(buf); }
    }

    private static T Read<T>(int level) where T : struct
    {
        int rc = NetUserModalsGet(null, level, out var buf);
        if (rc != NERR_Success) throw new Win32Exception(rc);
        try { return Marshal.PtrToStructure<T>(buf); }
        finally { NetApiBufferFree(buf); }
    }
}
