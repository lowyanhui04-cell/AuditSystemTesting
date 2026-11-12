using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EndpointLens.Agent;

/// <summary>
/// Agent settings stored per Windows user. The endpoint credential is encrypted with DPAPI
/// (CurrentUser scope) and is never written in plain text or logged.
/// </summary>
internal sealed class AgentSettings
{
    public string ServerUrl { get; set; } = "https://auditsystemtesting.onrender.com/";
    public string? ProtectedToken { get; set; }

    public static string DataDirectory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EndpointLens");

    private static string FilePath => Path.Combine(DataDirectory, "agent-settings.json");

    public string? GetToken()
    {
        if (ProtectedToken is null) return null;
        try
        {
            var bytes = ProtectedData.Unprotect(Convert.FromBase64String(ProtectedToken), null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (CryptographicException) { return null; }
    }

    public void SetToken(string? token)
    {
        ProtectedToken = string.IsNullOrWhiteSpace(token)
            ? null
            : Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(token.Trim()), null, DataProtectionScope.CurrentUser));
    }

    public static AgentSettings Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<AgentSettings>(File.ReadAllText(FilePath)) ?? new AgentSettings()
                : new AgentSettings();
        }
        catch { return new AgentSettings(); }
    }

    public void Save()
    {
        Directory.CreateDirectory(DataDirectory);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}
