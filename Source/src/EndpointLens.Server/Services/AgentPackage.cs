using System.IO.Compression;
using System.Text.Json;

namespace EndpointLens.Server.Services;

/// <summary>
/// Builds the "Download agent" zip: the portable agent plus a one-time setup file holding the server
/// address and that endpoint's credential, so the agent is connected the first time it starts.
/// </summary>
public sealed class AgentPackage(IConfiguration config, IWebHostEnvironment env)
{
    public const string SetupFileName = "endpointlens-setup.json";
    public const string ExeName = "EndpointLens.exe";

    /// <summary>Agent:ExePath in configuration, otherwise agent/EndpointLens.exe under the server folder.</summary>
    public string ExePath => config["Agent:ExePath"] is { Length: > 0 } p
        ? Path.GetFullPath(p, env.ContentRootPath)
        : Path.Combine(env.ContentRootPath, "agent", ExeName);

    public bool IsAvailable => File.Exists(ExePath);

    /// <summary>Address the agent should upload to. Agent:ServerUrl overrides the address the admin is browsing with.</summary>
    public string ServerUrl(HttpRequest request) =>
        config["Agent:ServerUrl"] is { Length: > 0 } url ? url.TrimEnd('/') : $"{request.Scheme}://{request.Host}";

    public static bool IsLoopback(string serverUrl) =>
        Uri.TryCreate(serverUrl, UriKind.Absolute, out var u) && (u.IsLoopback || u.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase));

    public async Task<byte[]> BuildAsync(string endpointName, string serverUrl, string credential, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            // The single-file exe is already compressed; storing it keeps the download fast to build.
            var exe = zip.CreateEntry(ExeName, CompressionLevel.NoCompression);
            await using (var target = exe.Open())
            await using (var source = File.OpenRead(ExePath))
                await source.CopyToAsync(target, ct);

            var setup = zip.CreateEntry(SetupFileName, CompressionLevel.Optimal);
            await using (var target = setup.Open())
                await JsonSerializer.SerializeAsync(target, new SetupFile(1, endpointName, serverUrl, credential), new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }, ct);

            var readme = zip.CreateEntry("READ ME FIRST.txt", CompressionLevel.Optimal);
            await using (var w = new StreamWriter(readme.Open()))
                await w.WriteAsync(
                    $"EndpointLens agent for \"{endpointName}\"\r\n\r\n" +
                    "1. Right-click this zip and choose \"Extract All...\".\r\n" +
                    "2. Open the extracted folder and double-click EndpointLens.exe.\r\n" +
                    "   If Windows shows \"Windows protected your PC\", click More info > Run anyway.\r\n" +
                    "3. Sign in to the local dashboard, then click Start audit.\r\n" +
                    "4. EndpointLens uploads automatically. Check the upload status on the results page.\r\n\r\n" +
                    $"Keep {SetupFileName} and this ZIP private. They contain the endpoint upload credential.\r\n");
        }
        return ms.ToArray();
    }

    public sealed record SetupFile(int Version, string EndpointName, string ServerUrl, string Credential);
}
