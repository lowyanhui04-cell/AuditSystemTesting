using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using EndpointLens.Core.Snapshot;

namespace EndpointLens.Agent;

/// <summary>Result of talking to the server, worded for the person using the agent.</summary>
internal sealed record SubmitResult(bool Success, string Message, bool Retryable, int? AuditId = null);

/// <summary>Talks to the EndpointLens server over HTTPS (certificate validation stays enabled).</summary>
internal sealed class SubmissionClient : IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <summary>Checks the server URL and credential without sending any audit data.</summary>
    public async Task<SubmitResult> CheckConnectionAsync(string serverUrl, string token, CancellationToken ct = default)
    {
        if (BuildUri(serverUrl, "/api/v1/whoami") is not { } uri)
            return new SubmitResult(false, "The server address must start with https://", false);

        using var req = new HttpRequestMessage(HttpMethod.Get, uri);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await SendAsync(req, async resp =>
        {
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var name = doc.RootElement.TryGetProperty("name", out var n) ? n.GetString() : null;
            return new SubmitResult(true, $"Connected as \"{name}\"", false);
        }, ct);
    }

    public async Task<SubmitResult> SubmitAsync(string serverUrl, string token, string snapshotJson, CancellationToken ct = default)
    {
        if (BuildUri(serverUrl, "/api/v1/snapshots") is not { } uri)
            return new SubmitResult(false, "The server address must start with https://", false);

        using var req = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new StringContent(snapshotJson, Encoding.UTF8, "application/json")
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await SendAsync(req, async resp =>
        {
            var id = ReadAuditId(await resp.Content.ReadAsStringAsync(ct));
            return resp.StatusCode == HttpStatusCode.Created
                ? new SubmitResult(true, "Uploaded to the dashboard", false, id)
                : new SubmitResult(true, "Already on the dashboard (uploaded before)", false, id);
        }, ct);
    }

    private async Task<SubmitResult> SendAsync(HttpRequestMessage req, Func<HttpResponseMessage, Task<SubmitResult>> onSuccess, CancellationToken ct)
    {
        try
        {
            using var resp = await _http.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode) return await onSuccess(resp);
            var body = await resp.Content.ReadAsStringAsync(ct);
            return resp.StatusCode switch
            {
                HttpStatusCode.Unauthorized => new SubmitResult(false, "The server rejected the credential. Check it, or create a new one on the dashboard.", false),
                HttpStatusCode.BadRequest => new SubmitResult(false, "The server rejected the audit data: " + Errors(body), false),
                HttpStatusCode.Conflict => new SubmitResult(false, "This audit belongs to a different endpoint.", false),
                _ => new SubmitResult(false, $"The server returned an error ({(int)resp.StatusCode}). Try again later.", true)
            };
        }
        catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException)
        {
            return new SubmitResult(false, "This PC does not trust the server's HTTPS certificate. Install the certificate, then try again.", true);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return new SubmitResult(false, "Cannot reach the server. Check the address and that the server is running.", true);
        }
    }

    private static Uri? BuildUri(string serverUrl, string path) =>
        Uri.TryCreate(serverUrl.Trim().TrimEnd('/') + path, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps ? uri : null;

    private static int? ReadAuditId(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("auditId", out var id) && id.TryGetInt32(out var v) ? v : null;
        }
        catch (JsonException) { return null; }
    }

    private static string Errors(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("errors", out var e) && e.ValueKind == JsonValueKind.Array)
                return string.Join(" ", e.EnumerateArray().Select(x => x.GetString()));
        }
        catch (JsonException) { }
        return body.Length > 200 ? body[..200] : body;
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>
/// Local store of snapshots. Every snapshot is written to 'outbox' first and moved to 'sent' after the
/// server accepts it, so a failed upload can be retried (idempotent by snapshotId) or imported manually.
/// </summary>
internal static class Outbox
{
    public static string PendingDir => Path.Combine(AgentSettings.DataDirectory, "outbox");
    public static string SentDir => Path.Combine(AgentSettings.DataDirectory, "sent");

    public static string Save(AuditSnapshot s, string json)
    {
        Directory.CreateDirectory(PendingDir);
        var path = Path.Combine(PendingDir, $"{s.CollectedAtUtc:yyyyMMddTHHmmssZ}_{s.SnapshotId:N}.json");
        File.WriteAllText(path, json);
        return path;
    }

    public static IReadOnlyList<string> Pending() =>
        Directory.Exists(PendingDir) ? Directory.GetFiles(PendingDir, "*.json").OrderBy(p => p).ToList() : Array.Empty<string>();

    public static void MarkSent(string path)
    {
        Directory.CreateDirectory(SentDir);
        File.Move(path, Path.Combine(SentDir, Path.GetFileName(path)), overwrite: true);
    }
}
