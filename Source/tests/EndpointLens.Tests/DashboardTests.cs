using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using EndpointLens.Core.Snapshot;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using static EndpointLens.Tests.TestSnapshots;

namespace EndpointLens.Tests;

/// <summary>End-to-end through the dashboard: first-run setup, sign-in, submission, every page and export.</summary>
public class DashboardTests : IClassFixture<ServerFactory>
{
    private const string Password = "Correct-Horse-42!";
    private readonly ServerFactory _factory;
    private readonly HttpClient _client;

    public DashboardTests(ServerFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
    }

    private static string Antiforgery(string html) =>
        Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;

    private async Task<HttpResponseMessage> PostFormAsync(string path, Dictionary<string, string> fields)
    {
        var page = await _client.GetStringAsync(path);
        fields["__RequestVerificationToken"] = Antiforgery(page);
        return await _client.PostAsync(path, new FormUrlEncodedContent(fields));
    }

    private async Task SignInAsync()
    {
        // Setup only exists until the first administrator is created (tests in this class share one server).
        if ((await _client.GetAsync("/Account/Setup")).StatusCode == HttpStatusCode.OK)
            await PostFormAsync("/Account/Setup", new() { ["UserName"] = "admin", ["Password"] = Password, ["ConfirmPassword"] = Password });
        var resp = await PostFormAsync("/Account/Login", new() { ["UserName"] = "admin", ["Password"] = Password });
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
    }

    [Fact]
    public async Task Super_admin_can_confirm_and_delete_endpoint_with_its_audit_history()
    {
        await SignInAsync();
        var (id, credential) = await _factory.EnrollAsync("DELETE-PC");
        var snapshot = With(s => s.CollectedAtUtc = DateTimeOffset.UtcNow);
        using var upload = new HttpRequestMessage(HttpMethod.Post, "/api/v1/snapshots")
        {
            Content = new StringContent(SnapshotJson.Serialize(snapshot), Encoding.UTF8, "application/json")
        };
        upload.Headers.Authorization = new AuthenticationHeaderValue("Bearer", credential);
        Assert.Equal(HttpStatusCode.Created, (await _client.SendAsync(upload)).StatusCode);

        var page = $"/Endpoints/Delete/{id}";
        Assert.Contains("DELETE-PC", await _client.GetStringAsync(page));
        Assert.True(await _factory.QueryAsync(db => db.Endpoints.AnyAsync(e => e.Id == id)));
        Assert.Equal(HttpStatusCode.Redirect, (await PostFormAsync(page, new())).StatusCode);
        Assert.False(await _factory.QueryAsync(db => db.Endpoints.AnyAsync(e => e.Id == id)));
        Assert.False(await _factory.QueryAsync(db => db.Audits.AnyAsync(a => a.SnapshotId == snapshot.SnapshotId)));
    }

    [Fact]
    public async Task Full_workflow_renders_every_page_and_escapes_endpoint_data()
    {
        await SignInAsync();

        var (endpointId, token) = await _factory.EnrollAsync("LAB-PC-01");
        var snap = With(s =>
        {
            s.CollectedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-2);
            s.System.Data!.Hostname = "<script>alert(1)</script>";
            s.Firewall.Data!.Profiles[2].Enabled = false;
            s.SecurityConfig.Data!.SystemDriveBitLocker = null;
        });
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/snapshots") { Content = new StringContent(SnapshotJson.Serialize(snap), Encoding.UTF8, "application/json") };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert.Equal(HttpStatusCode.Created, (await _client.SendAsync(req)).StatusCode);
        var auditId = await _factory.QueryAsync(db => db.Audits.Where(a => a.SnapshotId == snap.SnapshotId).Select(a => a.Id).SingleAsync());

        var pages = new Dictionary<string, string[]>
        {
            ["/"] = new[] { "LAB-PC-01", "High risk", "Most common failures" },
            [$"/Endpoints/Details/{endpointId}"] = new[] { "Security score", "FW-001", "What to do" },
            [$"/Endpoints/Details/{endpointId}?tab=hardware"] = new[] { "Processor", "Disks", "WD Blue SN5000 2TB", "NVMe", "DDR4 SODIMM", "3200 MT/s", "M471A5244CB0-CWE", "1 of 2 slots used" },
            [$"/Endpoints/Details/{endpointId}?tab=software"] = new[] { "Installed software", "7-Zip" },
            [$"/Endpoints/Details/{endpointId}?tab=accounts"] = new[] { "Password policy", "Built-in Guest" },
            [$"/Endpoints/Details/{endpointId}?tab=security"] = new[] { "Firewall service", "BitLocker" },
            [$"/Endpoints/Details/{endpointId}?tab=history"] = new[] { "Signed-in user" },
            [$"/Endpoints/Details/{endpointId}?tab=settings"] = new[] { "Create new credential" },
            [$"/Audits/Details/{auditId}"] = new[] { "FW-001", "FAIL", "UNKNOWN", "Export CSV" },
            [$"/Audits/Details/{auditId}?outcome=Fail"] = new[] { "FW-001" },
            [$"/Audits/Details/{auditId}?tab=security"] = new[] { "Firewall service" },
            [$"/Audits/Report/{auditId}"] = new[] { "Findings requiring action", "Public", "WD Blue SN5000 2TB", "M471A5244CB0-CWE", "7-Zip", "Scope and limitations" },
            ["/Findings"] = new[] { "FW-001" },
            ["/Findings?show=all&severity=High"] = new[] { "FW-001" },
            ["/Rules"] = new[] { "SMB-001", "Security rules" },
            ["/Import"] = new[] { "Import audit file" },
            ["/Endpoints/Enroll"] = new[] { "Enroll computer" },
            ["/Agent"] = new[] { "Download agent", "Extract All" },
            [$"/Endpoints/Details/{endpointId}?tab=agent"] = new[] { "Download agent (.zip)", "Extract All" },
        };
        foreach (var (path, expected) in pages)
        {
            var resp = await _client.GetAsync(path);
            Assert.True(resp.StatusCode == HttpStatusCode.OK, $"{path} returned {resp.StatusCode}");
            var html = await resp.Content.ReadAsStringAsync();
            foreach (var text in expected) Assert.True(html.Contains(text), $"{path} is missing '{text}'");
            Assert.DoesNotContain("<script>alert(1)</script>", html);
        }

        var filtered = await _client.GetStringAsync($"/Audits/Details/{auditId}?outcome=Pass");
        Assert.DoesNotContain("Disabled profile(s)", filtered);

        var csv = await _client.GetAsync($"/audits/{auditId}/export/csv");
        Assert.Equal("text/csv", csv.Content.Headers.ContentType!.MediaType);
        Assert.Equal(12, (await csv.Content.ReadAsStringAsync()).Trim().Split('\n').Length); // header + 11 rules

        var json = await _client.GetStringAsync($"/audits/{auditId}/export/json");
        Assert.Contains("\"ruleSetVersion\"", json);

        var exported = await _client.GetStringAsync($"/audits/{auditId}/export/snapshot");
        Assert.Equal(snap.SnapshotId, SnapshotJson.Deserialize(exported)?.SnapshotId);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync("/LocalAudit")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync($"/Audits/Submit/{auditId}")).StatusCode);

        var download = await _client.GetAsync($"/Audits/Report/{auditId}?download=true");
        Assert.Equal("attachment", download.Content.Headers.ContentDisposition?.DispositionType ?? download.Headers.GetValues("Content-Disposition").First().Split(';')[0]);
    }

    [Fact]
    public async Task Download_agent_returns_zip_with_a_working_fresh_credential()
    {
        await SignInAsync();
        var (endpointId, oldToken) = await _factory.EnrollAsync("DL-PC-01");

        var page = await _client.GetStringAsync($"/Endpoints/Details/{endpointId}?tab=agent");
        Assert.Contains("Download agent (.zip)", page);
        var resp = await _client.PostAsync($"/Endpoints/Details/{endpointId}?handler=DownloadAgent",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = Antiforgery(page) }));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/zip", resp.Content.Headers.ContentType!.MediaType);

        using var zip = new System.IO.Compression.ZipArchive(await resp.Content.ReadAsStreamAsync());
        Assert.Contains(zip.Entries, e => e.Name == "EndpointLens.exe");
        var setupEntry = zip.Entries.Single(e => e.Name == "endpointlens-setup.json");
        using var setup = System.Text.Json.JsonDocument.Parse(setupEntry.Open());
        Assert.Equal("DL-PC-01", setup.RootElement.GetProperty("endpointName").GetString());
        Assert.StartsWith("https://", setup.RootElement.GetProperty("serverUrl").GetString());
        var newToken = setup.RootElement.GetProperty("credential").GetString()!;

        async Task<HttpStatusCode> WhoAmI(string token)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/whoami");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return (await _client.SendAsync(req)).StatusCode;
        }
        Assert.Equal(HttpStatusCode.OK, await WhoAmI(newToken));
        Assert.Equal(HttpStatusCode.Unauthorized, await WhoAmI(oldToken)); // each download replaces the credential
    }

    [Fact]
    public async Task One_click_download_adds_computer_named_after_first_audit()
    {
        await SignInAsync();
        var page = await _client.GetStringAsync("/Agent");
        Assert.Contains("Download agent", page);
        var resp = await _client.PostAsync("/Agent", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = Antiforgery(page) }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var zip = new System.IO.Compression.ZipArchive(await resp.Content.ReadAsStreamAsync());
        using var setup = System.Text.Json.JsonDocument.Parse(zip.Entries.Single(e => e.Name == "endpointlens-setup.json").Open());
        var token = setup.RootElement.GetProperty("credential").GetString()!;
        Assert.StartsWith("New computer ", setup.RootElement.GetProperty("endpointName").GetString());

        var snap = With(s => { s.CollectedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1); s.System.Data!.Hostname = "QUICK-PC-77"; });
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/snapshots") { Content = new StringContent(SnapshotJson.Serialize(snap), Encoding.UTF8, "application/json") };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert.Equal(HttpStatusCode.Created, (await _client.SendAsync(req)).StatusCode);

        Assert.Contains("QUICK-PC-77", await _client.GetStringAsync("/"));
        Assert.True(await _factory.QueryAsync(db => db.Endpoints.AnyAsync(e => e.Name == "QUICK-PC-77" && e.Notes == null)));
    }

    [Fact]
    public async Task Download_agent_requires_login_and_antiforgery()
    {
        var (endpointId, _) = await _factory.EnrollAsync("DL-PC-02");
        using var anon = _factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
        var resp = await anon.PostAsync($"/Endpoints/Details/{endpointId}?handler=DownloadAgent", new FormUrlEncodedContent(new Dictionary<string, string>()));
        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Wrong_password_is_rejected_and_setup_closes_after_first_admin()
    {
        await SignInAsync();
        using var anon = _factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });

        var setup = await anon.GetAsync("/Account/Setup");
        Assert.Equal(HttpStatusCode.Redirect, setup.StatusCode);

        var page = await anon.GetStringAsync("/Account/Login");
        var resp = await anon.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["UserName"] = "admin", ["Password"] = "wrong-password", ["__RequestVerificationToken"] = Antiforgery(page)
        }));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("Invalid user name or password", await resp.Content.ReadAsStringAsync());
    }
}
