using System.Net;
using System.Net.Http.Headers;
using System.Text;
using EndpointLens.Core.Snapshot;
using EndpointLens.Server.Data;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using static EndpointLens.Tests.TestSnapshots;

namespace EndpointLens.Tests;

public sealed class ServerFactory : WebApplicationFactory<Program>
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"el-test-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder) =>
        builder.UseSetting("ConnectionStrings:Default", $"Data Source={_dbPath};Pooling=False");

    public async Task<(int Id, string Token)> EnrollAsync(string name)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var e = new Endpoint { Name = name, CreatedAtUtc = DateTimeOffset.UtcNow, TokenHash = "pending" };
        db.Endpoints.Add(e);
        await db.SaveChangesAsync();
        var (token, hash) = EndpointCredentials.Generate(e.Id);
        e.TokenHash = hash;
        await db.SaveChangesAsync();
        return (e.Id, token);
    }

    public async Task<T> QueryAsync<T>(Func<AppDbContext, Task<T>> q)
    {
        using var scope = Services.CreateScope();
        return await q(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }
}

public class ApiTests : IClassFixture<ServerFactory>
{
    private readonly ServerFactory _factory;
    private readonly HttpClient _client;

    public ApiTests(ServerFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });
    }

    private static AuditSnapshot Fresh() => With(s => s.CollectedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1));

    private Task<HttpResponseMessage> PostAsync(string? token, string body)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/snapshots") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (token is not null) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return _client.SendAsync(req);
    }

    [Fact]
    public async Task Valid_submission_is_stored_with_findings()
    {
        var (id, token) = await _factory.EnrollAsync("api-valid");
        var snap = Fresh();
        var resp = await PostAsync(token, SnapshotJson.Serialize(snap));
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);

        var audit = await _factory.QueryAsync(db => db.Audits.Include(a => a.Findings).SingleAsync(a => a.SnapshotId == snap.SnapshotId));
        Assert.Equal(id, audit.EndpointId);
        Assert.Equal(11, audit.Findings.Count);
        Assert.Equal(100, audit.Score);
    }

    [Fact]
    public async Task Duplicate_submission_is_idempotent()
    {
        var (_, token) = await _factory.EnrollAsync("api-dup");
        var json = SnapshotJson.Serialize(Fresh());
        Assert.Equal(HttpStatusCode.Created, (await PostAsync(token, json)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(token, json)).StatusCode);

        var snap = SnapshotJson.Deserialize(json)!;
        Assert.Equal(1, await _factory.QueryAsync(db => db.Audits.CountAsync(a => a.SnapshotId == snap.SnapshotId)));
    }

    [Fact]
    public async Task Same_snapshot_from_other_endpoint_conflicts()
    {
        var (_, t1) = await _factory.EnrollAsync("api-c1");
        var (_, t2) = await _factory.EnrollAsync("api-c2");
        var json = SnapshotJson.Serialize(Fresh());
        await PostAsync(t1, json);
        Assert.Equal(HttpStatusCode.Conflict, (await PostAsync(t2, json)).StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("garbage")]
    [InlineData("el_1_wrongsecret")]
    public async Task Invalid_credentials_are_rejected(string? token) =>
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(token, SnapshotJson.Serialize(Fresh()))).StatusCode);

    [Fact]
    public async Task Credential_for_one_endpoint_cannot_be_reused_with_another_id()
    {
        var (_, token) = await _factory.EnrollAsync("api-scope");
        var (otherId, _) = await _factory.EnrollAsync("api-scope-2");
        var forged = $"el_{otherId}_{token.Split('_', 3)[2]}";
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(forged, SnapshotJson.Serialize(Fresh()))).StatusCode);
    }

    [Fact]
    public async Task Revoked_endpoint_is_rejected()
    {
        var (id, token) = await _factory.EnrollAsync("api-revoked");
        await _factory.QueryAsync(async db =>
        {
            var e = await db.Endpoints.FindAsync(id);
            e!.Revoked = true;
            return await db.SaveChangesAsync();
        });
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(token, SnapshotJson.Serialize(Fresh()))).StatusCode);
    }

    [Fact]
    public async Task Whoami_returns_endpoint_name_only_for_valid_credential()
    {
        var (_, token) = await _factory.EnrollAsync("api-whoami");
        var ok = new HttpRequestMessage(HttpMethod.Get, "/api/v1/whoami");
        ok.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var resp = await _client.SendAsync(ok);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("api-whoami", await resp.Content.ReadAsStringAsync());

        var bad = new HttpRequestMessage(HttpMethod.Get, "/api/v1/whoami");
        bad.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "el_1_nope");
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.SendAsync(bad)).StatusCode);
    }

    [Fact]
    public async Task Malformed_json_is_rejected()
    {
        var (_, token) = await _factory.EnrollAsync("api-malformed");
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(token, "{ not json")).StatusCode);
    }

    [Fact]
    public async Task Invalid_snapshot_is_rejected()
    {
        var (_, token) = await _factory.EnrollAsync("api-invalid");
        var snap = With(s => { s.SnapshotId = Guid.Empty; s.CollectedAtUtc = DateTimeOffset.UtcNow; });
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(token, SnapshotJson.Serialize(snap))).StatusCode);
    }

    [Fact]
    public async Task Endpoint_credential_does_not_grant_dashboard_access()
    {
        var (_, token) = await _factory.EnrollAsync("api-dashboard");
        var req = new HttpRequestMessage(HttpMethod.Get, "/");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var resp = await _client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Contains("/Account/Login", resp.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/Findings")]
    [InlineData("/Rules")]
    [InlineData("/Import")]
    [InlineData("/Audits/Report/1")]
    [InlineData("/audits/1/export/csv")]
    public async Task Dashboard_and_reports_require_login(string path)
    {
        var resp = await _client.GetAsync(path);
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Contains("/Account/Login", resp.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Plain_http_submission_is_refused()
    {
        var http = _factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("http://localhost"), AllowAutoRedirect = false });
        var resp = await http.PostAsync("/api/v1/snapshots", new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.NotEqual(HttpStatusCode.Created, resp.StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }
}
