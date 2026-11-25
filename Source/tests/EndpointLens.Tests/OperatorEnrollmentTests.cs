using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Mvc.Testing;

namespace EndpointLens.Tests;

public class OperatorEnrollmentTests : IClassFixture<ServerFactory>
{
    private readonly ServerFactory _factory;

    public OperatorEnrollmentTests(ServerFactory factory) => _factory = factory;

    [Fact]
    public async Task Authorized_operator_reuses_endpoint_for_the_same_device()
    {
        const string password = "Test-operator-password-17";
        await using var configured = _factory.WithWebHostBuilder(builder =>
            builder.UseSetting("AuditOperator:Password", password));
        using var client = configured.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        const string path = "/api/v1/enroll";
        var login = new OperatorLogin("audit-admin", password, new string('A', 64), "DESK-ONE");
        using var unauthorized = await client.PostAsJsonAsync(path, login with { Password = "wrong" });
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        using var first = await client.PostAsJsonAsync(path, login);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var next = await client.PostAsJsonAsync(path, login with { Hostname = "DESK-RENAMED" });
        Assert.Equal(HttpStatusCode.OK, next.StatusCode);

        var original = await first.Content.ReadFromJsonAsync<JsonElement>();
        var repeated = await next.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(original.GetProperty("endpointId").GetInt32(), repeated.GetProperty("endpointId").GetInt32());
        Assert.NotEqual(original.GetProperty("credential").GetString(), repeated.GetProperty("credential").GetString());
        Assert.Equal(HttpStatusCode.Redirect, (await client.GetAsync("/")).StatusCode);
    }
}
