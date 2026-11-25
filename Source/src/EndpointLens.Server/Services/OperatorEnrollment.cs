using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using EndpointLens.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Win32;

namespace EndpointLens.Server.Services;

public sealed class OperatorEnrollment(IConfiguration config)
{
    private readonly AdminUser _operator = new()
    {
        UserName = config["AuditOperator:UserName"] ?? "audit-admin"
    };
    private readonly PasswordHasher<AdminUser> _hasher = new();
    private readonly string? _password = config["AuditOperator:Password"];

    public bool Enabled => _password is { Length: >= 12 and <= 128 };

    private string? _hash;
    public bool Authenticate(string user, string password)
    {
        if (!Enabled || user.Length > 80 || password.Length > 128) return false;
        var hash = LazyInitializer.EnsureInitialized(ref _hash, () => _hasher.HashPassword(_operator, _password!));
        var verified = _hasher.VerifyHashedPassword(_operator, hash, password);
        return verified != PasswordVerificationResult.Failed &&
            string.Equals(user, _operator.UserName, StringComparison.Ordinal);
    }

    public static async Task<IResult> EnrollAsync(
        OperatorLogin input, HttpRequest request, LocalDashboard mode, OperatorEnrollment auth,
        AppDbContext db, TimeProvider clock, CancellationToken ct)
    {
        if (mode.Enabled || !auth.Enabled) return Results.NotFound();
        if (!request.IsHttps || input.UserName is null || input.Password is null ||
            !auth.Authenticate(input.UserName, input.Password))
            return Results.Unauthorized();
        if (input.DeviceKey is not { Length: 64 } || !input.DeviceKey.All(Uri.IsHexDigit) ||
            input.Hostname is not { Length: > 0 and <= 63 } ||
            !input.Hostname.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            return Results.BadRequest();

        var key = input.DeviceKey.ToUpperInvariant();
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var registration = await db.EndpointDevices.Include(d => d.Endpoint)
            .SingleOrDefaultAsync(d => d.DeviceKey == key, ct);
        if (registration is null)
        {
            var name = input.Hostname;
            if (await db.Endpoints.AnyAsync(e => e.Name == name, ct))
                name = $"{name} [{key}]";

            registration = new EndpointDevice
            {
                DeviceKey = key,
                Endpoint = new Data.Endpoint { Name = name, CreatedAtUtc = clock.GetUtcNow() }
            };
            db.EndpointDevices.Add(registration);
            await db.SaveChangesAsync(ct);
        }
        if (registration.Endpoint.Revoked) return Results.StatusCode(StatusCodes.Status403Forbidden);
        var (token, hash) = EndpointCredentials.Generate(registration.Endpoint.Id);
        registration.Endpoint.TokenHash = hash;
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);

        request.HttpContext.Response.Headers.CacheControl = "no-store";
        return Results.Ok(new OperatorSession(registration.Endpoint.Id, token));
    }
}

public sealed record OperatorLogin(string? UserName, string? Password, string? DeviceKey, string? Hostname);
internal sealed record OperatorSession(int EndpointId, string Credential);

public sealed class LocalEnrollment
{
    internal UploadSetup? Current { get; set; }
    public string? Address { get; }
    public bool Managed => Address is not null;

    public LocalEnrollment(LocalDashboard mode, IConfiguration config)
    {
        if (!mode.Enabled) return;
        Current = UploadSetup.Load(AppContext.BaseDirectory);
        if (Current is null && Uri.TryCreate(config["Company:CentralAddress"], UriKind.Absolute, out var uri) &&
            uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0)
            Address = uri.GetLeftPart(UriPartial.Authority);
    }

    [SupportedOSPlatform("windows")]
    internal async Task<UploadSetup?> SignInAsync(string user, string password, CancellationToken ct)
    {
        using var registry = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var crypto = registry.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        var machine = crypto?.GetValue("MachineGuid") as string;
        if (string.IsNullOrWhiteSpace(machine)) return null;

        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("EndpointLens:" + machine.Trim().ToUpperInvariant())));
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(15) };
        using var result = await client.PostAsJsonAsync(
            Address + "/api/v1/enroll", new OperatorLogin(user, password, key, Environment.MachineName), ct);
        if (!result.IsSuccessStatusCode) return null;
        var session = await result.Content.ReadFromJsonAsync<OperatorSession>(ct);
        return session is { EndpointId: > 0, Credential.Length: > 0 }
            ? new UploadSetup(Address!, session.Credential, $"{Address}/{session.EndpointId}")
            : null;
    }
}
