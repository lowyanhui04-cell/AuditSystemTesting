using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;
using EndpointLens.Server.Data;
using EndpointLens.Server.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

var local = new LocalDashboard(LocalDashboard.Requested(args));
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args.Where(arg => arg is not "--local" and not "--server").ToArray(),
    ContentRootPath = local.Enabled ? AppContext.BaseDirectory : null
});
builder.Services.AddSingleton(local);
builder.Services.AddSingleton<LocalEnrollment>();
builder.Services.AddSingleton<OperatorEnrollment>();
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("operator-enrollment", window =>
    {
        window.PermitLimit = 12;
        window.Window = TimeSpan.FromMinutes(1);
    });
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});
if (local.Enabled)
{
    builder.Services.AddSingleton<AutomaticUpload>();
    builder.Services.AddHostedService(services => services.GetRequiredService<AutomaticUpload>());
}
if (local.Enabled)
{
    builder.WebHost.ConfigureKestrel(options =>
    {
        // Ignore configured network endpoints for the portable Windows session.
        options.Configure(new ConfigurationBuilder().Build());
        options.Listen(IPAddress.Loopback, 0);
    });
}

// Database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(new SqliteConnectionStringBuilder(local.Enabled
        ? LocalDashboard.ConnectionString()
        : builder.Configuration.GetConnectionString("Default") ?? "Data Source=endpointlens.db")
        { ForeignKeys = true }.ToString()));

// Application services
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<RuleEngine>();

builder.Services.AddSingleton<
    IPasswordHasher<AdminUser>,
    PasswordHasher<AdminUser>>();

builder.Services.AddScoped<AuditIngestion>();
builder.Services.AddSingleton<AgentPackage>();

// Administrator authentication
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";

        options.Cookie.Name = local.Enabled ? "EndpointLens.Local.Auth" : "EndpointLens.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.IsEssential = true;
        options.Cookie.SecurePolicy = local.Enabled ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;

        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });

// Require authentication unless an endpoint explicitly allows anonymous access.
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

builder.Services.AddRazorPages(options =>
{
    options.Conventions.AllowAnonymousToFolder("/Account");
});

builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(180);
});

var app = builder.Build();

// Create the database if it does not exist.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
    if (!local.Enabled)
    {
        db.Database.ExecuteSqlRaw("""
            CREATE TABLE IF NOT EXISTS EndpointDevices (
                DeviceKey TEXT PRIMARY KEY NOT NULL,
                EndpointId INTEGER NOT NULL UNIQUE REFERENCES Endpoints(Id) ON DELETE CASCADE
            );
            """);
    }
    if (local.Enabled)
    {
        // Older local databases already exist, so EnsureCreated does not add this table.
        db.Database.ExecuteSqlRaw("""
            CREATE TABLE IF NOT EXISTS AuditUploads (
                AuditId INTEGER PRIMARY KEY REFERENCES Audits(Id) ON DELETE CASCADE,
                Destination TEXT NOT NULL,
                Attempted INTEGER NOT NULL,
                Uploaded INTEGER NOT NULL
            );
            """);
    }
}

// On Render, set ASPNETCORE_FORWARDEDHEADERS_ENABLED=true.
// ASP.NET Core then enables forwarded-header processing automatically,
// before the middleware below.

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    if (!local.Enabled) app.UseHsts();
}

if (local.Enabled)
{
    app.Use(async (context, next) =>
    {
        if (!LocalDashboard.IsLocalRequest(context))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        await next();
    });
}
else
{
    app.UseHttpsRedirection();
}

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Cache-Control"] = "no-store";

    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "frame-ancestors 'none'";

    await next();
});

app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapPost("/api/v1/enroll", OperatorEnrollment.EnrollAsync)
    .AllowAnonymous()
    .RequireRateLimiting("operator-enrollment")
    .WithMetadata(new RequestSizeLimitAttribute(4096));
app.MapGet("/css/site.css", () => Results.Stream(
    typeof(Program).Assembly.GetManifestResourceStream("EndpointLens.site.css")!,
    "text/css; charset=utf-8")).AllowAnonymous();
app.MapGet("/scripts/audit.js", () => Results.Stream(
    typeof(Program).Assembly.GetManifestResourceStream("EndpointLens.audit.js")!,
    "text/javascript; charset=utf-8")).RequireAuthorization();

// Endpoint submission API.
// Uses an endpoint credential instead of the administrator login cookie.
app.MapPost(
    "/api/v1/snapshots",
    async (
        HttpRequest request,
        AppDbContext db,
        AuditIngestion ingestion,
        CancellationToken ct) =>
    {
        if (!request.IsHttps)
        {
            return Results.Problem(
                "HTTPS is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var endpoint = await EndpointCredentials.AuthenticateAsync(
            db,
            request.Headers.Authorization.ToString(),
            ct);

        if (endpoint is null)
        {
            return Results.Unauthorized();
        }

        if (request.ContentType?.StartsWith(
                "application/json",
                StringComparison.OrdinalIgnoreCase) != true)
        {
            return Results.Problem(
                "Content-Type must be application/json.",
                statusCode: StatusCodes.Status415UnsupportedMediaType);
        }

        AuditSnapshot? snapshot;

        try
        {
            snapshot = await SnapshotJson.DeserializeAsync(
                request.Body,
                ct);
        }
        catch (JsonException ex)
        {
            return Results.BadRequest(new
            {
                errors = new[]
                {
                    "Malformed JSON: " + ex.Message
                }
            });
        }

        var result = await ingestion.IngestAsync(
            endpoint,
            snapshot,
            "agent",
            ct);

        return result.Status switch
        {
            IngestStatus.Created => Results.Created(
                $"/Audits/Details/{result.AuditId}",
                new
                {
                    auditId = result.AuditId,
                    ruleSetVersion = result.Evaluation!.RuleSetVersion,
                    score = result.Evaluation.Score,
                    coverage = result.Evaluation.Coverage,
                    riskLevel = result.Evaluation.RiskLevel
                }),

            IngestStatus.Duplicate => Results.Ok(new
            {
                auditId = result.AuditId,
                duplicate = true
            }),

            IngestStatus.Conflict => Results.Conflict(new
            {
                errors = result.Errors
            }),

            _ => Results.BadRequest(new
            {
                errors = result.Errors
            })
        };
    })
    .AllowAnonymous()
    .DisableAntiforgery()
    .WithMetadata(new RequestSizeLimitAttribute(5 * 1024 * 1024));

// Allows the agent to test its server address and endpoint credential.
app.MapGet(
    "/api/v1/whoami",
    async (
        HttpRequest request,
        AppDbContext db,
        CancellationToken ct) =>
    {
        if (!request.IsHttps)
        {
            return Results.Problem(
                "HTTPS is required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var endpoint = await EndpointCredentials.AuthenticateAsync(
            db,
            request.Headers.Authorization.ToString(),
            ct);

        return endpoint is null
            ? Results.Unauthorized()
            : Results.Ok(new
            {
                name = endpoint.Name
            });
    })
    .AllowAnonymous();

// Authenticated audit exports
app.MapGet(
    "/audits/{id:int}/export/{format}",
    async (
        int id,
        string format,
        AppDbContext db) =>
    {
        var audit = await db.Audits
            .AsNoTracking()
            .Include(a => a.Endpoint)
            .Include(a => a.Findings)
            .FirstOrDefaultAsync(a => a.Id == id);

        if (audit is null)
        {
            return Results.NotFound();
        }

        var baseName =
            $"endpointlens_{audit.Endpoint?.Name}_" +
            $"{audit.CollectedAtUtc:yyyyMMdd_HHmmss}";

        return format switch
        {
            "csv" => Results.File(
                System.Text.Encoding.UTF8.GetBytes(
                    Exports.FindingsCsv(audit)),
                "text/csv",
                baseName + ".csv"),

            "snapshot" => Results.File(
                System.Text.Encoding.UTF8.GetBytes(audit.SnapshotJson),
                "application/json",
                baseName + "_snapshot.json"),

            "json" => Results.File(
                System.Text.Encoding.UTF8.GetBytes(
                    Exports.AuditJson(audit)),
                "application/json",
                baseName + ".json"),

            _ => Results.NotFound()
        };
    })
    .RequireAuthorization();

if (local.Enabled)
{
    await app.StartAsync();
    var addresses = app.Services.GetRequiredService<IServer>()
        .Features.Get<IServerAddressesFeature>()!.Addresses;
    LocalDashboard.OpenBrowser(addresses.Single());
    await app.WaitForShutdownAsync();
}
else
{
    await app.RunAsync();
}

public partial class Program;