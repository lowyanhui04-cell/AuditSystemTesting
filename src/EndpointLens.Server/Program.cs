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

var builder = WebApplication.CreateBuilder(args);

// Database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(
        builder.Configuration.GetConnectionString("Default")
        ?? "Data Source=endpointlens.db"));

// Application services
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<RuleEngine>();

builder.Services.AddSingleton<
    IPasswordHasher<AdminUser>,
    PasswordHasher<AdminUser>>();

builder.Services.AddScoped<AuditIngestion>();

// Administrator authentication
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";

        options.Cookie.Name = "EndpointLens.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
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
}

// On Render, set ASPNETCORE_FORWARDEDHEADERS_ENABLED=true.
// ASP.NET Core then enables forwarded-header processing automatically,
// before the middleware below.

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";

    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "frame-ancestors 'none'";

    await next();
});

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

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

            "json" => Results.File(
                System.Text.Encoding.UTF8.GetBytes(
                    Exports.AuditJson(audit)),
                "application/json",
                baseName + ".json"),

            _ => Results.NotFound()
        };
    })
    .RequireAuthorization();

app.Run();

public partial class Program;