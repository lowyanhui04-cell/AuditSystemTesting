using System.Security.Cryptography;
using System.Text;
using EndpointLens.Server.Data;
using Microsoft.EntityFrameworkCore;

namespace EndpointLens.Server.Services;

/// <summary>
/// Endpoint submission credentials have the form "el_{endpointId}_{secret}". The secret is 32 random
/// bytes; only its SHA-256 hash is stored. A credential authorizes snapshot submission for that one
/// endpoint and grants no dashboard access.
/// </summary>
public static class EndpointCredentials
{
    public static (string Token, string Hash) Generate(int endpointId)
    {
        var secret = Base64Url(RandomNumberGenerator.GetBytes(32));
        var token = $"el_{endpointId}_{secret}";
        return (token, Hash(token));
    }

    public static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    public static async Task<Data.Endpoint?> AuthenticateAsync(AppDbContext db, string? authorizationHeader, CancellationToken ct)
    {
        if (authorizationHeader is null || !authorizationHeader.StartsWith("Bearer ", StringComparison.Ordinal)) return null;
        var token = authorizationHeader["Bearer ".Length..].Trim();
        var parts = token.Split('_', 3);
        if (parts.Length != 3 || parts[0] != "el" || !int.TryParse(parts[1], out var id)) return null;

        var endpoint = await db.Endpoints.FirstOrDefaultAsync(e => e.Id == id, ct);
        if (endpoint is null || endpoint.Revoked) return null;

        var expected = Convert.FromHexString(endpoint.TokenHash);
        var actual = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return CryptographicOperations.FixedTimeEquals(expected, actual) ? endpoint : null;
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
