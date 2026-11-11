using System.Text.Json;
using System.Text.Json.Serialization;

namespace EndpointLens.Core.Snapshot;

public static class SnapshotJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 16
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);

    public static AuditSnapshot? Deserialize(string json) => JsonSerializer.Deserialize<AuditSnapshot>(json, Options);

    public static ValueTask<AuditSnapshot?> DeserializeAsync(Stream stream, CancellationToken ct = default) =>
        JsonSerializer.DeserializeAsync<AuditSnapshot>(stream, Options, ct);
}
