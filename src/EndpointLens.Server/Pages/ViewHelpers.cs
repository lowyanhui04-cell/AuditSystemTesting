using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;

namespace EndpointLens.Server.Pages;

public sealed record RingModel(double? Score, string Size = "");

public sealed record EvidenceTabModel(AuditSnapshot Snapshot, string Tab);

public static class ViewHelpers
{
    public static readonly (string Key, string Label)[] EvidenceTabs =
    {
        ("hardware", "Hardware & Windows"),
        ("software", "Software"),
        ("accounts", "Users & accounts"),
        ("security", "Security settings"),
    };

    public static string Utc(DateTimeOffset? d) => d is null ? "—" : d.Value.UtcDateTime.ToString("d MMM yyyy, HH:mm 'UTC'");

    public static string Ago(DateTimeOffset? d, DateTimeOffset now)
    {
        if (d is null) return "never";
        var span = now - d.Value;
        if (span.TotalMinutes < 1) return "just now";
        if (span.TotalMinutes < 60) return $"{(int)span.TotalMinutes} min ago";
        if (span.TotalHours < 24) return $"{(int)span.TotalHours} h ago";
        if (span.TotalDays < 30) return $"{(int)span.TotalDays} day{((int)span.TotalDays == 1 ? "" : "s")} ago";
        return d.Value.UtcDateTime.ToString("d MMM yyyy");
    }

    public static string Bytes(long? b)
    {
        if (b is null) return "—";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = b.Value;
        int i = 0;
        while (v >= 1024 && i < units.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {units[i]}";
    }

    public static string YesNo(bool? b) => b is null ? "Unknown" : b.Value ? "Yes" : "No";
    public static string OnOff(bool? b) => b is null ? "Unknown" : b.Value ? "On" : "Off";

    public static string Score(double? s) => s is null ? "–" : s.Value.ToString("0");

    public static string ScoreColor(double? s) => s switch
    {
        null => "var(--neutral)",
        >= 85 => "var(--good)",
        >= 60 => "var(--warn)",
        _ => "var(--bad)"
    };

    public static string RingStyle(double? s) => $"--p:{(s ?? 0):0.#};--c:{ScoreColor(s)}";

    public static string OutcomeLabel(Outcome o) => o == Outcome.NotApplicable ? "N/A" : o.ToString().ToUpperInvariant();
    public static string OutcomeClass(Outcome o) => "badge o-" + o.ToString().ToLowerInvariant();
    public static string SeverityClass(Severity s) => "badge s-" + s.ToString().ToLowerInvariant();
    public static string RiskClass(string? risk) => "badge r-" + (risk ?? "none").ToLowerInvariant();
    public static string RiskLabel(string? risk) => risk switch
    {
        null or "" => "No data",
        "Incomplete" => "Not enough data",
        _ => risk + " risk"
    };

    public static string Plural(int n, string word) => $"{n} {word}{(n == 1 ? "" : "s")}";
}
