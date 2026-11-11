using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;
using EndpointLens.Agent.Collection;
using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;

namespace EndpointLens.Agent;

internal static class Palette
{
    public static Brush Get(string key) => (Brush)Application.Current.Resources[key];

    public static (Brush Fg, Brush Bg) ForOutcome(Outcome o) => o switch
    {
        Outcome.Fail => (Get("Bad"), Get("BadSoft")),
        Outcome.Warning => (Get("Warn"), Get("WarnSoft")),
        Outcome.Pass => (Get("Good"), Get("GoodSoft")),
        _ => (Get("Neutral"), Get("NeutralSoft"))
    };

    public static string OutcomeLabel(Outcome o) => o switch
    {
        Outcome.NotApplicable => "N/A",
        _ => o.ToString().ToUpperInvariant()
    };
}

/// <summary>One line in the "What will be checked" list and the live collection list.</summary>
internal sealed class CategoryRow : INotifyPropertyChanged
{
    public CategoryRow(Category c)
    {
        Title = c.Title;
        Description = c.Description;
        Detail = c.Description;
        Icon = (c.Index + 1).ToString();
        IconFg = Palette.Get("Muted");
        IconBg = Palette.Get("NeutralSoft");
    }

    public string Title { get; }
    public string Description { get; }
    public string Detail { get; private set; }
    public string Icon { get; private set; }
    public string Duration { get; private set; } = "";
    public Brush IconFg { get; private set; }
    public Brush IconBg { get; private set; }

    public void Update(CategoryProgress p)
    {
        if (p.Status is null)
        {
            Icon = "…";
            (IconFg, IconBg) = (Palette.Get("Primary"), Palette.Get("PrimarySoft"));
            Detail = "Reading…";
        }
        else
        {
            (Icon, IconFg, IconBg) = p.Status switch
            {
                EvidenceStatus.Collected => ("✓", Palette.Get("Good"), Palette.Get("GoodSoft")),
                EvidenceStatus.Partial => ("!", Palette.Get("Warn"), Palette.Get("WarnSoft")),
                _ => ("✕", Palette.Get("Neutral"), Palette.Get("NeutralSoft"))
            };
            var prefix = p.Status switch
            {
                EvidenceStatus.Collected => "",
                EvidenceStatus.Partial => "Partly read: ",
                EvidenceStatus.AccessDenied => "Needs administrator: ",
                EvidenceStatus.TimedOut => "Took too long: ",
                _ => "Could not read: "
            };
            Detail = prefix + (p.Detail ?? "");
            Duration = p.DurationMs < 1000 ? $"{p.DurationMs} ms" : $"{p.DurationMs / 1000.0:0.0} s";
        }
        Changed(nameof(Icon), nameof(IconFg), nameof(IconBg), nameof(Detail), nameof(Duration));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed(params string[] names)
    {
        foreach (var n in names) PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }
}

/// <summary>One rule result on the Results screen.</summary>
internal sealed class FindingRow
{
    public FindingRow(RuleResult r)
    {
        Result = r;
        (OutcomeFg, OutcomeBg) = Palette.ForOutcome(r.Outcome);
        OutcomeText = Palette.OutcomeLabel(r.Outcome);
    }

    public RuleResult Result { get; }
    public string OutcomeText { get; }
    public Brush OutcomeFg { get; }
    public Brush OutcomeBg { get; }
    public string Title => Result.Title;
    public string Meta => $"{Result.RuleId} · {Result.Severity} severity · {Result.Category}";
    public string Observed => Result.Observed;
    public string Advice => Result.Outcome == Outcome.Unknown
        ? "Check this manually, or run the audit again as administrator."
        : Result.Recommendation;
    public Visibility AdviceVisibility => Result.Outcome is Outcome.Fail or Outcome.Warning or Outcome.Unknown ? Visibility.Visible : Visibility.Collapsed;
    public bool NeedsAttention => Result.Outcome is Outcome.Fail or Outcome.Warning or Outcome.Unknown;
}
