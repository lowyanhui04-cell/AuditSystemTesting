using System.Diagnostics;
using EndpointLens.Core.Snapshot;

namespace EndpointLens.Agent.Collection;

/// <summary>
/// Runs one collector with a timeout and converts its outcome into an explicit evidence status.
/// Collectors call <c>warn</c> for sub-probes that failed; the section is then marked Partial.
/// </summary>
internal static class CollectorRunner
{
    public static EvidenceSection<T> Run<T>(Func<Action<string>, T> collect, TimeSpan timeout) where T : class
    {
        var sw = Stopwatch.StartNew();
        var warnings = new List<string>();
        void Warn(string w) { lock (warnings) warnings.Add(w); }

        var task = Task.Run(() => collect(Warn));
        try
        {
            if (!task.Wait(timeout))
                return new EvidenceSection<T> { Status = EvidenceStatus.TimedOut, Error = $"Collection exceeded {timeout.TotalSeconds:0}s.", DurationMs = sw.ElapsedMilliseconds };

            string[] w;
            lock (warnings) w = warnings.ToArray();
            return new EvidenceSection<T>
            {
                Data = task.Result,
                Status = w.Length > 0 ? EvidenceStatus.Partial : EvidenceStatus.Collected,
                Error = w.Length > 0 ? string.Join(" | ", w) : null,
                DurationMs = sw.ElapsedMilliseconds
            };
        }
        catch (AggregateException ae)
        {
            var ex = ae.GetBaseException();
            var status = Wmi.IsAccessDenied(ex) ? EvidenceStatus.AccessDenied
                : Wmi.IsNotSupported(ex) ? EvidenceStatus.NotSupported
                : EvidenceStatus.Failed;
            return new EvidenceSection<T> { Status = status, Error = ex.Message, DurationMs = sw.ElapsedMilliseconds };
        }
    }

    /// <summary>Runs a sub-probe; on failure records a warning and returns default.</summary>
    public static TValue? Probe<TValue>(string name, Action<string> warn, Func<TValue?> probe)
    {
        try { return probe(); }
        catch (Exception ex)
        {
            var kind = Wmi.IsAccessDenied(ex) ? "access denied" : ex.Message;
            warn($"{name}: {kind}");
            return default;
        }
    }
}
