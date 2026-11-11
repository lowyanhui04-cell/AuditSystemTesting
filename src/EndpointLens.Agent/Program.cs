using System.Runtime.InteropServices;
using EndpointLens.Agent.Collection;
using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;

namespace EndpointLens.Agent;

internal static class Program
{
    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int processId);

    /// <summary>
    /// Window by default. Command line: EndpointLens.Agent.exe --collect &lt;output.json&gt;
    /// writes a snapshot without opening the window (useful for testing and manual import).
    /// </summary>
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length >= 2 && args[0] == "--collect")
        {
            AttachConsole(-1);
            var progress = new Progress<CategoryProgress>(p =>
            {
                if (p.Status is { } st) Console.WriteLine($"  {p.Category.Title}: {st} ({p.DurationMs} ms){(p.Detail is null ? "" : " - " + p.Detail)}");
            });
            var snapshot = SnapshotCollector.Collect(progress);
            File.WriteAllText(args[1], SnapshotJson.Serialize(snapshot));
            var eval = new RuleEngine().Evaluate(snapshot);
            Console.WriteLine($"Snapshot {snapshot.SnapshotId} written to {Path.GetFullPath(args[1])}");
            foreach (var r in eval.Results)
                Console.WriteLine($"  {r.RuleId,-8} {r.Outcome,-13} {r.Severity,-6} {r.Observed}");
            Console.WriteLine($"Preview score {eval.Score?.ToString("0.0") ?? "n/a"}, coverage {eval.Coverage:P0}, risk {eval.RiskLevel}");
            return 0;
        }

        var app = new App();
        app.InitializeComponent();
        return app.Run(new MainWindow());
    }
}
