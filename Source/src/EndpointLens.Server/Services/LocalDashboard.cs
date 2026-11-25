using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Data.Sqlite;

namespace EndpointLens.Server.Services;

public sealed class LocalDashboard(bool enabled)
{
    public bool Enabled { get; } = enabled;
    internal SemaphoreSlim AuditGate { get; } = new(1, 1);

    internal static bool Requested(string[] args) =>
        OperatingSystem.IsWindows() &&
        (args.Contains("--local", StringComparer.Ordinal) ||
            (args.Length == 0 && string.Equals(
                Path.GetFileName(Environment.ProcessPath), "EndpointLens.exe",
                StringComparison.OrdinalIgnoreCase)));

    internal static string ConnectionString()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "EndpointLens", "Dashboard");
        Directory.CreateDirectory(dir);
        return new SqliteConnectionStringBuilder { DataSource = Path.Combine(dir, "local.db") }.ToString();
    }

    internal static bool IsLocalRequest(HttpContext context)
    {
        var address = context.Connection.LocalIpAddress;
        var peer = context.Connection.RemoteIpAddress;
        return address is { AddressFamily: AddressFamily.InterNetwork } &&
            IPAddress.IsLoopback(address) && peer is not null && IPAddress.IsLoopback(peer) &&
            context.Request.Host.Host == "127.0.0.1" &&
            context.Request.Host.Port == context.Connection.LocalPort;
    }

    internal static void OpenBrowser(string url)
    {
        Console.WriteLine($"EndpointLens local dashboard: {url}");
        Console.WriteLine("Keep this window open while auditing. Press Ctrl+C to exit.");
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            Console.WriteLine("Open the address above in your browser.");
        }
    }
}
