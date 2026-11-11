using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;

namespace EndpointLens.Agent;

/// <summary>Read-only tree view of everything the agent collected, so the user can see exactly what is uploaded.</summary>
internal sealed class DataWindow : Window
{
    private static readonly Dictionary<string, string> Titles = new()
    {
        ["system"] = "Hardware & Windows",
        ["applications"] = "Installed software",
        ["currentUser"] = "Signed-in user",
        ["localAccounts"] = "Local accounts",
        ["antivirus"] = "Antivirus",
        ["firewall"] = "Firewall",
        ["securityConfig"] = "Security settings",
    };

    public DataWindow(string json)
    {
        Title = "Collected data";
        Width = 760;
        Height = 640;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = (System.Windows.Media.Brush)Application.Current.Resources["Bg"];

        var tree = new TreeView { BorderThickness = new Thickness(0), Padding = new Thickness(8), FontSize = 13 };
        var root = JsonNode.Parse(json)!.AsObject();
        foreach (var (key, value) in root)
        {
            if (value is JsonObject section && Titles.TryGetValue(key, out var title))
                tree.Items.Add(Build($"{title}  [{section["status"]}]", section["data"], expand: true));
        }

        var header = new TextBlock
        {
            Text = "This is exactly what is sent to the dashboard. No passwords, documents or browsing history are collected.",
            Margin = new Thickness(16, 14, 16, 10),
            Foreground = (System.Windows.Media.Brush)Application.Current.Resources["Muted"]
        };
        var panel = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        panel.Children.Add(header);
        panel.Children.Add(new Border { Child = tree, Margin = new Thickness(16, 0, 16, 16), BorderThickness = new Thickness(1), BorderBrush = (System.Windows.Media.Brush)Application.Current.Resources["Line"] });
        Content = panel;
    }

    private static TreeViewItem Build(string label, JsonNode? node, bool expand = false)
    {
        var item = new TreeViewItem { Header = label, IsExpanded = expand };
        switch (node)
        {
            case JsonObject obj:
                foreach (var (k, v) in obj)
                    item.Items.Add(v is JsonObject or JsonArray ? Build(k, v) : new TreeViewItem { Header = $"{k}: {v?.ToString() ?? "—"}" });
                break;
            case JsonArray arr:
                item.Header = $"{label} ({arr.Count})";
                for (int i = 0; i < arr.Count; i++)
                {
                    var name = arr[i] is JsonObject o && o["name"] is { } n ? n.ToString()
                             : arr[i] is JsonObject o2 && o2["displayName"] is { } dn ? dn.ToString() : $"#{i + 1}";
                    item.Items.Add(Build(name, arr[i]));
                }
                break;
            case null:
                item.Header = $"{label}: not available";
                break;
            default:
                item.Header = $"{label}: {node}";
                break;
        }
        return item;
    }
}
