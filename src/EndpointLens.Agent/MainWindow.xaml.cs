using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using EndpointLens.Agent.Collection;
using EndpointLens.Core.Rules;
using EndpointLens.Core.Snapshot;
using Microsoft.Win32;

namespace EndpointLens.Agent;

public partial class MainWindow : Window
{
    private enum UploadState { NotConnected, Ready, Uploading, Uploaded, Failed }

    private readonly AgentSettings _settings = AgentSettings.Load();
    private readonly SubmissionClient _client = new();
    private readonly ObservableCollection<CategoryRow> _collectRows = new();
    private readonly ObservableCollection<FindingRow> _findingRows = new();

    private AuditSnapshot? _snapshot;
    private string? _snapshotJson;
    private string? _snapshotPath;
    private AuditEvaluation? _evaluation;
    private int? _uploadedAuditId;
    private bool? _serverReachable;

    public MainWindow()
    {
        InitializeComponent();
        Title = $"EndpointLens Agent {SnapshotCollector.AgentVersion}";
        PlanList.ItemsSource = SnapshotCollector.Categories.Select(c => new CategoryRow(c)).ToList();
        CollectList.ItemsSource = _collectRows;
        FindingsList.ItemsSource = _findingRows;

        ComputerName.Text = Environment.MachineName;
        var elevated = SnapshotCollector.IsElevated();
        AdminPill.Background = Palette.Get(elevated ? "GoodSoft" : "WarnSoft");
        AdminPillText.Foreground = Palette.Get(elevated ? "Good" : "Warn");
        AdminPillText.Text = elevated ? "Administrator" : "Standard user";
        AdminBanner.Visibility = elevated ? Visibility.Collapsed : Visibility.Visible;

        RefreshReadyInfo();
        RefreshServerState();
        ShowStep(1);
        Loaded += async (_, _) => await CheckServerQuietlyAsync();
    }

    // ---------------- Steps ----------------

    private void ShowStep(int step)
    {
        ReadyView.Visibility = step == 1 ? Visibility.Visible : Visibility.Collapsed;
        CollectView.Visibility = step == 2 ? Visibility.Visible : Visibility.Collapsed;
        ResultsView.Visibility = step == 3 ? Visibility.Visible : Visibility.Collapsed;

        void Paint(System.Windows.Controls.Border dot, System.Windows.Controls.TextBlock num, System.Windows.Controls.TextBlock text, int n)
        {
            var done = n < step;
            var current = n == step;
            dot.Background = Palette.Get(done ? "Good" : current ? "Primary" : "NeutralSoft");
            num.Foreground = done || current ? Brushes.White : Palette.Get("Muted");
            num.Text = done ? "✓" : n.ToString();
            text.Foreground = Palette.Get(current ? "Text" : "Muted");
        }
        Paint(Step1Dot, Step1Num, Step1Text, 1);
        Paint(Step2Dot, Step2Num, Step2Text, 2);
        Paint(Step3Dot, Step3Num, Step3Text, 3);
    }

    private void RefreshReadyInfo()
    {
        InfoComputer.Text = Environment.MachineName;
        InfoWindows.Text = WindowsName();
        InfoUser.Text = $"{Environment.UserDomainName}\\{Environment.UserName}";

        var last = Directory.Exists(Outbox.SentDir) ? Directory.GetFiles(Outbox.SentDir, "*.json") : Array.Empty<string>();
        var all = last.Concat(Outbox.Pending()).Select(File.GetLastWriteTime).DefaultIfEmpty().Max();
        InfoLastAudit.Text = all == default ? "Never on this PC" : all.ToString("d MMM yyyy, HH:mm");

        var pending = Outbox.Pending().Count;
        PendingBanner.Visibility = pending > 0 && HasToken ? Visibility.Visible : Visibility.Collapsed;
        PendingText.Text = $"{pending} earlier audit{(pending == 1 ? " is" : "s are")} saved on this PC and not uploaded yet.";
    }

    private static string WindowsName()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        var name = key?.GetValue("ProductName") as string ?? "Windows";
        var build = key?.GetValue("CurrentBuild") as string;
        // ProductName still says "Windows 10" on Windows 11; the build number tells them apart.
        if (int.TryParse(build, out var b) && b >= 22000) name = name.Replace("Windows 10", "Windows 11");
        var version = key?.GetValue("DisplayVersion") as string;
        return $"{name}{(version is null ? "" : " " + version)} (build {build})";
    }

    // ---------------- Audit ----------------

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        _collectRows.Clear();
        foreach (var c in SnapshotCollector.Categories) _collectRows.Add(new CategoryRow(c));
        CollectProgress.Value = 0;
        CollectCount.Text = $"0 of {_collectRows.Count}";
        ShowStep(2);

        var done = 0;
        var progress = new Progress<CategoryProgress>(p =>
        {
            _collectRows[p.Category.Index].Update(p);
            if (p.Status is not null)
            {
                done++;
                CollectProgress.Value = done;
                CollectCount.Text = $"{done} of {_collectRows.Count}";
            }
        });

        try
        {
            _snapshot = await Task.Run(() => SnapshotCollector.Collect(progress));
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "The audit could not finish: " + ex.Message, "EndpointLens", MessageBoxButton.OK, MessageBoxImage.Error);
            ShowStep(1);
            return;
        }

        _snapshotJson = SnapshotJson.Serialize(_snapshot);
        _snapshotPath = Outbox.Save(_snapshot, _snapshotJson);
        _evaluation = new RuleEngine().Evaluate(_snapshot);
        _uploadedAuditId = null;
        await Task.Delay(400); // let the last row's tick be seen
        ShowResults(_evaluation);
        ShowStep(3);

        if (HasToken) await UploadCurrentAsync();
        else SetUpload(UploadState.NotConnected);
    }

    private void ShowResults(AuditEvaluation eval)
    {
        var score = eval.Score ?? 0;
        Ring.Value = score;
        var ringKey = eval.Score is null ? "Neutral" : score >= 85 ? "Good" : score >= 60 ? "Warn" : "Bad";
        Ring.RingBrush = Palette.Get(ringKey);
        ScoreText.Text = eval.Score?.ToString("0") ?? "–";

        var (riskFg, riskBg) = eval.RiskLevel switch
        {
            "High" => ("Bad", "BadSoft"),
            "Medium" => ("Warn", "WarnSoft"),
            "Low" => ("Primary", "PrimarySoft"),
            "Minimal" => ("Good", "GoodSoft"),
            _ => ("Neutral", "NeutralSoft")
        };
        RiskPill.Background = Palette.Get(riskBg);
        RiskText.Foreground = Palette.Get(riskFg);
        RiskText.Text = eval.RiskLevel == "Incomplete" ? "Not enough data" : $"{eval.RiskLevel} risk";

        var applicable = eval.Results.Count(r => r.Outcome != Outcome.NotApplicable);
        var evaluated = eval.Results.Count(r => r.Outcome is Outcome.Pass or Outcome.Fail or Outcome.Warning);
        CoverageText.Text = $"{evaluated} of {applicable} checks had enough data ({eval.Coverage:P0} coverage)";

        FailCount.Text = eval.Count(Outcome.Fail).ToString();
        WarnCount.Text = eval.Count(Outcome.Warning).ToString();
        UnknownCount.Text = eval.Count(Outcome.Unknown).ToString();
        PassCount.Text = eval.Count(Outcome.Pass).ToString();
        RefreshFindings();
    }

    private void RefreshFindings()
    {
        if (_evaluation is null) return;
        var rows = _evaluation.Results.Select(r => new FindingRow(r)).ToList();
        var attention = rows.Count(r => r.NeedsAttention);
        var showAll = ShowPassed.IsChecked == true;

        _findingRows.Clear();
        foreach (var r in rows.Where(r => showAll || r.NeedsAttention)) _findingRows.Add(r);
        FindingsTitle.Text = showAll ? $"All {rows.Count} checks" : attention == 0 ? "No issues found" : $"{attention} check{(attention == 1 ? "" : "s")} need attention";
        AllGood.Visibility = !showAll && attention == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowPassed_Changed(object sender, RoutedEventArgs e) => RefreshFindings();

    private void RunAgain_Click(object sender, RoutedEventArgs e)
    {
        RefreshReadyInfo();
        ShowStep(1);
    }

    // ---------------- Upload ----------------

    private bool HasToken => !string.IsNullOrWhiteSpace(_settings.GetToken());

    private async void Upload_Click(object sender, RoutedEventArgs e)
    {
        if (!HasToken) { OpenSettings(); return; }
        await UploadCurrentAsync();
    }

    private async Task UploadCurrentAsync()
    {
        if (_snapshotPath is null || _snapshotJson is null) return;
        SetUpload(UploadState.Uploading);
        var result = await _client.SubmitAsync(_settings.ServerUrl, _settings.GetToken()!, _snapshotJson);
        if (result.Success)
        {
            if (File.Exists(_snapshotPath)) Outbox.MarkSent(_snapshotPath);
            _uploadedAuditId = result.AuditId;
            _serverReachable = true;
            SetUpload(UploadState.Uploaded, result.Message);
            await UploadOlderAsync();
        }
        else
        {
            SetUpload(UploadState.Failed, result.Message);
        }
        RefreshServerState();
    }

    /// <summary>Uploads earlier audits that were saved while the server was unavailable.</summary>
    private async Task<(int Sent, string? Error)> UploadOlderAsync()
    {
        var sent = 0;
        foreach (var path in Outbox.Pending())
        {
            var r = await _client.SubmitAsync(_settings.ServerUrl, _settings.GetToken()!, await File.ReadAllTextAsync(path));
            if (!r.Success) return (sent, r.Message);
            Outbox.MarkSent(path);
            sent++;
        }
        return (sent, null);
    }

    private async void UploadPending_Click(object sender, RoutedEventArgs e)
    {
        var (sent, error) = await UploadOlderAsync();
        RefreshReadyInfo();
        MessageBox.Show(this, error is null ? $"{sent} audit(s) uploaded." : $"{sent} uploaded. Stopped: {error}", "EndpointLens",
            MessageBoxButton.OK, error is null ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void SetUpload(UploadState state, string? message = null)
    {
        var (icon, fg, bg, title, detail) = state switch
        {
            UploadState.NotConnected => ("!", "Warn", "WarnSoft", "Not connected to the dashboard", "The audit is saved on this PC. Connect to upload it."),
            UploadState.Uploading => ("…", "Primary", "PrimarySoft", "Uploading…", "Sending the audit securely over HTTPS."),
            UploadState.Uploaded => ("✓", "Good", "GoodSoft", message ?? "Uploaded to the dashboard", $"Server: {_settings.ServerUrl}"),
            UploadState.Failed => ("✕", "Bad", "BadSoft", "Upload failed", (message ?? "") + " The audit is kept on this PC."),
            _ => ("•", "Neutral", "NeutralSoft", "Ready to upload", "")
        };
        UploadIcon.Background = Palette.Get(bg);
        UploadIconText.Foreground = Palette.Get(fg);
        UploadIconText.Text = icon;
        UploadTitle.Text = title;
        UploadDetail.Text = detail;

        UploadButton.Visibility = state is UploadState.Uploaded ? Visibility.Collapsed : Visibility.Visible;
        UploadButton.IsEnabled = state != UploadState.Uploading;
        UploadButton.Content = state switch
        {
            UploadState.NotConnected => "Connect to dashboard",
            UploadState.Failed => "Try again",
            _ => "Upload to dashboard"
        };
        OpenDashboardButton.Visibility = state == UploadState.Uploaded ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OpenDashboard_Click(object sender, RoutedEventArgs e)
    {
        var url = _settings.ServerUrl.TrimEnd('/') + (_uploadedAuditId is { } id ? $"/Audits/Details/{id}" : "/");
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }

    private void SaveCopy_Click(object sender, RoutedEventArgs e)
    {
        if (_snapshot is null || _snapshotJson is null) return;
        var dlg = new SaveFileDialog
        {
            Filter = "Audit file (*.json)|*.json",
            FileName = $"{Environment.MachineName}_{_snapshot.CollectedAtUtc.ToLocalTime():yyyyMMdd_HHmm}.json"
        };
        if (dlg.ShowDialog(this) != true) return;
        File.WriteAllText(dlg.FileName, _snapshotJson);
        MessageBox.Show(this, "Saved. You can upload this file on the dashboard's Import page.", "EndpointLens", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ViewData_Click(object sender, RoutedEventArgs e)
    {
        if (_snapshotJson is not null) new DataWindow(_snapshotJson) { Owner = this }.Show();
    }

    // ---------------- Server settings ----------------

    private void RefreshServerState()
    {
        if (!HasToken)
        {
            ServerDot.Fill = Palette.Get("Warn");
            ServerButtonText.Text = "Connect to dashboard";
            ServerBanner.Visibility = Visibility.Visible;
            return;
        }
        ServerBanner.Visibility = Visibility.Collapsed;
        ServerDot.Fill = Palette.Get(_serverReachable switch { true => "Good", false => "Bad", null => "Muted" });
        var host = Uri.TryCreate(_settings.ServerUrl, UriKind.Absolute, out var u) ? u.Authority : _settings.ServerUrl;
        ServerButtonText.Text = _serverReachable == false ? $"Dashboard offline · {host}" : $"Dashboard · {host}";
    }

    private async Task CheckServerQuietlyAsync()
    {
        if (!HasToken) return;
        var r = await _client.CheckConnectionAsync(_settings.ServerUrl, _settings.GetToken()!);
        _serverReachable = r.Success;
        RefreshServerState();
    }

    private void OpenSettings_Click(object sender, RoutedEventArgs e) => OpenSettings();

    private void OpenSettings()
    {
        ServerUrlBox.Text = _settings.ServerUrl;
        TokenBox.Password = _settings.GetToken() ?? "";
        SettingsStatus.Visibility = Visibility.Collapsed;
        SettingsOverlay.Visibility = Visibility.Visible;
        (string.IsNullOrEmpty(TokenBox.Password) ? (System.Windows.Controls.Control)TokenBox : ServerUrlBox).Focus();
    }

    private void CloseSettings_Click(object sender, RoutedEventArgs e) => SettingsOverlay.Visibility = Visibility.Collapsed;

    private async void TestConnection_Click(object sender, RoutedEventArgs e)
    {
        ShowSettingsStatus("Testing…", "Muted");
        var r = await _client.CheckConnectionAsync(ServerUrlBox.Text, TokenBox.Password.Trim());
        ShowSettingsStatus((r.Success ? "✓  " : "✕  ") + r.Message, r.Success ? "Good" : "Bad");
    }

    private async void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        _settings.ServerUrl = ServerUrlBox.Text.Trim();
        _settings.SetToken(TokenBox.Password);
        _settings.Save();
        SettingsOverlay.Visibility = Visibility.Collapsed;
        _serverReachable = null;
        RefreshServerState();
        RefreshReadyInfo();
        await CheckServerQuietlyAsync();

        // If an audit is on screen and not yet uploaded, upload it now.
        if (ResultsView.Visibility == Visibility.Visible && _uploadedAuditId is null && HasToken) await UploadCurrentAsync();
    }

    private void ShowSettingsStatus(string text, string brush)
    {
        SettingsStatus.Text = text;
        SettingsStatus.Foreground = Palette.Get(brush);
        SettingsStatus.Visibility = Visibility.Visible;
    }

    private void RestartElevated_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
            Application.Current.Shutdown();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // The user cancelled the Windows elevation prompt.
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _client.Dispose();
        base.OnClosed(e);
    }
}
