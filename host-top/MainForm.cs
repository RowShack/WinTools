using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Principal;
using System.Text;
using HostTop.Core;
using Microsoft.Win32;

namespace HostTop;

public sealed class MainForm : Form
{
    private readonly bool _demo;
    private readonly string? _screenshot;
    private readonly ProcessInfoCache _realProcs = new();
    private readonly DemoTraffic _demoSrc = new();
    private readonly FlowAggregator _agg;
    private readonly HostResolver _resolver;
    private readonly EtwSession _etw = new();
    private GeoIpDatabase? _geo;
    private CsvRecorder? _recorder;
    private DateTime _recordUntil;
    private FlowSnapshot _snap = new();
    private bool _bits = true;
    private bool _paused;
    private long _events;
    private bool _handlerHooked;

    private readonly Button _startStop = new() { Text = "Start capture", AutoSize = true };
    private readonly CheckBox _pause = new() { Text = "Pause", Appearance = Appearance.Button, AutoSize = true };
    private readonly CheckBox _hideLan = new() { Text = "Hide LAN", AutoSize = true };
    private readonly CheckBox _hideNet = new() { Text = "Hide internet", AutoSize = true };
    private readonly CheckBox _loopback = new() { Text = "Show loopback", AutoSize = true };
    private readonly CheckBox _dns = new() { Text = "Resolve names", AutoSize = true, Checked = true };
    private readonly ComboBox _units = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 80 };
    private readonly TextBox _filter = new() { Width = 200, PlaceholderText = "Filter (e.g. chrome 443 -dns)" };
    private readonly Button _export = new() { Text = "Export CSV…", AutoSize = true };
    private readonly Button _copy = new() { Text = "Copy table", AutoSize = true };
    private readonly Button _record = new() { Text = "Record…", AutoSize = true };
    private readonly Button _geoBtn = new() { Text = "GeoIP file…", AutoSize = true };
    private readonly Label _down = new() { AutoSize = true, Font = new Font("Segoe UI", 16f, FontStyle.Bold), ForeColor = Sparkline.DownColor };
    private readonly Label _up = new() { AutoSize = true, Font = new Font("Segoe UI", 16f, FontStyle.Bold), ForeColor = Sparkline.UpColor, Margin = new Padding(20, 3, 3, 3) };
    private readonly Label _totals = new() { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(24, 12, 3, 3) };
    private readonly Label _banner = new() { Dock = DockStyle.Top, Height = 28, BackColor = Color.FromArgb(255, 244, 206), Visible = false, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ToolStripStatusLabel _status = new("Ready");
    private readonly SparklineControl _detail = new() { Dock = DockStyle.Bottom };
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 1000 };
    private readonly System.Windows.Forms.Timer _demoTick = new() { Interval = 100 };
    private readonly FlowGrid _hostGrid, _procGrid, _connGrid;

    private FlowGrid CurrentGrid => _tabs.SelectedIndex switch { 1 => _procGrid, 2 => _connGrid, _ => _hostGrid };

    public MainForm(bool demo = false, string? screenshot = null)
    {
        _demo = demo; _screenshot = screenshot;
        _agg = new FlowAggregator(demo ? _demoSrc : _realProcs);
        _resolver = new HostResolver(demo ? DemoTraffic.FakeDns : null);

        Text = demo ? "Host Top (demo data)" : "Host Top";
        Size = new Size(1280, 820); MinimumSize = new Size(1000, 600);
        StartPosition = FormStartPosition.CenterScreen; Font = new Font("Segoe UI", 9.5f);

        _units.Items.AddRange(["bit/s", "bytes/s"]); _units.SelectedIndex = 0;
        _detail.RateFormat = v => Format.Rate(v, _bits);

        _hostGrid = new FlowGrid(HostColumns(), 3);
        _procGrid = new FlowGrid(ProcessColumns(), 3);
        _connGrid = new FlowGrid(ConnectionColumns(), 5);
        _hostGrid.ExtraSearch = r => r.Remote is { } ip ? (_resolver.TryGet(ip) ?? "") + " " + (_geo?.Lookup(ip) ?? "") : "";
        _connGrid.ExtraSearch = r => r.Remote is { } ip ? _resolver.TryGet(ip) ?? "" : "";
        foreach (var g in new[] { _hostGrid, _procGrid, _connGrid })
        {
            g.RowSelected += _ => UpdateDetail();
            g.ContextMenuStrip = BuildMenu(g);
        }

        var hostPage = new TabPage("By host") { Padding = Padding.Empty }; hostPage.Controls.Add(_hostGrid);
        var procPage = new TabPage("By process"); procPage.Controls.Add(_procGrid);
        var connPage = new TabPage("By connection"); connPage.Controls.Add(_connGrid);
        _tabs.TabPages.AddRange([hostPage, procPage, connPage]);
        _tabs.SelectedIndexChanged += (_, _) => { RefreshView(); };

        var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6, 4, 6, 2) };
        foreach (Control c in new Control[] { _startStop, _pause, _hideLan, _hideNet, _loopback, _dns, new Label { Text = "Units:", AutoSize = true, Margin = new Padding(8, 7, 0, 0) }, _units, _filter, _export, _copy, _record, _geoBtn })
        {
            if (c is CheckBox cb && cb.Appearance == Appearance.Normal) cb.Margin = new Padding(8, 6, 3, 3);
            toolbar.Controls.Add(c);
        }
        var totalsBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(10, 2, 6, 2), BackColor = SystemColors.ControlLightLight };
        totalsBar.Controls.AddRange([_down, _up, _totals]);

        var bar = new StatusStrip(); bar.Items.Add(_status);

        // Fill control first, then edge-docked controls; the last one added ends up outermost.
        Controls.Add(_tabs); Controls.Add(_detail); Controls.Add(bar); Controls.Add(totalsBar); Controls.Add(toolbar); Controls.Add(_banner);

        _startStop.Click += async (_, _) => { if (_etw.IsRunning) StopCapture(); else await StartCaptureAsync(); };
        _pause.CheckedChanged += (_, _) => { _paused = _pause.Checked; _pause.Text = _paused ? "Resume" : "Pause"; if (!_paused) RefreshView(); else _status.Text = "Display paused — capture continues in the background"; };
        _hideLan.CheckedChanged += (_, _) => { _agg.IncludeLan = !_hideLan.Checked; RefreshView(); };
        _hideNet.CheckedChanged += (_, _) => { _agg.IncludeInternet = !_hideNet.Checked; RefreshView(); };
        _loopback.CheckedChanged += (_, _) => { _agg.IncludeLoopback = _loopback.Checked; RefreshView(); };
        _dns.CheckedChanged += (_, _) => _resolver.Enabled = _dns.Checked;
        _units.SelectedIndexChanged += (_, _) => { _bits = _units.SelectedIndex == 0; RefreshView(); _detail.Invalidate(); };
        _filter.TextChanged += (_, _) => RefreshView();
        _export.Click += (_, _) => ExportCsv();
        _copy.Click += (_, _) => CopyTable();
        _record.Click += (_, _) => ToggleRecord();
        _geoBtn.Click += async (_, _) => await LoadGeoAsync();
        _tick.Tick += (_, _) => OnTick();
        _demoTick.Tick += (_, _) => _demoSrc.Pump(_agg);

        FormClosing += (_, _) => Shutdown();
        SystemEvents.SessionEnding += (_, _) => _etw.Stop();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => _etw.Stop();

        Shown += async (_, _) =>
        {
            if (!demo && !IsAdmin())
                ShowBanner("Not running as administrator: Windows only lets administrators listen to kernel network events. Restart this tool as administrator.");
            _tick.Start();
            if (demo) { _demoTick.Start(); _startStop.Enabled = false; _startStop.Text = "Demo data"; _status.Text = "Demo mode: showing generated traffic, no ETW session"; }
            else await StartCaptureAsync();
            if (_screenshot != null) _ = TakeScreenshotAsync();
        };
    }

    // ---------------------------------------------------------------- columns

    private string Rate(double v) => Format.Rate(v, _bits);
    private string Dns(FlowRow r) => r.Remote is { } ip ? (_resolver.TryGet(ip) ?? "") : "";
    private string Geo(FlowRow r) => r.Remote is { } ip ? (_geo?.Lookup(ip) ?? "") : "";
    private static string Raw(double v) => v.ToString("0", CultureInfo.InvariantCulture);

    private static GridColumn Str(string h, Func<FlowRow, string> t, int w) => new() { Header = h, Text = t, Width = w, Compare = (a, b) => string.Compare(t(a), t(b), StringComparison.OrdinalIgnoreCase) };

    private GridColumn Down() => new() { Header = "Down", Text = r => Rate(r.DownRate), Export = r => Raw(r.DownRate), Compare = (a, b) => a.DownRate.CompareTo(b.DownRate), Right = true, Width = 95 };
    private GridColumn Up() => new() { Header = "Up", Text = r => Rate(r.UpRate), Export = r => Raw(r.UpRate), Compare = (a, b) => a.UpRate.CompareTo(b.UpRate), Right = true, Width = 95 };
    private static GridColumn TotalDown() => new() { Header = "Total down", Text = r => Format.Bytes(r.TotalDown), Export = r => r.TotalDown.ToString(CultureInfo.InvariantCulture), Compare = (a, b) => a.TotalDown.CompareTo(b.TotalDown), Right = true, Width = 90 };
    private static GridColumn TotalUp() => new() { Header = "Total up", Text = r => Format.Bytes(r.TotalUp), Export = r => r.TotalUp.ToString(CultureInfo.InvariantCulture), Compare = (a, b) => a.TotalUp.CompareTo(b.TotalUp), Right = true, Width = 90 };
    private static GridColumn Spark() => new() { Header = "Last 60 s", Spark = true, Width = 130 };

    private List<GridColumn> HostColumns() =>
    [
        Str("Remote host", r => r.Name, 170),
        Str("Name", Dns, 200),
        new GridColumn { Header = "Location", Text = Geo, Compare = (a, b) => string.Compare(Geo(a), Geo(b), StringComparison.OrdinalIgnoreCase), Width = 160, Visible = () => _geo != null },
        Down(), Up(), TotalDown(), TotalUp(),
        new GridColumn { Header = "Conns", Text = r => r.Count.ToString(), Compare = (a, b) => a.Count.CompareTo(b.Count), Right = true, Width = 55 },
        Str("Scope", r => r.Class.ToString(), 70),
        Str("Services", r => r.Service, 120),
        Str("Processes", r => r.Related, 160),
        Spark(),
    ];

    private List<GridColumn> ProcessColumns() =>
    [
        Str("Process", r => r.Name, 160),
        new GridColumn { Header = "PID", Text = r => r.Pid.ToString(), Compare = (a, b) => a.Pid.CompareTo(b.Pid), Right = true, Width = 60 },
        Str("Path", r => r.Path ?? "", 300),
        Down(), Up(), TotalDown(), TotalUp(),
        new GridColumn { Header = "Hosts", Text = r => r.Count.ToString(), Compare = (a, b) => a.Count.CompareTo(b.Count), Right = true, Width = 55 },
        Str("Remote hosts", r => r.Related, 280),
        Spark(),
    ];

    private List<GridColumn> ConnectionColumns() =>
    [
        Str("Process", r => r.Name, 140),
        new GridColumn { Header = "PID", Text = r => r.Pid.ToString(), Compare = (a, b) => a.Pid.CompareTo(b.Pid), Right = true, Width = 60 },
        Str("Proto", r => r.Protocol?.ToString().ToUpperInvariant() ?? "", 55),
        Str("Local", r => r.Local, 190),
        Str("Remote", r => r.RemoteEndpoint, 230),
        Down(), Up(), TotalDown(), TotalUp(),
        Str("Name", Dns, 200),
        Str("Service", r => r.Service, 120),
        Spark(),
    ];

    // ---------------------------------------------------------------- capture

    private static bool IsAdmin()
    {
        try { using var id = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator); }
        catch { return false; }
    }

    private void ShowBanner(string text) { _banner.Text = "  " + text; _banner.Visible = true; }

    private async Task StartCaptureAsync()
    {
        _startStop.Enabled = false;
        _status.Text = "Starting ETW session…";
        try
        {
            var orphan = false;
            await Task.Run(() =>
            {
                orphan = EtwSession.StopOrphan();
                if (!_handlerHooked)
                {
                    _handlerHooked = true;
                    _etw.FlowReceived += e => { Interlocked.Increment(ref _events); _agg.Add(e); };
                    _etw.Error += m => BeginInvoke(() => { ShowBanner("Capture stopped: " + m); _status.Text = "Capture stopped"; _startStop.Text = "Start capture"; });
                }
                _etw.Start();
            });
            _startStop.Text = "Stop capture";
            _status.Text = (orphan ? "Stopped a leftover capture session from an earlier run. " : "") + "Capturing via ETW (Microsoft-Windows-Kernel-Network)";
            if (!_demo && IsAdmin()) _banner.Visible = false;
        }
        catch (Exception ex)
        {
            ShowBanner("Could not start the ETW session: " + ex.Message + (IsAdmin() ? "" : "  (run as administrator)"));
            _status.Text = "Capture not running";
        }
        finally { _startStop.Enabled = true; }
    }

    private void StopCapture()
    {
        _etw.Stop();
        _startStop.Text = "Start capture";
        _status.Text = "Capture stopped (ETW session removed)";
    }

    private void Shutdown()
    {
        _tick.Stop(); _demoTick.Stop();
        _etw.Stop();            // never leave the ETW session running
        _resolver.Stop();
        _recorder?.Dispose();
    }

    // ---------------------------------------------------------------- refresh

    private void OnTick()
    {
        var s = _agg.Tick(DateTime.UtcNow);
        if (_recorder != null)
        {
            _recorder.Record(s);
            if (_recorder.Finished) { _status.Text = $"Recording finished ({_recorder.Lines} lines written)"; _recorder = null; _record.Text = "Record…"; }
            else { var left = _recordUntil - DateTime.Now; _record.Text = $"Stop recording ({Math.Max(0, (int)left.TotalSeconds / 60)}:{Math.Max(0, (int)left.TotalSeconds % 60):00})"; }
        }
        if (_paused) return;
        _snap = s;
        RefreshView();
    }

    private void RefreshView()
    {
        var s = _snap;
        _down.Text = "▼ " + Rate(s.DownRate);
        _up.Text = "▲ " + Rate(s.UpRate);
        var t = $"Since start: ▼ {Format.Bytes(s.TotalDown)}  ▲ {Format.Bytes(s.TotalUp)}   (network adapters, loopback excluded)";
        if (s.LoopbackDownRate > 0 || s.LoopbackUpRate > 0) t += $"   Loopback now: ▼ {Rate(s.LoopbackDownRate)} ▲ {Rate(s.LoopbackUpRate)}" + (_loopback.Checked ? "" : " (hidden)");
        _totals.Text = t;

        bool Scope(FlowRow r) => !(r.Class == NetClass.Lan && _hideLan.Checked) && !(r.Class == NetClass.Internet && _hideNet.Checked)
                                 && !(r.Class == NetClass.Loopback && !_loopback.Checked);
        _hostGrid.UpdateColumnVisibility();
        switch (_tabs.SelectedIndex)
        {
            case 0: _hostGrid.SetData(s.Hosts, _filter.Text, Scope); break;
            case 1: _procGrid.SetData(s.Processes, _filter.Text); break;
            default: _connGrid.SetData(s.Connections, _filter.Text, Scope); break;
        }
        UpdateDetail();
    }

    private void UpdateDetail()
    {
        var r = CurrentGrid.Selected;
        if (r == null) { _detail.SetData("", [], []); return; }
        var cap = _tabs.SelectedIndex switch
        {
            0 => $"{r.Name} {Dns(r)}  ▼ {Rate(r.DownRate)}  ▲ {Rate(r.UpRate)}",
            1 => $"{r.Name} (PID {r.Pid})  ▼ {Rate(r.DownRate)}  ▲ {Rate(r.UpRate)}",
            _ => $"{r.Name}  {r.Local} → {r.RemoteEndpoint}  ▼ {Rate(r.DownRate)}  ▲ {Rate(r.UpRate)}",
        };
        _detail.SetData(cap, r.DownHistory, r.UpHistory);
    }

    // ---------------------------------------------------------------- export / copy / record / geoip

    private void ExportCsv()
    {
        var (h, rows) = CurrentGrid.ExportTable();
        using var d = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv|Text (*.txt)|*.txt", FileName = $"host-top-{_tabs.SelectedTab!.Text.Replace(' ', '-').ToLowerInvariant()}-{DateTime.Now:yyyyMMdd-HHmmss}.csv" };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var text = d.FileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ? CsvExport.BuildTsv(h, rows) : CsvExport.Build(h, rows);
            File.WriteAllText(d.FileName, text, new UTF8Encoding(false));
            _status.Text = $"Exported {rows.Count} rows to {d.FileName} (rates in bytes/s, totals in bytes)";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void CopyTable()
    {
        var (h, rows) = CurrentGrid.ExportTable();
        try { Clipboard.SetText(CsvExport.BuildTsv(h, rows)); _status.Text = $"Copied {rows.Count} rows to the clipboard"; }
        catch (Exception ex) { _status.Text = "Copy failed: " + ex.Message; }
    }

    private void ToggleRecord()
    {
        if (_recorder != null) { _recorder.Dispose(); _status.Text = $"Recording stopped ({_recorder.Lines} lines written)"; _recorder = null; _record.Text = "Record…"; return; }
        using var dlg = new RecordDialog();
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            _recordUntil = DateTime.Now.AddMinutes(dlg.Minutes);
            _recorder = new CsvRecorder(dlg.FilePath, TimeSpan.FromMinutes(dlg.Minutes), DateTime.UtcNow, ip => IPAddress.TryParse(ip, out var a) ? _resolver.TryGet(a) ?? "" : "");
            _status.Text = $"Recording to {dlg.FilePath} for {dlg.Minutes} min";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Cannot record", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private async Task LoadGeoAsync()
    {
        using var d = new OpenFileDialog { Title = "GeoIP/ASN CSV (start_ip,end_ip,country[,asn/org])", Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*" };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        _status.Text = "Loading GeoIP file…"; _geoBtn.Enabled = false;
        try
        {
            var db = await Task.Run(() => GeoIpDatabase.Load(d.FileName));
            _geo = db;
            _status.Text = $"GeoIP: {db.Count:N0} ranges loaded from {Path.GetFileName(d.FileName)} (offline lookups only)";
            RefreshView();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Cannot load file", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { _geoBtn.Enabled = true; }
    }

    // ---------------------------------------------------------------- context menu

    private ContextMenuStrip BuildMenu(FlowGrid g)
    {
        var m = new ContextMenuStrip();
        var copyIp = new ToolStripMenuItem("Copy IP address");
        var copyRow = new ToolStripMenuItem("Copy row");
        var whois = new ToolStripMenuItem("Whois lookup for this IP (opens browser)");
        var browse = new ToolStripMenuItem("Open this host in the browser");
        var loc = new ToolStripMenuItem("Open process file location");
        var kill = new ToolStripMenuItem("Kill process…");
        m.Items.AddRange([copyIp, copyRow, new ToolStripSeparator(), whois, browse, new ToolStripSeparator(), loc, kill]);
        m.Opening += (_, e) =>
        {
            var r = g.Selected;
            if (r == null) { e.Cancel = true; return; }
            copyIp.Enabled = whois.Enabled = browse.Enabled = r.Remote != null;
            loc.Enabled = !string.IsNullOrEmpty(r.Path);
            kill.Enabled = r.Pid > 4;
            copyIp.Visible = whois.Visible = browse.Visible = r.Remote != null;
            loc.Visible = kill.Visible = g != _hostGrid;
        };
        copyIp.Click += (_, _) => { if (g.Selected?.Remote is { } ip) Clipboard.SetText(ip.ToString()); };
        copyRow.Click += (_, _) =>
        {
            var r = g.Selected; if (r == null) return;
            var (h, rows) = g.ExportTable(); int i = g.Rows2.ToList().FindIndex(x => x.Id == r.Id);
            if (i >= 0) Clipboard.SetText(CsvExport.BuildTsv(h, [rows[i]]));
        };
        whois.Click += (_, _) => { if (g.Selected?.Remote is { } ip) OpenUrl("https://who.is/whois-ip/ip-address/" + Uri.EscapeDataString(ip.ToString())); };
        browse.Click += (_, _) =>
        {
            if (g.Selected?.Remote is not { } ip) return;
            var host = _resolver.TryGet(ip) ?? (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{ip}]" : ip.ToString());
            OpenUrl("http://" + host + "/");
        };
        loc.Click += (_, _) =>
        {
            var p = g.Selected?.Path;
            if (p == null) return;
            if (!File.Exists(p)) { MessageBox.Show(this, "The file no longer exists:\n" + p); return; }
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { "/select,", p }, UseShellExecute = false });
        };
        kill.Click += (_, _) => KillProcess(g.Selected);
        return m;
    }

    private void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { _status.Text = "Cannot open browser: " + ex.Message; }
    }

    private void KillProcess(FlowRow? r)
    {
        if (r == null || r.Pid <= 4) return;
        if (MessageBox.Show(this, $"Kill {r.Name} (PID {r.Pid})?\n\nUnsaved data in that program is lost.", "Kill process", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
        try
        {
            using var p = Process.GetProcessById(r.Pid);
            // PIDs get reused: make sure it is still the process we showed.
            if (!(p.ProcessName + ".exe").Equals(r.Name, StringComparison.OrdinalIgnoreCase)) { MessageBox.Show(this, "That PID now belongs to a different program; nothing was killed."); return; }
            p.Kill();
            _status.Text = $"Killed {r.Name} (PID {r.Pid})";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Could not kill process", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    // ---------------------------------------------------------------- dev helper

    private async Task TakeScreenshotAsync()
    {
        await Task.Delay(9000);
        try
        {
            _tabs.SelectedIndex = 0;
            if (_hostGrid.Rows2.Count > 0 && _hostGrid.RowCount > 0) _hostGrid.Rows[0].Selected = true;
            await Task.Delay(1500);
            using var bmp = new Bitmap(Width, Height);
            DrawToBitmap(bmp, new Rectangle(0, 0, Width, Height));
            bmp.Save(_screenshot!, System.Drawing.Imaging.ImageFormat.Png);
        }
        catch { }
        Close();
    }
}
