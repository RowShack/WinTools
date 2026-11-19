using System.Diagnostics;
using System.Text;
using WifiRoamLog.Core;

namespace WifiRoamLog;

public sealed class StartOptions
{
    public bool Demo, Minimized, AutoStart;
    public string? Screenshot;
    public string ScreenshotTab = "live";
    public double ShotDelaySeconds = 2.5;
}

public sealed class MainForm : Form
{
    private readonly StartOptions _opt;
    private readonly AppSettings _settings = AppSettings.Load();
    private readonly IWlanApi? _api;
    private readonly string? _apiError;
    private IReadOnlyList<WlanInterfaceInfo> _ifaces = [];
    private ApMap _apMap = new();
    private SessionData _live = new();
    private SessionData? _view;
    private string? _viewPath;
    private WifiMonitor? _monitor;
    private SessionLogWriter? _writer;
    private CancellationTokenSource? _cts;
    private Task? _runTask;
    private string? _lastFolder;
    private readonly LatencyWindow _gwWin = new(60), _tgWin = new(60);
    private LocationState _loc = LocationState.Ok;
    private volatile bool _running;
    private bool _exiting;
    private bool _rebuilding;
    private int _shownEvents = -1;
    private long _shownEventVersion = -1;
    private CancellationTokenSource? _loadCts;

    // toolbar
    private readonly ComboBox _adapter = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 230 };
    private readonly NumericUpDown _interval = new() { Minimum = 1, Maximum = 60, Value = 2, Width = 50 };
    private readonly TextBox _target = new() { Width = 130, Text = "8.8.8.8" };
    private readonly Button _startStop = new() { Text = "Start logging", AutoSize = true, MinimumSize = new Size(110, 0) };
    private readonly ComboBox _window = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 80 };
    private readonly CheckBox _follow = new() { Text = "Follow live", AutoSize = true, Checked = true };
    private readonly Button _importMap = new() { Text = "Import AP names…", AutoSize = true };
    private readonly Label _mapInfo = new() { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(3, 6, 8, 3), Text = "no AP names loaded" };
    private readonly NumericUpDown _prefix = new() { Minimum = 1, Maximum = 6, Value = 5, Width = 44 };
    private readonly CheckBox _ignoreFirst = new() { Text = "ignore 1st octet", AutoSize = true };
    private readonly Button _openLog = new() { Text = "Open log…", AutoSize = true };
    private readonly Button _openFolder = new() { Text = "Open folder", AutoSize = true };
    private readonly Button _logFolder = new() { Text = "Log folder…", AutoSize = true };
    private readonly Button _png = new() { Text = "Export PNG…", AutoSize = true };

    // banners
    private readonly Panel _banner = new() { Dock = DockStyle.Top, Height = 46, BackColor = System.Drawing.Color.FromArgb(255, 244, 206), Visible = false, Padding = new Padding(8, 3, 8, 3) };
    private readonly Label _bannerText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
    private readonly Button _bannerBtn = new() { Text = "Open Location settings", Dock = DockStyle.Right, Width = 170 };
    private readonly Panel _viewBanner = new() { Dock = DockStyle.Top, Height = 28, BackColor = System.Drawing.Color.FromArgb(227, 242, 253), Visible = false, Padding = new Padding(8, 2, 8, 2) };
    private readonly Label _viewText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
    private readonly Button _backLive = new() { Text = "Back to live", Dock = DockStyle.Right, Width = 110 };

    // header cards
    private readonly StatCard _cAp = new("AP", 190), _cSsid = new("SSID", 130), _cBssid = new("BSSID", 140), _cRssi = new("RSSI", 120), _cCh = new("Channel / band", 120),
        _cPhy = new("PHY", 175), _cRate = new("Rate rx / tx (Mbps)", 130), _cGw = new("Gateway latency", 175), _cTg = new("Target latency", 175), _cLoss = new("Loss gw / target", 110), _cRoam = new("Last roam", 360);

    private readonly ChartView _chart = new() { Dock = DockStyle.Fill };
    private readonly DataGridView _events = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false, RowHeadersVisible = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoGenerateColumns = false, BackgroundColor = SystemColors.Window, BorderStyle = BorderStyle.None, MultiSelect = true,
    };
    private readonly Button _copyEvents = new() { Text = "Copy events", AutoSize = true };
    private readonly Button _exportEvents = new() { Text = "Export events…", AutoSize = true };
    private readonly Label _eventsHint = new() { AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(10, 6, 3, 3), Text = "Click an event to jump to it on the charts. Dashed markers: purple = roam, red = disconnect, green = connect." };
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    private readonly VisibleApsView _visible;
    private readonly StatusStrip _statusStrip = new();
    private readonly ToolStripStatusLabel _status = new("Ready") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ToolStripStatusLabel _folderLabel = new("") { IsLink = true, LinkBehavior = LinkBehavior.HoverUnderline };
    private readonly ToolStripButton _cancelLoad = new("Cancel loading") { Visible = false };
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 1000 };
    private readonly NotifyIcon _tray = new();
    private readonly ToolStripMenuItem _trayStart = new("Start logging");
    private readonly ToolStripMenuItem _trayClose = new("Close button minimises to tray (while logging)") { CheckOnClick = true };

    private sealed class EventRow
    {
        public DateTime When { get; init; }
        public string Time { get; init; } = ""; public string Event { get; init; } = ""; public string Source { get; init; } = ""; public string Ssid { get; init; } = "";
        public string From { get; init; } = ""; public string To { get; init; } = ""; public string Duration { get; init; } = ""; public string Detail { get; init; } = "";
    }

    private bool _startHidden;
    private ApMatchOptions MatchOptions => new((int)_prefix.Value, _ignoreFirst.Checked);
    private string ApName(string bssid) => _apMap.Count == 0 || string.IsNullOrEmpty(bssid) ? "" : _apMap.NameFor(bssid, MatchOptions);
    private Guid? SelectedIface => (_adapter.SelectedItem as WlanInterfaceInfo)?.Id;
    private SessionData ShownData => _view ?? _live;

    public MainForm(StartOptions opt)
    {
        _opt = opt;
        Text = opt.Demo ? "Wi-Fi Roam Log (demo data)" : "Wi-Fi Roam Log";
        Size = new Size(1100, 700); MinimumSize = new Size(960, 620);
        StartPosition = FormStartPosition.CenterScreen; Font = new Font("Segoe UI", 9.5f);
        Icon = AppIcon.Create();

        try { _api = opt.Demo ? new DemoWlanApi() : new WlanApi(); }
        catch (Exception ex) { _apiError = ex.Message; }
        _visible = new VisibleApsView(_api ?? new DemoWlanApi(), () => SelectedIface, ApName, () => _live.LastSample()?.Bssid ?? "");

        _window.Items.AddRange(["5 min", "15 min", "1 hour", "4 hours", "All"]);
        _window.SelectedIndex = _settings.WindowMinutes switch { 5 => 0, 60 => 2, 240 => 3, 0 => 4, _ => 1 };
        _target.Text = _settings.Target; _interval.Value = Math.Clamp(_settings.IntervalSeconds, 1, 60);
        _prefix.Value = Math.Clamp(_settings.PrefixOctets, 1, 6); _ignoreFirst.Checked = _settings.IgnoreFirstOctet;
        _chart.ApName = ApName; _chart.WindowMinutes = WindowMinutesFromCombo();

        BuildLayout();
        WireEvents();
        LoadAdapters();
        LoadSavedMap();
        if (opt.Demo) SetupDemo();
        _chart.SetData(_live, true);
        _tick.Start();
        UpdateUi();
        CheckLocation();
        _startHidden = opt.Minimized;
    }

    // ---------------------------------------------------------------- layout

    private void BuildLayout()
    {
        var tb1 = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4, 4, 4, 0), WrapContents = true };
        tb1.Controls.AddRange([L("Adapter"), _adapter, L("every"), _interval, L("s  Ping target"), _target, _startStop, L("Window"), _window, _follow]);
        var tb2 = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4, 0, 4, 2), WrapContents = true };
        tb2.Controls.AddRange([_importMap, _mapInfo, L("match first"), _prefix, L("octets"), _ignoreFirst, new Label { Width = 12 }, _openLog, _openFolder, _logFolder, _png]);

        _banner.Controls.AddRange([_bannerText, _bannerBtn]);
        _viewBanner.Controls.AddRange([_viewText, _backLive]);

        var header = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4, 2, 4, 2), BackColor = System.Drawing.Color.FromArgb(246, 248, 250), WrapContents = true };
        header.Controls.AddRange([_cAp, _cSsid, _cBssid, _cRssi, _cCh, _cPhy, _cRate, _cGw, _cTg, _cLoss, _cRoam]);

        AddCol("Time", "Time", 178); AddCol("Event", "Event", 80); AddCol("Source", "Source", 68); AddCol("SSID", "Ssid", 90); AddCol("From", "From", 170);
        AddCol("To", "To", 170); AddCol("Duration", "Duration", 70); AddCol("Detail", "Detail", 300, fill: true);

        var evBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4, 2, 4, 2), WrapContents = false };
        evBar.Controls.AddRange([_copyEvents, _exportEvents, _eventsHint]);
        var evPanel = new Panel { Dock = DockStyle.Fill };
        evPanel.Controls.Add(_events); evPanel.Controls.Add(evBar);
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        split.Panel1.Controls.Add(_chart); split.Panel2.Controls.Add(evPanel);
        HandleCreated += (_, _) => { try { split.Panel1MinSize = 160; split.Panel2MinSize = 110; split.SplitterDistance = Math.Max(160, (int)(split.Height * 0.55)); } catch { } };
        var live = new TabPage("Live") { Padding = Padding.Empty }; live.Controls.Add(split);
        var vis = new TabPage("Visible APs") { Padding = Padding.Empty }; vis.Controls.Add(_visible);
        _tabs.TabPages.AddRange([live, vis]);

        _statusStrip.Items.AddRange([_status, _cancelLoad, _folderLabel]);

        // Fill first; edge controls last (the later one added docks outermost)
        Controls.Add(_tabs);
        Controls.Add(header);
        Controls.Add(_banner);
        Controls.Add(_viewBanner);
        Controls.Add(tb2);
        Controls.Add(tb1);
        Controls.Add(_statusStrip);

        var menu = new ContextMenuStrip();
        var show = new ToolStripMenuItem("Show window"); show.Click += (_, _) => RestoreFromTray();
        var openF = new ToolStripMenuItem("Open log folder"); openF.Click += (_, _) => OpenFolder();
        var exit = new ToolStripMenuItem("Exit (stops logging)"); exit.Click += (_, _) => ExitApp();
        _trayStart.Click += (_, _) => ToggleSession();
        _trayClose.Checked = _settings.CloseToTray == true;
        _trayClose.CheckedChanged += (_, _) => { _settings.CloseToTray = _trayClose.Checked; _settings.Save(); };
        menu.Items.AddRange([show, _trayStart, openF, _trayClose, new ToolStripSeparator(), exit]);
        _tray.ContextMenuStrip = menu; _tray.Icon = Icon; _tray.Text = "Wi-Fi Roam Log"; _tray.Visible = true;
        _tray.DoubleClick += (_, _) => RestoreFromTray();
    }

    private static Label L(string t) => new() { Text = t, AutoSize = true, Margin = new Padding(8, 7, 3, 3) };

    private void AddCol(string header, string prop, int width, bool fill = false) =>
        _events.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = header, DataPropertyName = prop, Width = width, AutoSizeMode = fill ? DataGridViewAutoSizeColumnMode.Fill : DataGridViewAutoSizeColumnMode.None, SortMode = DataGridViewColumnSortMode.NotSortable });

    private void WireEvents()
    {
        _startStop.Click += (_, _) => ToggleSession();
        _window.SelectedIndexChanged += (_, _) => { _chart.WindowMinutes = WindowMinutesFromCombo(); _settings.WindowMinutes = WindowMinutesFromCombo(); };
        _follow.CheckedChanged += (_, _) => { if (_follow.Checked) { if (_view is null) _chart.SetFollow(true); } else _chart.SetFollow(false); };
        _chart.FollowChanged += on => { if (_follow.Checked != on) _follow.Checked = on; };
        _importMap.Click += (_, _) => ImportMap();
        _prefix.ValueChanged += (_, _) => { OptionsChanged(); };
        _ignoreFirst.CheckedChanged += (_, _) => { OptionsChanged(); };
        _openFolder.Click += (_, _) => OpenFolder();
        _logFolder.Click += (_, _) => ChooseLogFolder();
        _openLog.Click += async (_, _) => await OpenLogAsync();
        _backLive.Click += (_, _) => BackToLive();
        _png.Click += (_, _) => ExportPng();
        _copyEvents.Click += (_, _) => CopyEvents();
        _exportEvents.Click += (_, _) => ExportEvents();
        _bannerBtn.Click += (_, _) => OpenLocationSettings();
        _adapter.SelectedIndexChanged += (_, _) => { CheckLocation(); _visible.ReloadCached(); };
        _events.SelectionChanged += (_, _) => OnEventSelected();
        _cancelLoad.Click += (_, _) => _loadCts?.Cancel();
        _folderLabel.Click += (_, _) => OpenFolder();
        _tick.Tick += (_, _) => OnTick();
        _tabs.SelectedIndexChanged += (_, _) => { if (_tabs.SelectedIndex == 1) _visible.ReloadCached(); };
        Resize += (_, _) => { if (WindowState == FormWindowState.Minimized && _running) Hide(); };
        Shown += OnShown;
        FormClosing += OnFormClosing;
        FormClosed += (_, _) => Cleanup();
    }

    private int WindowMinutesFromCombo() => _window.SelectedIndex switch { 0 => 5, 1 => 15, 2 => 60, 3 => 240, _ => 0 };

    protected override void SetVisibleCore(bool value)
    {
        base.SetVisibleCore(value);
    }

    // ---------------------------------------------------------------- start up

    private void LoadAdapters()
    {
        _adapter.Items.Clear();
        if (_api is null) { SetBanner(_apiError ?? "Windows Wi-Fi API unavailable.", false); return; }
        try { _ifaces = _api.EnumInterfaces(); }
        catch (Exception ex) { SetBanner("Could not list Wi-Fi adapters: " + ex.Message, false); return; }
        foreach (var i in _ifaces) _adapter.Items.Add(i);
        if (_ifaces.Count == 0) { SetBanner("No Wi-Fi adapter found on this PC. Logging needs a Wi-Fi adapter.", false); return; }
        int idx = _ifaces.ToList().FindIndex(i => i.Id.ToString() == _settings.AdapterGuid);
        _adapter.SelectedIndex = Math.Max(0, idx);
    }

    private void LoadSavedMap()
    {
        if (string.IsNullOrEmpty(_settings.ApMapPath) || !File.Exists(_settings.ApMapPath)) return;
        try { ApplyMap(ApMapImporter.ParseFile(_settings.ApMapPath), _settings.ApMapPath, silent: true); } catch { }
    }

    private void SetupDemo()
    {
        var csv = "BSSID prefix,AP name,Location\n94:2a:6f:5d:a1,FAP-2F-East,Floor 2 east\n94:2a:6f:d1:07,FAP-3F-West,Floor 3 west\n94:2a:6f:a8:11,FAP-1F-Lobby,Reception\ne4:5f:01:22:33,Lab-AP-01,Lab\n";
        ApplyMap(ApMapImporter.Parse(csv), "demo", silent: true);
        DemoWlanApi.Populate(_live, DateTime.Now, 20, _apMap, MatchOptions);
        foreach (var p in _live.Pings().TakeLast(60)) (p.Target == PingTarget.Gateway ? _gwWin : _tgWin).Add(p);
    }

    private void OnShown(object? sender, EventArgs e)
    {
        if (_opt.Minimized) { WindowState = FormWindowState.Minimized; Hide(); }
        if (_opt.AutoStart) ToggleSession();
        if (_opt.Screenshot != null) _ = TakeScreenshotAsync();
    }

    // ---------------------------------------------------------------- session

    private void ToggleSession()
    {
        if (_running) _ = StopSessionAsync(); else _ = StartSessionAsync();
    }

    private async Task StartSessionAsync()
    {
        if (_running || _api is null || SelectedIface is not { } id) return;
        SaveSettings();
        var data = new SessionData();
        SessionLogWriter? writer = null;
        if (!_opt.Demo)
        {
            try
            {
                writer = new SessionLogWriter(_settings.EffectiveLogFolder, DateTime.Now,
                    $"Adapter: {(_adapter.SelectedItem as WlanInterfaceInfo)?.Description}{Environment.NewLine}Sample interval: {_interval.Value} s{Environment.NewLine}Ping target: {_target.Text.Trim()}{Environment.NewLine}AP match: first {_prefix.Value} octets{(_ignoreFirst.Checked ? ", ignoring octet 1" : "")}");
            }
            catch (Exception ex) { MessageBox.Show(this, "Cannot create the log folder:\r\n" + ex.Message, "Wi-Fi Roam Log", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
        }
        _live = data; _writer = writer; _lastFolder = writer?.Folder ?? _lastFolder;
        lock (_gwWin) { _gwWin.Clear(); } lock (_tgWin) { _tgWin.Clear(); }
        _shownEvents = -1;
        if (_view is null) _chart.SetData(_live, true);

        IPinger pinger = _opt.Demo ? new DemoPinger() : new SystemPinger();
        IGatewayProvider gw = _opt.Demo ? new DemoGatewayProvider() : new NetworkGatewayProvider();
        var mon = new WifiMonitor(_api, pinger, gw, new WifiMonitorOptions
        {
            InterfaceGuid = id, SampleInterval = TimeSpan.FromSeconds((double)_interval.Value), Target = _target.Text.Trim(), ApNameResolver = ApName,
        });
        mon.SampleReady += s => { data.AddSample(s); writer?.AppendSample(s); };
        mon.EventLogged += ev => { data.AddEvent(ev); writer?.AppendEvent(ev); };
        mon.PingReady += p =>
        {
            data.AddPing(p); writer?.AppendPing(p);
            if (p.Target == PingTarget.Gateway) lock (_gwWin) _gwWin.Add(p); else lock (_tgWin) _tgWin.Add(p);
        };
        mon.LocationChanged += s => { _loc = s; if (IsHandleCreated && !IsDisposed) BeginInvoke(UpdateBannerFromState); };
        _monitor = mon;
        _cts = new CancellationTokenSource();
        _running = true;
        UpdateUi();
        _status.Text = writer is null ? "Logging (demo, nothing written)" : "Logging to " + writer.Folder;
        _runTask = mon.RunAsync(_cts.Token);
        try { await _runTask; }
        catch (Exception ex) { _status.Text = "Monitor stopped: " + ex.Message; }
        finally
        {
            writer?.Dispose();
            if (ReferenceEquals(_writer, writer)) _writer = null;
            _running = false; _monitor = null;
            if (!IsDisposed) { UpdateUi(); _status.Text = writer is null ? "Stopped" : "Stopped. Log saved in " + writer.Folder; }
        }
    }

    private async Task StopSessionAsync()
    {
        if (!_running) return;
        _startStop.Enabled = false; _trayStart.Enabled = false;
        _status.Text = "Stopping…";
        _cts?.Cancel();
        if (_runTask != null) { try { await _runTask; } catch { } }
        _startStop.Enabled = true; _trayStart.Enabled = true;
    }

    private void UpdateUi()
    {
        bool r = _running;
        _startStop.Text = r ? "Stop logging" : "Start logging";
        _trayStart.Text = r ? "Stop logging" : "Start logging";
        _startStop.Enabled = r || SelectedIface is not null;
        _adapter.Enabled = _interval.Enabled = _target.Enabled = !r;
        _folderLabel.Text = _lastFolder ?? "";
        UpdateTitle();
    }

    private void UpdateTitle() =>
        Text = (_opt.Demo ? "Wi-Fi Roam Log (demo data)" : "Wi-Fi Roam Log") + (_running ? "  [logging]" : "") + (_view is not null ? "  [viewing a log]" : "");

    // ---------------------------------------------------------------- periodic UI refresh

    private void OnTick()
    {
        var s = _live.LastSample();
        UpdateHeader(s);
        UpdateTray(s);
        if (_tabs.SelectedIndex == 0) _chart.Tick();
        RefreshEvents(false);
    }

    private void UpdateHeader(WifiSample? s)
    {
        if (s is null || (!_running && _live.LastSample() is null))
        {
            foreach (var c in new[] { _cAp, _cSsid, _cBssid, _cRssi, _cCh, _cPhy, _cRate, _cGw, _cTg, _cLoss, _cRoam }) c.SetValue("–", null);
            _cAp.SetValue(_running ? "waiting…" : "not logging", null);
            return;
        }
        string stale = !_running ? " (last)" : "";
        if (!s.IsConnected)
        {
            _cAp.SetValue("DISCONNECTED", System.Drawing.Color.FromArgb(198, 40, 40)); _cSsid.SetValue(s.Ssid.Length > 0 ? s.Ssid : "–", null); _cBssid.SetValue("–", null);
            _cRssi.SetValue("–", null); _cCh.SetValue("–", null); _cPhy.SetValue("–", null); _cRate.SetValue("–", null);
        }
        else
        {
            string ap = s.ApName.Length > 0 ? s.ApName : ApName(s.Bssid);
            _cAp.SetValue(ap.Length > 0 ? ap : "(no name mapped)", null);
            _cSsid.SetValue(s.Ssid.Length > 0 ? s.Ssid : "(hidden / blocked)", null);
            _cBssid.SetValue(s.Bssid.Length > 0 ? s.Bssid : "(blocked)", null);
            _cRssi.SetValue(s.RssiDbm is { } r ? $"{r} dBm  {s.SignalPct}%" : "–", s.RssiDbm is { } rr ? RssiColor(rr) : null);
            _cCh.SetValue(s.Channel is { } ch ? $"{ch} / {WifiMath.BandName(s.Band)}" : "–", null);
            _cPhy.SetValue(s.Phy.Length > 0 ? s.Phy : "–", null);
            _cRate.SetValue($"{WifiMath.FormatMbps(s.RxMbps)} / {WifiMath.FormatMbps(s.TxMbps)}", null);
        }
        LatencyStats g, t;
        lock (_gwWin) g = _gwWin.Stats; lock (_tgWin) t = _tgWin.Stats;
        _cGw.SetValue(Lat(g), LatColor(g)); _cTg.SetValue(Lat(t), LatColor(t));
        _cLoss.SetValue(g.Count == 0 && t.Count == 0 ? "–" : $"{g.LossPct:0}% / {t.LossPct:0}%", g.LossPct > 2 || t.LossPct > 2 ? System.Drawing.Color.FromArgb(198, 40, 40) : null);
        var lr = _live.LastRoam();
        _cRoam.SetValue(lr is null ? "none yet" : $"{lr.Time:HH:mm:ss}  {Disp(lr.OldAp, lr.OldBssid)} → {Disp(lr.NewAp, lr.NewBssid)}" + (lr.DurationMs is { } d ? $" ({d:0} ms)" : ""), null);
        _ = stale;
    }

    private static string Lat(LatencyStats s) => s.Count == 0 ? "–" : s.LastMs is { } l ? $"{l:0.#} ms (avg {s.AvgMs:0.#})" : "lost";
    private static System.Drawing.Color? LatColor(LatencyStats s) => s.Count == 0 ? null : s.LastMs is null ? System.Drawing.Color.FromArgb(198, 40, 40) : s.LastMs > 100 ? System.Drawing.Color.FromArgb(239, 108, 0) : null;
    private static System.Drawing.Color RssiColor(int r) => r >= -67 ? System.Drawing.Color.FromArgb(46, 125, 50) : r >= -75 ? System.Drawing.Color.FromArgb(239, 108, 0) : System.Drawing.Color.FromArgb(198, 40, 40);

    private string Disp(string ap, string bssid)
    {
        string name = ApName(bssid); if (name.Length == 0) name = ap;
        return name.Length > 0 ? name : bssid.Length > 0 ? bssid : "?";
    }

    private void UpdateTray(WifiSample? s)
    {
        string t = !_running ? "Wi-Fi Roam Log: not logging"
            : s is null ? "Wi-Fi Roam Log: waiting…"
            : !s.IsConnected ? "Wi-Fi Roam Log: DISCONNECTED"
            : $"{(s.ApName.Length > 0 ? s.ApName : s.Bssid)}  {s.RssiDbm} dBm  ch {s.Channel}";
        _tray.Text = t.Length > 120 ? t[..120] : t;
    }

    private void RefreshEvents(bool force)
    {
        var d = ShownData;
        var ev = d.Events();
        if (!force && ev.Length == _shownEvents && d.Version == _shownEventVersion && !_apMapDirty) { return; }
        _shownEventVersion = d.Version; _apMapDirty = false;
        if (!force && ev.Length == _shownEvents) return;
        _shownEvents = ev.Length;
        var rows = ev.Reverse().Select(e => new EventRow
        {
            When = e.Time, Time = LogFormat.T(e.Time)[..23], Event = KindText(e.Kind), Source = e.Source == WifiEventSource.Inferred ? "inferred" : "notified", Ssid = e.Ssid,
            From = Disp(e.OldAp, e.OldBssid) is var f && e.OldBssid.Length > 0 ? WithBssid(e.OldAp, e.OldBssid) : "", To = e.NewBssid.Length > 0 ? WithBssid(e.NewAp, e.NewBssid) : "",
            Duration = e.DurationMs is { } ms ? $"{ms:0} ms" : "", Detail = e.Detail,
        }).ToList();
        _rebuilding = true;
        try
        {
            _events.DataSource = rows;
            _events.ClearSelection();
        }
        finally { _rebuilding = false; }
    }

    private bool _apMapDirty;

    private string WithBssid(string storedAp, string bssid)
    {
        string name = ApName(bssid); if (name.Length == 0) name = storedAp;
        return name.Length > 0 ? $"{name} ({bssid[^8..]})" : bssid;
    }

    private static string KindText(WifiEventKind k) => k switch
    {
        WifiEventKind.Roam => "Roam", WifiEventKind.RoamStart => "Roam start", WifiEventKind.Connect => "Connect", WifiEventKind.Disconnect => "Disconnect",
        WifiEventKind.ConnectFail => "Connect failed", _ => "Info",
    };

    private void OnEventSelected()
    {
        if (_rebuilding || _events.SelectedRows.Count == 0) return;
        if (_events.SelectedRows[0].DataBoundItem is EventRow r) _chart.CenterOn(r.When);
    }

    // ---------------------------------------------------------------- AP names

    private void ImportMap()
    {
        using var dlg = new OpenFileDialog { Title = "Import AP names (CSV: BSSID prefix, AP name, location)", Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var res = ApMapImporter.ParseFile(dlg.FileName);
            ApplyMap(res, dlg.FileName, silent: false);
            _settings.ApMapPath = dlg.FileName; SaveSettings();
        }
        catch (Exception ex) { MessageBox.Show(this, "Could not read the file:\r\n" + ex.Message, "Import AP names", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void ApplyMap(ApMapImportResult res, string source, bool silent)
    {
        _apMap = res.Map;
        _mapInfo.Text = $"{res.Map.Count} AP names ({(source == "demo" ? "demo" : Path.GetFileName(source))})";
        _apMapDirty = true;
        if (!silent && res.Errors.Count > 0)
        {
            var sb = new StringBuilder($"{res.Map.Count} entries imported, {res.Errors.Count} line(s) skipped:\r\n\r\n");
            foreach (var e in res.Errors.Take(15)) sb.AppendLine(e);
            if (res.Errors.Count > 15) sb.AppendLine($"… and {res.Errors.Count - 15} more");
            MessageBox.Show(this, sb.ToString(), "Import AP names", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        _chart.ApName = ApName;
        RefreshEvents(true);
        _chart.Tick();
        _visible.ReloadCached();
    }

    private void OptionsChanged()
    {
        _apMapDirty = true; SaveSettings();
        RefreshEvents(true);
        _visible.ReloadCached();
    }

    // ---------------------------------------------------------------- location banner

    private void CheckLocation()
    {
        if (_api is null || SelectedIface is not { } id) return;
        try { _loc = LocationCheck.Evaluate(_api.QueryConnection(id)); }
        catch { return; }
        UpdateBannerFromState();
    }

    private void UpdateBannerFromState()
    {
        if (_loc == LocationState.Blocked) SetBanner(LocationCheck.Steps, true);
        else if (_banner.Visible && _bannerBtn.Visible) _banner.Visible = false;
    }

    private void SetBanner(string text, bool locationButton)
    {
        _bannerText.Text = text; _bannerBtn.Visible = locationButton; _banner.Visible = true;
        _banner.BackColor = locationButton ? System.Drawing.Color.FromArgb(255, 244, 206) : System.Drawing.Color.FromArgb(253, 226, 226);
        _banner.Height = locationButton ? 50 : 30;
    }

    private static void OpenLocationSettings()
    {
        try { Process.Start(new ProcessStartInfo("ms-settings:privacy-location") { UseShellExecute = true }); } catch { }
    }

    // ---------------------------------------------------------------- logs, export

    private void OpenFolder()
    {
        string path = _writer?.Folder ?? _lastFolder ?? _settings.EffectiveLogFolder;
        try { Directory.CreateDirectory(path); Process.Start(new ProcessStartInfo("explorer.exe", $"\"{path}\"") { UseShellExecute = true }); }
        catch (Exception ex) { _status.Text = "Cannot open folder: " + ex.Message; }
    }

    private void ChooseLogFolder()
    {
        using var dlg = new FolderBrowserDialog { Description = "Folder that will contain one timestamped sub-folder per logging session", SelectedPath = _settings.EffectiveLogFolder, UseDescriptionForTitle = true };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        _settings.LogFolder = dlg.SelectedPath; SaveSettings();
        _status.Text = "New sessions will be logged under " + dlg.SelectedPath;
    }

    private async Task OpenLogAsync()
    {
        using var dlg = new OpenFileDialog { Title = "Open an earlier log (samples.csv, events.csv or pings.csv)", Filter = "Wi-Fi Roam Log CSV (*.csv)|*.csv", InitialDirectory = Directory.Exists(_settings.EffectiveLogFolder) ? _settings.EffectiveLogFolder : "" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        _loadCts = new CancellationTokenSource();
        _cancelLoad.Visible = true; _status.Text = "Loading log…"; UseWaitCursor = true;
        try
        {
            var ct = _loadCts.Token;
            var loaded = await Task.Run(() => SessionLogReader.Load(dlg.FileName, ct), ct);
            _view = SessionLogReader.ToSessionData(loaded); _viewPath = loaded.Folder;
            _viewText.Text = $"Viewing log {loaded.Folder}  ({loaded.Samples.Length} samples, {loaded.Events.Length} events, {loaded.Pings.Length} pings" + (loaded.SkippedLines > 0 ? $", {loaded.SkippedLines} unreadable lines skipped" : "") + ")";
            _viewBanner.Visible = true;
            _chart.SetData(_view, false); _follow.Checked = false;
            _tabs.SelectedIndex = 0;
            RefreshEvents(true);
            _status.Text = "Opened " + loaded.Folder;
        }
        catch (OperationCanceledException) { _status.Text = "Loading cancelled"; }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Open log", MessageBoxButtons.OK, MessageBoxIcon.Error); _status.Text = "Could not open the log"; }
        finally { _cancelLoad.Visible = false; UseWaitCursor = false; UpdateTitle(); }
    }

    private void BackToLive()
    {
        _view = null; _viewPath = null; _viewBanner.Visible = false;
        _chart.SetData(_live, true); _follow.Checked = true;
        RefreshEvents(true); UpdateTitle();
        _status.Text = "Back to live view";
    }

    private IEnumerable<WifiEvent> CurrentEventsForExport()
    {
        var all = ShownData.Events();
        var sel = _events.SelectedRows.Cast<DataGridViewRow>().Select(r => r.DataBoundItem as EventRow).Where(r => r is not null).Select(r => r!.When).ToHashSet();
        var list = sel.Count > 1 ? all.Where(e => sel.Contains(e.Time)) : all;
        return list.Select(e => e with { OldAp = e.OldBssid.Length > 0 ? ApNameOr(e.OldBssid, e.OldAp) : "", NewAp = e.NewBssid.Length > 0 ? ApNameOr(e.NewBssid, e.NewAp) : "" });
    }

    private string ApNameOr(string bssid, string stored) { var n = ApName(bssid); return n.Length > 0 ? n : stored; }

    private void CopyEvents()
    {
        var text = EventExport.ToText(CurrentEventsForExport());
        try { Clipboard.SetText(text); _status.Text = "Events copied to the clipboard"; } catch (Exception ex) { _status.Text = "Clipboard unavailable: " + ex.Message; }
    }

    private void ExportEvents()
    {
        using var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv|Text (*.txt)|*.txt", FileName = $"wifi-events-{DateTime.Now:yyyyMMdd-HHmm}.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var ev = CurrentEventsForExport();
            File.WriteAllText(dlg.FileName, dlg.FileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ? EventExport.ToText(ev) : EventExport.ToCsv(ev), new UTF8Encoding(true));
            _status.Text = "Events exported to " + dlg.FileName;
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void ExportPng()
    {
        using var dlg = new SaveFileDialog { Filter = "PNG image (*.png)|*.png", FileName = $"wifi-charts-{DateTime.Now:yyyyMMdd-HHmm}.png" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            string title = "Wi-Fi Roam Log  " + (_view is not null ? $"({_viewPath})" : DateTime.Now.ToString("yyyy-MM-dd HH:mm")) + "   window: " + _window.Text;
            _chart.ExportPng(dlg.FileName, title);
            _status.Text = "Charts saved to " + dlg.FileName;
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export PNG", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    // ---------------------------------------------------------------- tray / closing

    private void RestoreFromTray()
    {
        Show(); WindowState = FormWindowState.Normal; Activate();
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (_exiting || e.CloseReason != CloseReason.UserClosing || !_running) return;
        bool toTray;
        if (_settings.CloseToTray is { } remembered) toTray = remembered;
        else
        {
            var r = MessageBox.Show(this, "Logging is running.\r\n\r\nYes = keep logging in the system tray (the window just hides).\r\nNo = stop logging and exit.\r\n\r\nYour answer is remembered; you can change it from the tray icon menu.",
                "Wi-Fi Roam Log", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (r == DialogResult.Cancel) { e.Cancel = true; return; }
            toTray = r == DialogResult.Yes;
            _settings.CloseToTray = toTray; _trayClose.Checked = toTray; _settings.Save();
        }
        if (toTray) { e.Cancel = true; Hide(); }
    }

    private void ExitApp()
    {
        _exiting = true;
        Close();
        if (!IsDisposed) Application.Exit();
    }

    private void Cleanup()
    {
        _exiting = true;
        _tick.Stop();
        SaveSettings();
        try
        {
            _cts?.Cancel();
            _runTask?.Wait(5000);   // stops pings, unregisters notifications and finalises the CSV files
        }
        catch { }
        _writer?.Dispose();
        _tray.Visible = false; _tray.Dispose();
        _api?.Dispose();                   // closes the WLAN handle
    }

    private void SaveSettings()
    {
        _settings.IntervalSeconds = (int)_interval.Value; _settings.Target = _target.Text.Trim();
        _settings.PrefixOctets = (int)_prefix.Value; _settings.IgnoreFirstOctet = _ignoreFirst.Checked;
        _settings.WindowMinutes = WindowMinutesFromCombo();
        if (SelectedIface is { } id) _settings.AdapterGuid = id.ToString();
        _settings.Save();
    }

    // ---------------------------------------------------------------- screenshots

    private async Task TakeScreenshotAsync()
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(_opt.ShotDelaySeconds));
            if (_opt.ScreenshotTab == "visible") { _tabs.SelectedIndex = 1; await Task.Delay(2500); }
            else if (_events.Rows.Count > 1) { _events.Rows[1].Selected = true; await Task.Delay(800); }
            using var bmp = new Bitmap(Width, Height);
            DrawToBitmap(bmp, new Rectangle(0, 0, Width, Height));
            bmp.Save(_opt.Screenshot!, System.Drawing.Imaging.ImageFormat.Png);
        }
        catch (Exception ex) { File.WriteAllText(_opt.Screenshot + ".err.txt", ex.ToString()); }
        finally { _exiting = true; Application.Exit(); }
    }
}

/// <summary>Small caption + value tile for the status header.</summary>
internal sealed class StatCard : Panel
{
    private readonly Label _cap = new() { AutoSize = false, Dock = DockStyle.Top, Height = 16, ForeColor = SystemColors.GrayText, Font = new Font("Segoe UI", 8f) };
    private readonly Label _val = new() { AutoSize = false, Dock = DockStyle.Fill, Font = new Font("Segoe UI", 10.5f, FontStyle.Bold), TextAlign = ContentAlignment.TopLeft, AutoEllipsis = true };

    public StatCard(string caption, int width)
    {
        Width = width; Height = 40; Margin = new Padding(2, 1, 6, 1);
        _cap.Text = caption; _val.Text = "–";
        Controls.Add(_val); Controls.Add(_cap);
    }

    public void SetValue(string text, System.Drawing.Color? color)
    {
        if (_val.Text != text) _val.Text = text;
        var c = color ?? SystemColors.ControlText;
        if (_val.ForeColor != c) _val.ForeColor = c;
    }
}
