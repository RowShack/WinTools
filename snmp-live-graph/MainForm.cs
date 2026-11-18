using System.Text;
using SnmpLiveGraph.Core;

namespace SnmpLiveGraph;

public sealed class MainForm : Form
{
    private sealed class Device
    {
        public SnmpTarget Target = null!;
        public SnmpSession Session = null!;
        public List<InterfaceInfo> Interfaces = [];
        public HashSet<int> Selected = [];
        public DevicePoller? Poller;
        public CancellationTokenSource? Cts;
        public Dictionary<int, Threshold> Thresholds = [];
        public List<CustomOidSpec> CustomOids = [];
        public string Health = "";
        public override string ToString() => Target + (Health.Length > 0 ? "  (" + Health + ")" : "");
    }

    private readonly List<Device> _devices = [];
    private readonly Dictionary<string, Tile> _tiles = [];
    private readonly Dictionary<string, OidTile> _oidTiles = [];
    private readonly StatusLog _statusLog = new();
    private readonly ListView _logView = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false };
    private readonly ListBox _deviceList = new() { Dock = DockStyle.Top, Height = 130, IntegralHeight = false };
    private readonly TextBox _search = new() { Dock = DockStyle.Top, PlaceholderText = "search interfaces (name, description)…" };
    private readonly CheckedListBox _ifList = new() { Dock = DockStyle.Fill, CheckOnClick = true, IntegralHeight = false };
    private readonly NumericUpDown _interval = new() { Minimum = 1, Maximum = 60, Value = 5, Width = 60 };
    private readonly ComboBox _window = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 90 };
    private readonly Button _pause = new() { Text = "Pause", Width = 90, Height = 30 };
    private readonly FlowLayoutPanel _tilePanel = new() { Dock = DockStyle.Fill, AutoScroll = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
    private readonly ToolStripStatusLabel _status = new("Add a device to start.");
    private readonly System.Windows.Forms.Timer _redraw = new() { Interval = 1000 };
    private bool _paused;
    private bool _updatingChecks;
    private Device? Current => _deviceList.SelectedItem as Device;

    public MainForm()
    {
        Text = "SNMP Live Graph";
        Size = new Size(1300, 860);
        MinimumSize = new Size(1000, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        _window.Items.AddRange(["5 min", "15 min", "1 hour"]); _window.SelectedIndex = 1;

        var devButtons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        devButtons.Controls.AddRange([Btn("Add device…", async () => await AddDeviceAsync()), Btn("Edit…", async () => await EditDeviceAsync()),
            Btn("Remove", RemoveDevice), Btn("Rediscover", async () => { if (Current != null) await DiscoverAsync(Current); }),
            Btn("Graph an OID…", AddOid)]);

        var left = new Panel { Dock = DockStyle.Left, Width = 400, Padding = new Padding(6) };
        var ifBox = new GroupBox { Text = "Interfaces of the selected device (tick to graph)", Dock = DockStyle.Fill, Padding = new Padding(6) };
        ifBox.Controls.Add(_ifList); ifBox.Controls.Add(_search);
        var devBox = new GroupBox { Text = "Devices", Dock = DockStyle.Top, Height = 215, Padding = new Padding(6) };
        devBox.Controls.Add(_deviceList); devBox.Controls.Add(devButtons);
        left.Controls.Add(ifBox); left.Controls.Add(devBox);

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6), WrapContents = true };
        bar.Controls.AddRange([new Label { Text = "Poll every", AutoSize = true, Margin = new Padding(0, 8, 4, 0) }, _interval, new Label { Text = "s", AutoSize = true, Margin = new Padding(2, 8, 12, 0) },
            new Label { Text = "Show last", AutoSize = true, Margin = new Padding(0, 8, 4, 0) }, _window, new Label { Width = 12 },
            _pause, Btn("Clear", ClearAll), Btn("Export CSV…", ExportCsv), Btn("Export all PNGs…", ExportPngs), Btn("Save session…", SaveSession), Btn("Load session…", async () => await LoadSessionAsync())]);
        var right = new Panel { Dock = DockStyle.Fill };
        right.Controls.Add(_tilePanel); right.Controls.Add(BuildLogPanel()); right.Controls.Add(bar);

        var statusBar = new StatusStrip(); statusBar.Items.Add(_status);
        Controls.Add(right); Controls.Add(left); Controls.Add(statusBar);

        _tilePanel.SizeChanged += (_, _) => FitTiles();
        _deviceList.SelectedIndexChanged += (_, _) => ShowInterfaces();
        _search.TextChanged += (_, _) => ShowInterfaces();
        _ifList.ItemCheck += (_, e) => { if (!_updatingChecks) BeginInvoke(() => OnItemChecked((InterfaceInfo)_ifList.Items[e.Index], e.NewValue == CheckState.Checked)); };
        _interval.ValueChanged += (_, _) => RestartPollers();
        _window.SelectedIndexChanged += (_, _) => { foreach (var t in _tiles.Values) t.SetWindow(Window()); foreach (var t in _oidTiles.Values) t.SetWindow(Window()); };
        _pause.Click += (_, _) => TogglePause();
        _redraw.Tick += (_, _) => { if (!_paused) { foreach (var t in _tiles.Values) t.Redraw(); foreach (var t in _oidTiles.Values) t.Redraw(); } };
        _redraw.Start();
        FormClosing += (_, _) => { foreach (var d in _devices) d.Cts?.Cancel(); };
    }

    private void FitTiles()
    {
        int w = Math.Max(300, _tilePanel.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 12);
        foreach (var t in _tiles.Values) t.Width = w;
        foreach (var t in _oidTiles.Values) t.Width = w;
    }

    private Control BuildLogPanel()
    {
        _logView.Columns.Add("Time", 150); _logView.Columns.Add("Device", 140); _logView.Columns.Add("Interface", 130); _logView.Columns.Add("Change", 200);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Right, Width = 110, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        buttons.Controls.AddRange([Btn("Copy", CopyLog), Btn("Export…", ExportLog), Btn("Clear", ClearLog)]);
        var box = new GroupBox { Text = "Interface status changes (while watching)", Dock = DockStyle.Bottom, Height = 150, Padding = new Padding(6) };
        box.Controls.Add(_logView); box.Controls.Add(buttons);
        return box;
    }

    private void OnStatusChange(StatusChange c)
    {
        _statusLog.Add(c);
        var item = new ListViewItem([c.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"), c.Device, c.Interface, $"{c.FromText} → {c.ToText}"])
        { ForeColor = c.WentDown ? Color.Firebrick : c.CameUp ? Color.SeaGreen : SystemColors.ControlText };
        _logView.Items.Insert(0, item);
        _status.Text = $"{c.Device} {c.Interface}: {c.FromText} → {c.ToText}";
    }

    private void CopyLog()
    {
        if (_statusLog.Items.Count == 0) return;
        Clipboard.SetText(_statusLog.ToText());
        _status.Text = $"Copied {_statusLog.Items.Count} status change(s) to the clipboard.";
    }

    private void ExportLog()
    {
        if (_statusLog.Items.Count == 0) { MessageBox.Show(this, "No status changes recorded yet.", Text); return; }
        using var d = new SaveFileDialog { FileName = "interface-status-changes.csv", Filter = "CSV|*.csv|Text|*.txt" };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllText(d.FileName, d.FilterIndex == 2 ? _statusLog.ToText() : _statusLog.ToCsv(), Encoding.UTF8);
        _status.Text = "Exported " + d.FileName;
    }

    private void ClearLog() { _statusLog.Clear(); _logView.Items.Clear(); }

    private static Button Btn(string t, Action a) { var b = new Button { Text = t, AutoSize = true }; b.Click += (_, _) => a(); return b; }
    private TimeSpan Window() => _window.SelectedIndex switch { 0 => TimeSpan.FromMinutes(5), 2 => TimeSpan.FromHours(1), _ => TimeSpan.FromMinutes(15) };

    // ================= devices =================

    private async Task AddDeviceAsync()
    {
        using var dlg = new AddDeviceDialog();
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var d = new Device { Target = dlg.Result };
        d.Session = new SnmpSession(d.Target);
        _devices.Add(d); _deviceList.Items.Add(d); _deviceList.SelectedItem = d;
        await DiscoverAsync(d);
    }

    private async Task EditDeviceAsync()
    {
        if (Current is not { } d) return;
        using var dlg = new AddDeviceDialog(d.Target);
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        d.Cts?.Cancel();
        d.Target = dlg.Result; d.Session = new SnmpSession(d.Target); d.Poller = null;
        _deviceList.Items[_deviceList.SelectedIndex] = d;
        await DiscoverAsync(d);
        StartPoller(d);
    }

    private void RemoveDevice()
    {
        if (Current is not { } d) return;
        d.Cts?.Cancel();
        foreach (var key in _tiles.Keys.Where(k => k.StartsWith(DeviceKey(d) + "|")).ToList()) RemoveTile(key);
        foreach (var key in _oidTiles.Keys.Where(k => k.StartsWith(DeviceKey(d) + "|")).ToList()) RemoveOidTile(key);
        _devices.Remove(d); _deviceList.Items.Remove(d); _ifList.Items.Clear();
    }

    private static string DeviceKey(Device d) => $"{d.Target.Host}:{d.Target.Port}";

    private async Task DiscoverAsync(Device d)
    {
        _status.Text = $"Discovering interfaces on {d.Target}…"; UseWaitCursor = true;
        try
        {
            var info = await d.Session.GetSystemInfoAsync(default);
            if (d.Target.Name.Length == 0) d.Target.Name = info.Name.Length > 0 ? info.Name : d.Target.Host;
            d.Interfaces = await InterfaceDiscovery.DiscoverAsync(d.Session, default);
            d.Health = "";
            _status.Text = $"{d.Target}: {d.Interfaces.Count} interfaces — {info.Description.Split('\n')[0]}";
        }
        catch (Exception ex)
        {
            d.Health = "unreachable";
            _status.Text = $"{d.Target}: {ex.Message}";
            MessageBox.Show(this, ex.Message, "Interface discovery failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { UseWaitCursor = false; RefreshDeviceList(d); ShowInterfaces(); }
    }

    private void RefreshDeviceList(Device d)
    {
        int i = _deviceList.Items.IndexOf(d);
        if (i >= 0) { _updatingChecks = true; _deviceList.Items[i] = d; _updatingChecks = false; }
    }

    private void ShowInterfaces()
    {
        _updatingChecks = true;
        _ifList.Items.Clear();
        if (Current is { } d)
        {
            string q = _search.Text.Trim();
            foreach (var i in d.Interfaces.Where(i => q.Length == 0 || i.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || i.Alias.Contains(q, StringComparison.OrdinalIgnoreCase)))
                _ifList.Items.Add(i, d.Selected.Contains(i.Index));
        }
        _updatingChecks = false;
    }

    private void OnItemChecked(InterfaceInfo i, bool on)
    {
        if (Current is not { } d) return;
        string key = $"{DeviceKey(d)}|{i.Index}";
        if (on)
        {
            d.Selected.Add(i.Index);
            if (!_tiles.ContainsKey(key)) AddTile(d, i);
        }
        else { d.Selected.Remove(i.Index); RemoveTile(key); }
        ApplySelection(d);
    }

    private void AddTile(Device d, InterfaceInfo i)
    {
        string key = $"{DeviceKey(d)}|{i.Index}";
        var t = new Tile(key, d.Target.ToString(), i);
        t.SetWindow(Window()); t.Pause(_paused); t.CloseRequested += UncheckTile;
        t.SetThreshold(d.Thresholds.GetValueOrDefault(i.Index));
        t.ThresholdChanged += tt => { if (tt.Threshold is { } th) d.Thresholds[tt.If.Index] = th; else d.Thresholds.Remove(tt.If.Index); };
        _tiles[key] = t; _tilePanel.Controls.Add(t); FitTiles();
    }

    private void AddOid()
    {
        if (Current is not { } d) { MessageBox.Show(this, "Add or select a device first.", Text); return; }
        using var dlg = new AddOidDialog(d.Session, d.Target.ToString());
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        if (d.CustomOids.Any(c => c.Oid == dlg.Result.Oid)) { _status.Text = "That OID is already graphed for this device."; return; }
        d.CustomOids.Add(dlg.Result);
        AddOidTile(d, dlg.Result);
        ApplySelection(d);
    }

    private void AddOidTile(Device d, CustomOidSpec spec)
    {
        string key = $"{DeviceKey(d)}|oid|{spec.Oid}";
        var t = new OidTile(key, d.Target.ToString(), spec);
        t.SetWindow(Window()); t.Pause(_paused);
        t.CloseRequested += tt => { d.CustomOids.RemoveAll(c => c.Oid == tt.Spec.Oid); RemoveOidTile(tt.Key); ApplySelection(d); };
        _oidTiles[key] = t; _tilePanel.Controls.Add(t); FitTiles();
    }

    private void RemoveOidTile(string key)
    {
        if (_oidTiles.Remove(key, out var t)) { _tilePanel.Controls.Remove(t); t.Dispose(); }
    }

    private void UncheckTile(Tile t)
    {
        foreach (var d in _devices)
            if (t.Key.StartsWith(DeviceKey(d) + "|")) { d.Selected.Remove(t.If.Index); ApplySelection(d); }
        RemoveTile(t.Key);
        ShowInterfaces();
    }

    private void RemoveTile(string key)
    {
        if (_tiles.Remove(key, out var t)) { _tilePanel.Controls.Remove(t); t.Dispose(); }
    }

    private void ApplySelection(Device d)
    {
        var chosen = d.Interfaces.Where(i => d.Selected.Contains(i.Index)).ToList();
        if (chosen.Count == 0 && d.CustomOids.Count == 0) { d.Cts?.Cancel(); d.Poller = null; _status.Text = "Nothing selected for " + d.Target; return; }
        if (d.Poller == null) { d.Poller = MakePoller(d, chosen); StartPoller(d); }
        else { d.Poller.SetInterfaces(chosen); d.Poller.SetCustomOids(d.CustomOids); }
    }

    // ================= polling =================

    private DevicePoller MakePoller(Device d, List<InterfaceInfo> chosen)
    {
        var p = new DevicePoller(d.Session, chosen);
        p.SetCustomOids(d.CustomOids);
        p.StatusChanged += c => { if (!IsDisposed) BeginInvoke(() => OnStatusChange(c)); };
        p.CustomPoint += (spec, cp) => { if (!IsDisposed) BeginInvoke(() => { if (_oidTiles.TryGetValue($"{DeviceKey(d)}|oid|{spec.Oid}", out var t)) t.Add(cp); }); };
        p.Point += (iface, pt) => { if (!IsDisposed) BeginInvoke(() => { if (_tiles.TryGetValue($"{DeviceKey(d)}|{iface.Index}", out var t)) t.Add(pt); }); };
        p.Error += msg => { if (!IsDisposed) BeginInvoke(() => { d.Health = "no response"; RefreshDeviceList(d); _status.Text = $"{d.Target}: {msg}"; }); };
        p.Recovered += () => { if (!IsDisposed) BeginInvoke(() => { d.Health = ""; RefreshDeviceList(d); _status.Text = $"{d.Target}: polling again"; }); };
        return p;
    }

    private void StartPoller(Device d)
    {
        d.Cts?.Cancel();
        if (_paused) return;
        var chosen = d.Interfaces.Where(i => d.Selected.Contains(i.Index)).ToList();
        if (chosen.Count == 0 && d.CustomOids.Count == 0) return;
        d.Poller ??= MakePoller(d, chosen);
        d.Cts = new CancellationTokenSource();
        var poller = d.Poller; var ct = d.Cts.Token; var every = TimeSpan.FromSeconds((double)_interval.Value);
        _ = Task.Run(() => poller.RunAsync(every, ct));
        _status.Text = $"Polling {d.Target} every {_interval.Value} s";
    }

    private void RestartPollers() { foreach (var d in _devices) StartPoller(d); }

    private void TogglePause()
    {
        _paused = !_paused;
        _pause.Text = _paused ? "Resume" : "Pause";
        foreach (var t in _tiles.Values) t.Pause(_paused);
        foreach (var t in _oidTiles.Values) t.Pause(_paused);
        if (_paused) { foreach (var d in _devices) d.Cts?.Cancel(); _status.Text = "Paused"; }
        else RestartPollers();
    }

    private void ClearAll() { foreach (var t in _tiles.Values) t.Clear(); foreach (var t in _oidTiles.Values) t.Clear(); }

    // ================= export / session =================

    private void ExportCsv()
    {
        if (_tiles.Count == 0 && _oidTiles.Count == 0) return;
        using var d = new SaveFileDialog { FileName = "snmp-live-graph.csv", Filter = "CSV|*.csv" };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        var rows = _tiles.Values.SelectMany(t => t.History.Points.Select(p => (t.Series, p))).OrderBy(r => r.p.Time);
        File.WriteAllText(d.FileName, CsvExport.Build(rows), Encoding.UTF8);
        _status.Text = "Exported " + d.FileName;
        if (_oidTiles.Count > 0)
        {
            string oidFile = Path.Combine(Path.GetDirectoryName(d.FileName)!, Path.GetFileNameWithoutExtension(d.FileName) + "-oids.csv");
            var orows = _oidTiles.Values.SelectMany(t => t.History.Points.Select(p => (t.Series, p))).OrderBy(r => r.p.Time);
            File.WriteAllText(oidFile, CsvExport.BuildCustom(orows), Encoding.UTF8);
            _status.Text = $"Exported {d.FileName} and {oidFile}";
        }
    }

    private void ExportPngs()
    {
        if (_tiles.Count == 0 && _oidTiles.Count == 0) return;
        using var d = new FolderBrowserDialog { Description = "Folder for the chart images" };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        foreach (var t in _tiles.Values) t.SavePng(Path.Combine(d.SelectedPath, t.Series.Replace('/', '-').Replace(' ', '_').Replace(':', '-') + ".png"));
        foreach (var t in _oidTiles.Values) t.SavePng(Path.Combine(d.SelectedPath, t.Series.Replace('/', '-').Replace(' ', '_').Replace(':', '-') + ".png"));
        _status.Text = $"Saved {_tiles.Count + _oidTiles.Count} image(s) to {d.SelectedPath}";
    }

    private void SaveSession()
    {
        using var d = new SaveFileDialog { FileName = "snmp-session.json", Filter = "Session|*.json" };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        var s = new SavedSession { IntervalSeconds = (int)_interval.Value, WindowMinutes = (int)Window().TotalMinutes };
        foreach (var dev in _devices) s.Devices.Add(SessionStore.ToSaved(dev.Target, dev.Interfaces.Where(i => dev.Selected.Contains(i.Index)), dev.Thresholds, dev.CustomOids));
        SessionStore.Save(d.FileName, s);
        _status.Text = "Session saved (passwords and communities are encrypted for your Windows account).";
    }

    private async Task LoadSessionAsync()
    {
        using var d = new OpenFileDialog { Filter = "Session|*.json" };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        SavedSession s;
        try { s = SessionStore.Load(d.FileName); } catch (Exception ex) { MessageBox.Show(this, "Couldn't read the session file: " + ex.Message, Text); return; }
        _interval.Value = Math.Clamp(s.IntervalSeconds, 1, 60);
        _window.SelectedIndex = s.WindowMinutes <= 5 ? 0 : s.WindowMinutes >= 60 ? 2 : 1;
        foreach (var sd in s.Devices)
        {
            var dev = new Device { Target = SessionStore.ToTarget(sd) };
            dev.Session = new SnmpSession(dev.Target);
            _devices.Add(dev); _deviceList.Items.Add(dev); _deviceList.SelectedItem = dev;
            dev.Thresholds = sd.Thresholds.Where(kv => kv.Value.IsSet).ToDictionary(kv => kv.Key, kv => kv.Value);
            dev.CustomOids = sd.CustomOids.Where(c => CustomOidSpec.Validate(c.Oid) is null).ToList();
            await DiscoverAsync(dev);
            foreach (var spec in dev.CustomOids) AddOidTile(dev, spec);
            foreach (var idx in sd.InterfaceIndexes)
            {
                var iface = dev.Interfaces.FirstOrDefault(i => i.Index == idx);
                if (iface == null) continue;
                dev.Selected.Add(idx);
                if (!_tiles.ContainsKey($"{DeviceKey(dev)}|{idx}")) AddTile(dev, iface);
            }
            ShowInterfaces(); ApplySelection(dev);
        }
    }
}
