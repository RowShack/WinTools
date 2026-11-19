using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using PortProbe.Core;

namespace PortProbe;

public sealed class MainForm : Form
{
    private readonly bool _isAdmin = FirewallManager.IsAdmin();
    private readonly ToolStripStatusLabel _status = new("Ready");
    private CancellationTokenSource? _cts;

    // ---- listener tab ----
    private readonly TextBox _lPorts = new() { Width = 360, Text = "443, 8080-8090, udp:514" };
    private readonly ComboBox _lBind = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 260 };
    private readonly CheckBox _lFw = new() { Text = "Add temporary Windows Firewall allow rules (removed on stop / exit)", AutoSize = true };
    private readonly Button _lStart = new() { Text = "Start listening", Width = 130, Height = 30 };
    private readonly Button _lStop = new() { Text = "Stop", Width = 90, Height = 30, Enabled = false };
    private readonly Label _lFwStatus = new() { AutoSize = true, MaximumSize = new Size(900, 0) };
    private readonly TextBox _lLog = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font(FontFamily.GenericMonospace, 9f) };
    private PortListener? _listener;
    private bool _rulesAdded;

    // ---- probe tab ----
    private readonly TextBox _pHost = new() { Width = 260, PlaceholderText = "host name or IP" };
    private readonly TextBox _pPorts = new() { Width = 360, Text = "443, 8080-8090, udp:514" };
    private readonly NumericUpDown _pTimeout = new() { Minimum = 200, Maximum = 30000, Value = 2000, Increment = 250, Width = 75 };
    private readonly NumericUpDown _pParallel = new() { Minimum = 1, Maximum = 500, Value = 50, Width = 65 };
    private readonly Button _pStart = new() { Text = "Probe", Width = 110, Height = 30 };
    private readonly Button _pCancel = new() { Text = "Cancel", Width = 90, Height = 30, Enabled = false };
    private readonly Button _pCsv = new() { Text = "Export CSV…", AutoSize = true, Enabled = false };
    private readonly Button _pCopy = new() { Text = "Copy table", AutoSize = true, Enabled = false };
    private readonly Button _pTicket = new() { Text = "Copy as ticket text", AutoSize = true, Enabled = false };
    private readonly ProgressBar _pBar = new() { Width = 200, Style = ProgressBarStyle.Continuous };
    private readonly DataGridView _pGrid = MakeGrid();
    private readonly Label _pExplain = new() { Dock = DockStyle.Bottom, Height = 54, Padding = new Padding(6), BackColor = SystemColors.Info };
    private readonly List<PortResult> _pResults = [];
    private string _pTargetText = "";

    // ---- quick check tab ----
    private readonly TextBox _qInput = new() { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Vertical, AcceptsReturn = true, Font = new Font(FontFamily.GenericMonospace, 9.5f), Text = "example.com:443\r\n" };
    private readonly Button _qRun = new() { Text = "Check", Width = 110, Height = 30 };
    private readonly Button _qCancel = new() { Text = "Cancel", Width = 90, Height = 30, Enabled = false };
    private readonly Button _qCsv = new() { Text = "Export CSV…", AutoSize = true, Enabled = false };
    private readonly Button _qCopy = new() { Text = "Copy table", AutoSize = true, Enabled = false };
    private readonly DataGridView _qGrid = MakeGrid();

    private static DataGridView MakeGrid() => new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToResizeRows = false, RowHeadersVisible = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells,
        BackgroundColor = SystemColors.Window,
    };

    public MainForm()
    {
        Text = "Port Probe";
        Size = new Size(1150, 780);
        MinimumSize = new Size(900, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.AddRange([BuildProbeTab(), BuildListenerTab(), BuildQuickTab()]);
        var bar = new StatusStrip();
        bar.Items.Add(_status);
        Controls.Add(tabs);
        Controls.Add(bar);

        foreach (var c in new[] { "Protocol", "Port", "State", "Latency (ms)", "Banner / detail", "What it means" }) _pGrid.Columns.Add(c, c);
        foreach (var c in new[] { "Host", "Port", "TCP", "TLS", "Protocol", "Certificate subject", "Issuer", "Expires", "Days left", "Certificate problems" }) _qGrid.Columns.Add(c, c);

        _pStart.Click += async (_, _) => await ProbeAsync();
        _pCancel.Click += (_, _) => _cts?.Cancel();
        _pCsv.Click += (_, _) => Save("port-probe.csv", Csv(_pGrid));
        _pCopy.Click += (_, _) => Clipboard.SetText(Tsv(_pGrid));
        _pTicket.Click += (_, _) => Clipboard.SetText(TicketText());
        _pGrid.SelectionChanged += (_, _) => _pExplain.Text = _pGrid.CurrentRow?.Cells[5].Value?.ToString() ?? "";
        _lStart.Click += async (_, _) => await StartListenerAsync();
        _lStop.Click += async (_, _) => await StopListenerAsync();
        _qRun.Click += async (_, _) => await QuickAsync();
        _qCancel.Click += (_, _) => _cts?.Cancel();
        _qCsv.Click += (_, _) => Save("quick-check.csv", Csv(_qGrid));
        _qCopy.Click += (_, _) => Clipboard.SetText(Tsv(_qGrid));
        FormClosing += (_, _) => Cleanup();
        Shown += async (_, _) => await OnShownAsync();
    }

    // ================= layout =================

    private TabPage BuildProbeTab()
    {
        var page = new TabPage("Probe a host") { Padding = new Padding(10) };
        var form = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Top };
        void Row(string l, Control c) { form.Controls.Add(new Label { Text = l, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 12, 6) }); form.Controls.Add(c); }
        Row("Target host:", _pHost);
        Row("Ports:", _pPorts);
        var o = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        o.Controls.AddRange([_pTimeout, new Label { Text = "ms timeout    parallel probes:", AutoSize = true, Margin = new Padding(6, 6, 6, 0) }, _pParallel]);
        Row("Options:", o);
        var b = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 6) };
        b.Controls.AddRange([_pStart, _pCancel, _pBar, _pCsv, _pCopy, _pTicket]);
        _pBar.Margin = new Padding(12, 8, 12, 0);
        form.Controls.Add(new Label()); form.Controls.Add(b);
        form.Controls.Add(new Label());
        form.Controls.Add(new Label
        {
            AutoSize = true, ForeColor = SystemColors.GrayText,
            Text = "Syntax: 443, 8080-8090, udp:514, udp:1812-1813   (TCP unless prefixed with udp:)",
        });

        var box = new GroupBox { Text = "Results", Dock = DockStyle.Fill, Padding = new Padding(6) };
        box.Controls.Add(_pGrid);
        page.Controls.Add(box);
        page.Controls.Add(_pExplain);
        page.Controls.Add(form);
        return page;
    }

    private TabPage BuildListenerTab()
    {
        var page = new TabPage("Listen on this PC") { Padding = new Padding(10) };
        var form = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Top };
        void Row(string l, Control c) { form.Controls.Add(new Label { Text = l, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 12, 6) }); form.Controls.Add(c); }
        Row("Ports:", _lPorts);
        Row("Listen on:", _lBind);
        form.Controls.Add(new Label()); form.Controls.Add(_lFw);
        var b = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 6) };
        b.Controls.AddRange([_lStart, _lStop]);
        form.Controls.Add(new Label()); form.Controls.Add(b);
        form.Controls.Add(new Label()); form.Controls.Add(_lFwStatus);

        var box = new GroupBox { Text = "Who connected", Dock = DockStyle.Fill, Padding = new Padding(6) };
        box.Controls.Add(_lLog);
        page.Controls.Add(box);
        page.Controls.Add(form);

        _lBind.Items.Add("All IPv4 interfaces (0.0.0.0)");
        _lBind.Items.Add("All IPv6 interfaces (::)");
        foreach (var ip in LocalAddresses()) _lBind.Items.Add(ip);
        _lBind.SelectedIndex = 0;
        return page;
    }

    private TabPage BuildQuickTab()
    {
        var page = new TabPage("Quick check (no listener)") { Padding = new Padding(10) };
        var input = new GroupBox { Text = "host:port list, one per line  (TCP connect + TLS handshake)", Dock = DockStyle.Left, Width = 320, Padding = new Padding(6) };
        input.Controls.Add(_qInput);
        var b = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(0, 0, 0, 6) };
        b.Controls.AddRange([_qRun, _qCancel, _qCsv, _qCopy]);
        var box = new GroupBox { Text = "Results", Dock = DockStyle.Fill, Padding = new Padding(6) };
        box.Controls.Add(_qGrid);
        var right = new Panel { Dock = DockStyle.Fill };
        right.Controls.Add(box); right.Controls.Add(b);
        page.Controls.Add(right); page.Controls.Add(input);
        return page;
    }

    private static IEnumerable<string> LocalAddresses() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(u => u.Address))
            .Where(a => !a.IsIPv6LinkLocal)
            .Select(a => a.ToString());

    // ================= startup / cleanup =================

    private async Task OnShownAsync()
    {
        // Crash recovery: remove firewall rules a previous run left behind.
        if (await FirewallManager.HasLeftoverRulesAsync())
        {
            if (_isAdmin)
            {
                await FirewallManager.RemoveRulesAsync();
                _lLog.AppendText("Removed leftover firewall rules from a previous run." + Environment.NewLine);
            }
            else
                MessageBox.Show(this, "Temporary firewall rules from a previous Port Probe run are still present (group \"WinTools PortProbe\").\n\nRestart this tool as administrator to remove them automatically.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        var fw = await FirewallManager.GetStatusAsync();
        _lFwStatus.Text = fw.Summary + (_isAdmin ? "" : "\nNot running as administrator: firewall rules cannot be added. Restart as administrator or add rules yourself.");
        _lFw.Enabled = _isAdmin;
        _lFw.Checked = _isAdmin && fw.InboundBlockedByDefault;
    }

    private void Cleanup()
    {
        try { _listener?.Dispose(); } catch { }
        if (_rulesAdded) { try { FirewallManager.RemoveRulesAsync().GetAwaiter().GetResult(); } catch { } _rulesAdded = false; }
    }

    // ================= listener =================

    private async Task StartListenerAsync()
    {
        if (!PortSpecParser.TryParse(_lPorts.Text, out var specs, out var err)) { MessageBox.Show(this, err, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
        if (specs.Count > 1000) { MessageBox.Show(this, "Please listen on 1000 ports or fewer at a time.", Text); return; }
        IPAddress bind = _lBind.SelectedIndex switch { 0 => IPAddress.Any, 1 => IPAddress.IPv6Any, _ => IPAddress.Parse((string)_lBind.SelectedItem!) };

        SetListenerUi(true);
        try
        {
            if (_lFw.Checked && _isAdmin)
            {
                _status.Text = "Adding firewall rules…";
                await FirewallManager.AddRulesAsync(specs);
                _rulesAdded = true;
                _lLog.AppendText($"Firewall: temporary allow rules added for {string.Join(" + ", new[] { PortSpecParser.Compact(specs, Proto.Tcp) is { Length: > 0 } t ? "TCP " + t : "", PortSpecParser.Compact(specs, Proto.Udp) is { Length: > 0 } u ? "UDP " + u : "" }.Where(x => x.Length > 0))}" + Environment.NewLine);
            }
            _listener = new PortListener();
            _listener.Event += e => { if (!IsDisposed) BeginInvoke(() => _lLog.AppendText(e + Environment.NewLine)); };
            var failed = _listener.Start(specs, bind);
            foreach (var (s, e) in failed) _lLog.AppendText($"Could not listen on {s}: {e}{Environment.NewLine}");
            if (_listener.ActiveCount == 0) { await StopListenerAsync(); return; }
            _lLog.AppendText($"Listening on {_listener.ActiveCount} port(s) on {bind}. Waiting for connections…{Environment.NewLine}");
            _status.Text = $"Listening on {_listener.ActiveCount} port(s)";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Couldn't start listener", MessageBoxButtons.OK, MessageBoxIcon.Error);
            await StopListenerAsync();
        }
    }

    private async Task StopListenerAsync()
    {
        _listener?.Dispose(); _listener = null;
        if (_rulesAdded)
        {
            try { await FirewallManager.RemoveRulesAsync(); _lLog.AppendText("Firewall: temporary rules removed." + Environment.NewLine); _rulesAdded = false; }
            catch (Exception ex) { _lLog.AppendText("WARNING: could not remove firewall rules (group \"WinTools PortProbe\"): " + ex.Message + Environment.NewLine); }
        }
        SetListenerUi(false);
        _status.Text = "Ready";
    }

    private void SetListenerUi(bool running)
    {
        _lStart.Enabled = !running; _lStop.Enabled = running;
        _lPorts.Enabled = _lBind.Enabled = !running;
    }

    // ================= probe =================

    private async Task<IPAddress> ResolveAsync(string host, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out var ip)) return ip;
        var all = await Dns.GetHostAddressesAsync(host, ct);
        return all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? all.FirstOrDefault()
               ?? throw new InvalidOperationException($"Could not resolve '{host}'.");
    }

    private async Task ProbeAsync()
    {
        if (_cts != null) return;
        string host = _pHost.Text.Trim();
        if (host.Length == 0) { _pHost.Focus(); return; }
        if (!PortSpecParser.TryParse(_pPorts.Text, out var specs, out var err)) { MessageBox.Show(this, err, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }

        _cts = new CancellationTokenSource();
        SetProbeUi(true);
        _pGrid.Rows.Clear(); _pResults.Clear(); _pExplain.Text = "";
        _pBar.Maximum = specs.Count; _pBar.Value = 0;
        try
        {
            var ip = await ResolveAsync(host, _cts.Token);
            _pTargetText = ip.ToString() == host ? host : $"{host} ({ip})";
            _status.Text = $"Probing {_pTargetText}…";
            var opt = new ProbeOptions { Timeout = TimeSpan.FromMilliseconds((double)_pTimeout.Value), Parallelism = (int)_pParallel.Value };
            var progress = new Progress<PortResult>(r => { _pResults.Add(r); _pBar.Value = Math.Min(_pBar.Maximum, _pResults.Count); });
            var results = await Prober.RunAsync(ip, specs, opt, progress, _cts.Token);
            _pResults.Clear(); _pResults.AddRange(results);
            foreach (var r in results) AddRow(r);
            var counts = results.GroupBy(r => r.State).Select(g => $"{g.Count()} {Label(g.Key).ToLower()}");
            _status.Text = (_cts.IsCancellationRequested ? "Cancelled — " : "Done — ") + string.Join(", ", counts);
        }
        catch (OperationCanceledException) { _status.Text = "Cancelled"; }
        catch (Exception ex) { _status.Text = "Failed"; MessageBox.Show(this, ex.Message, "Probe failed", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { _cts.Dispose(); _cts = null; SetProbeUi(false); }
    }

    private static string Label(PortState s) => s switch
    {
        PortState.OpenListener => "Open (PortProbe listener)",
        PortState.OpenOther => "Open (other service)",
        PortState.Refused => "Refused",
        PortState.Filtered => "Filtered",
        PortState.Unreachable => "Unreachable",
        PortState.NoReply => "No reply",
        _ => "Error",
    };

    private void AddRow(PortResult r)
    {
        int i = _pGrid.Rows.Add(r.Proto == Proto.Tcp ? "TCP" : "UDP", r.Port, Label(r.State), r.LatencyMs?.ToString() ?? "", r.Banner ?? r.Detail ?? "", r.Explanation);
        _pGrid.Rows[i].DefaultCellStyle.ForeColor = r.State switch
        {
            PortState.OpenListener or PortState.OpenOther => Color.FromArgb(0, 110, 40),
            PortState.Refused => Color.FromArgb(150, 90, 0),
            PortState.Filtered or PortState.Unreachable => Color.Firebrick,
            _ => SystemColors.GrayText,
        };
    }

    private void SetProbeUi(bool busy)
    {
        _pStart.Enabled = !busy; _pCancel.Enabled = busy;
        _pCsv.Enabled = _pCopy.Enabled = _pTicket.Enabled = !busy && _pGrid.Rows.Count > 0;
        UseWaitCursor = busy;
    }

    private string TicketText()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Port test from {Environment.MachineName} to {_pTargetText} on {DateTime.Now:yyyy-MM-dd HH:mm}");
        sb.AppendLine($"Timeout {_pTimeout.Value} ms. Test tool: WinTools Port Probe.");
        sb.AppendLine();
        foreach (var r in _pResults.OrderBy(r => r.Proto).ThenBy(r => r.Port))
        {
            string verdict = r.State switch
            {
                PortState.OpenListener => "OPEN (test listener answered)",
                PortState.OpenOther => "OPEN (service answered)",
                PortState.Refused => "REACHED HOST, nothing listening (refused)",
                PortState.Filtered => "NO ANSWER (blocked or dropped)",
                PortState.Unreachable => "UNREACHABLE (routing / reject)",
                PortState.NoReply => "NO REPLY (open-but-silent or blocked)",
                _ => "ERROR",
            };
            sb.AppendLine($"{(r.Proto == Proto.Tcp ? "TCP" : "UDP")} {r.Port,-5} {verdict}{(r.LatencyMs is int l ? $", {l} ms" : "")}");
        }
        sb.AppendLine();
        sb.AppendLine("Summary: " + string.Join(", ", _pResults.GroupBy(r => r.State).Select(g => $"{g.Count()} {Label(g.Key).ToLower()}")));
        return sb.ToString();
    }

    // ================= quick check =================

    private async Task QuickAsync()
    {
        if (_cts != null) return;
        var lines = _qInput.Lines.Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
        if (lines.Count == 0) return;
        var items = new List<(string host, int port)>();
        foreach (var l in lines)
        {
            int c = l.LastIndexOf(':');
            if (c <= 0 || !int.TryParse(l[(c + 1)..], out int p) || p is < 1 or > 65535)
            { MessageBox.Show(this, $"'{l}' isn't in host:port form.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            items.Add((l[..c].Trim('[', ']'), p));
        }
        _cts = new CancellationTokenSource();
        _qRun.Enabled = false; _qCancel.Enabled = true; _qGrid.Rows.Clear(); UseWaitCursor = true;
        try
        {
            using var gate = new SemaphoreSlim(8);
            var tasks = items.Select(async it =>
            {
                await gate.WaitAsync(_cts.Token);
                try
                {
                    var ip = await ResolveAsync(it.host, _cts.Token);
                    var tcp = await Prober.ProbeTcpAsync(ip, it.port, new ProbeOptions { Timeout = TimeSpan.FromSeconds(4), BannerWait = TimeSpan.FromMilliseconds(100) }, _cts.Token);
                    TlsInfo? tls = tcp.State is PortState.OpenListener or PortState.OpenOther
                        ? await Prober.CheckTlsAsync(it.host, it.port, TimeSpan.FromSeconds(5), _cts.Token) : null;
                    BeginInvoke(() => _qGrid.Rows.Add(it.host, it.port, Label(tcp.State) + (tcp.LatencyMs is int l ? $" ({l} ms)" : ""),
                        tls is null ? "—" : tls.Handshake ? "OK" : "No TLS / failed", tls?.Protocol ?? "", tls?.Subject ?? "", tls?.Issuer ?? "",
                        tls?.NotAfter?.ToString("yyyy-MM-dd") ?? "", tls?.DaysLeft?.ToString() ?? "", tls?.Errors ?? tls?.Detail ?? ""));
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { BeginInvoke(() => _qGrid.Rows.Add(it.host, it.port, "Error", "", "", "", "", "", "", ex.Message)); }
                finally { gate.Release(); }
            });
            await Task.WhenAll(tasks);
            _status.Text = $"Checked {items.Count} endpoint(s)";
        }
        catch (OperationCanceledException) { _status.Text = "Cancelled"; }
        finally
        {
            _cts.Dispose(); _cts = null; UseWaitCursor = false;
            _qRun.Enabled = true; _qCancel.Enabled = false; _qCsv.Enabled = _qCopy.Enabled = _qGrid.Rows.Count > 0;
        }
    }

    // ================= export helpers =================

    private static string Tsv(DataGridView g) => string.Join(Environment.NewLine, new[] { string.Join("\t", g.Columns.Cast<DataGridViewColumn>().Select(c => c.HeaderText)) }
        .Concat(g.Rows.Cast<DataGridViewRow>().Select(r => string.Join("\t", r.Cells.Cast<DataGridViewCell>().Select(c => c.Value?.ToString() ?? "")))));

    private static string Csv(DataGridView g)
    {
        static string Q(string s) => s.Contains(',') || s.Contains('"') || s.Contains('\n') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        return string.Join(Environment.NewLine, new[] { string.Join(",", g.Columns.Cast<DataGridViewColumn>().Select(c => Q(c.HeaderText))) }
            .Concat(g.Rows.Cast<DataGridViewRow>().Select(r => string.Join(",", r.Cells.Cast<DataGridViewCell>().Select(c => Q(c.Value?.ToString() ?? ""))))));
    }

    private void Save(string name, string text)
    {
        using var d = new SaveFileDialog { FileName = name, Filter = "CSV/Text|*.csv;*.txt|All files|*.*" };
        if (d.ShowDialog(this) == DialogResult.OK) File.WriteAllText(d.FileName, text, Encoding.UTF8);
    }
}
