using System.Net;
using System.Net.Sockets;
using System.Text;
using MtuFinder.Core;

namespace MtuFinder;

public sealed class MainForm : Form
{
    // ---- single target tab ----
    private readonly TextBox _target = new() { Width = 260, PlaceholderText = "host name or IP address" };
    private readonly ComboBox _family = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
    private readonly ComboBox _source = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 330 };
    private readonly NumericUpDown _tries = new() { Minimum = 1, Maximum = 10, Value = 3, Width = 55 };
    private readonly NumericUpDown _timeout = new() { Minimum = 200, Maximum = 10000, Value = 1500, Increment = 100, Width = 75 };
    private readonly Button _start = new() { Text = "Find MTU", Width = 110, Height = 30 };
    private readonly Button _cancel = new() { Text = "Cancel", Width = 90, Height = 30, Enabled = false };
    private readonly Label _verdict = new() { AutoSize = true, Font = new Font("Segoe UI", 13f, FontStyle.Bold), Text = "—" };
    private readonly Label _details = new() { AutoSize = true, MaximumSize = new Size(560, 0) };
    private readonly TextBox _log = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font(FontFamily.GenericMonospace, 9f) };
    private readonly Button _copy = new() { Text = "Copy result", AutoSize = true };
    private readonly Button _exportLog = new() { Text = "Export log…", AutoSize = true };

    // ---- batch tab ----
    private readonly TextBox _batchInput = new() { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Vertical, AcceptsReturn = true, Font = new Font(FontFamily.GenericMonospace, 9.5f) };
    private readonly Button _batchRun = new() { Text = "Run batch", Width = 110, Height = 30 };
    private readonly Button _batchCancel = new() { Text = "Cancel", Width = 90, Height = 30, Enabled = false };
    private readonly Button _batchCsv = new() { Text = "Export CSV…", AutoSize = true, Enabled = false };
    private readonly Button _batchCopy = new() { Text = "Copy table", AutoSize = true, Enabled = false };
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToResizeRows = false, RowHeadersVisible = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells,
        BackgroundColor = SystemColors.Window,
    };

    private readonly ToolStripStatusLabel _status = new("Ready");
    private CancellationTokenSource? _cts;
    private MtuResult? _last;
    private List<LocalInterface> _ifs4 = [], _ifs6 = [];

    public MainForm()
    {
        Text = "MTU Finder";
        Size = new Size(1100, 760);
        MinimumSize = new Size(900, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        _family.Items.AddRange(["Auto", "IPv4", "IPv6"]);
        _family.SelectedIndex = 0;
        _family.SelectedIndexChanged += (_, _) => LoadInterfaces();

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildSingleTab());
        tabs.TabPages.Add(BuildBatchTab());
        var bar = new StatusStrip();
        bar.Items.Add(_status);
        Controls.Add(tabs);
        Controls.Add(bar);

        foreach (var (n, w) in new[] { ("Target", 160), ("Address", 160), ("Result", 180), ("Path MTU", 80), ("Max payload", 90), ("Suggested MSS", 100), ("Local MTU", 80), ("Notes", 400) })
            _grid.Columns.Add(n, n);

        _start.Click += async (_, _) => await RunSingleAsync();
        _cancel.Click += (_, _) => _cts?.Cancel();
        _target.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await RunSingleAsync(); } };
        _copy.Click += (_, _) => { if (_last != null) Clipboard.SetText(Describe(_last)); };
        _exportLog.Click += (_, _) => SaveText("mtu-log.txt", _log.Text);
        _batchRun.Click += async (_, _) => await RunBatchAsync();
        _batchCancel.Click += (_, _) => _cts?.Cancel();
        _batchCsv.Click += (_, _) => SaveText("mtu-batch.csv", GridCsv());
        _batchCopy.Click += (_, _) => Clipboard.SetText(GridText());
        Shown += (_, _) => LoadInterfaces();
    }

    // ---------------- layout ----------------

    private TabPage BuildSingleTab()
    {
        var page = new TabPage("Single target") { Padding = new Padding(10) };

        var form = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Top };
        void Row(string label, Control c)
        {
            form.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 12, 6) });
            form.Controls.Add(c);
        }
        Row("Target:", _target);
        Row("IP version:", _family);
        Row("Source interface:", _source);
        var opts = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        opts.Controls.AddRange([_tries, new Label { Text = "tries per size   timeout (ms):", AutoSize = true, Margin = new Padding(6, 6, 6, 0) }, _timeout]);
        Row("Probing:", opts);
        var buttons = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 6) };
        buttons.Controls.AddRange([_start, _cancel, _copy, _exportLog]);
        form.Controls.Add(new Label()); form.Controls.Add(buttons);

        var resultBox = new GroupBox { Text = "Result", Dock = DockStyle.Top, Height = 150, Padding = new Padding(10) };
        var resultFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        resultFlow.Controls.AddRange([_verdict, _details]);
        resultBox.Controls.Add(resultFlow);

        var logBox = new GroupBox { Text = "Probe log", Dock = DockStyle.Fill, Padding = new Padding(6) };
        logBox.Controls.Add(_log);

        var left = new Panel { Dock = DockStyle.Fill };
        left.Controls.Add(logBox);
        left.Controls.Add(resultBox);
        left.Controls.Add(form);

        var reference = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = SystemColors.Window, Font = new Font(FontFamily.GenericMonospace, 8.5f),
            Text = ReferenceText.Replace("\n", Environment.NewLine),
        };
        var refBox = new GroupBox { Text = "Reference: common MTUs", Dock = DockStyle.Right, Width = 380, Padding = new Padding(6) };
        refBox.Controls.Add(reference);

        page.Controls.Add(left);
        page.Controls.Add(refBox);
        return page;
    }

    private TabPage BuildBatchTab()
    {
        var page = new TabPage("Batch") { Padding = new Padding(10) };
        var inputBox = new GroupBox { Text = "Targets (one per line, optional)", Dock = DockStyle.Left, Width = 300, Padding = new Padding(6) };
        inputBox.Controls.Add(_batchInput);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(0, 0, 0, 6) };
        buttons.Controls.AddRange([_batchRun, _batchCancel, _batchCsv, _batchCopy]);
        var resultBox = new GroupBox { Text = "Results", Dock = DockStyle.Fill, Padding = new Padding(6) };
        resultBox.Controls.Add(_grid);
        var right = new Panel { Dock = DockStyle.Fill };
        right.Controls.Add(resultBox);
        right.Controls.Add(buttons);
        page.Controls.Add(right);
        page.Controls.Add(inputBox);
        return page;
    }

    private const string ReferenceText = """
        Ethernet                       1500
        Ethernet + 802.1Q VLAN tag     1500 payload, 1496 on some gear
        PPPoE (most DSL / fibre ISPs)  1492
        PPPoE + VLAN                   1488
        Jumbo frames                   9000 (often 9000-9216)
        IPv6 minimum link MTU          1280
        IPv4 minimum                   576

        Typical tunnel overheads (from 1500)
        GRE                  -24  ->  1476
        GRE over IPsec       ~ -70 ->  ~1430
        IPsec ESP tunnel     -50 to -73 -> ~1427-1450
        IPsec + NAT-T (UDP)  ~ -80 -> ~1420
        L2TP/IPsec           ~ -100 -> ~1400
        WireGuard            -60 (v4) / -80 (v6) -> 1440 / 1420
        OpenVPN (UDP)        ~ -50 .. -70 -> ~1430-1450
        VXLAN                -50 -> 1450

        MSS = MTU - 40 (IPv4) or MTU - 60 (IPv6).

        What results usually mean
        1500: nothing on the path shrinks packets.
        1492: a PPPoE link somewhere (often your ISP).
        1400-1450: a VPN/IPsec/GRE tunnel on the path.
        Lower than 1280 on IPv6, or lower than
        576 on IPv4, is probably packet loss rather
        than a real MTU.

        If oversized packets time out instead of
        getting 'packet too big', a device is
        filtering ICMP. Clamp MSS on the tunnel
        or firewall instead of relying on PMTUD.
        """;

    // ---------------- single run ----------------

    private void LoadInterfaces()
    {
        _ifs4 = NetInfo.Interfaces(false);
        _ifs6 = NetInfo.Interfaces(true);
        _source.Items.Clear();
        _source.Items.Add("Automatic (the one Windows would use)");
        var list = _family.SelectedIndex switch { 1 => _ifs4, 2 => _ifs6, _ => _ifs4.Concat(_ifs6).ToList() };
        foreach (var i in list) _source.Items.Add(i);
        _source.SelectedIndex = 0;
    }

    private async Task RunSingleAsync()
    {
        if (_cts != null) return;
        string host = _target.Text.Trim();
        if (host.Length == 0) { _target.Focus(); return; }
        _cts = new CancellationTokenSource();
        SetBusy(true);
        _log.Clear(); _verdict.Text = "Working…"; _details.Text = ""; _verdict.ForeColor = SystemColors.ControlText;
        try
        {
            var progress = new Progress<ProbeAttempt>(a => { _log.AppendText(a + Environment.NewLine); _status.Text = $"Probing payload {a.PayloadSize}…"; });
            var r = await ProbeOneAsync(host, _source.SelectedItem as LocalInterface, progress, _cts.Token);
            _last = r;
            ShowResult(r);
        }
        catch (Exception ex) { _verdict.Text = "Error"; _verdict.ForeColor = Color.Firebrick; _details.Text = ex.Message; }
        finally { _cts.Dispose(); _cts = null; SetBusy(false); _status.Text = "Ready"; }
    }

    /// <summary>Resolves, picks the interface, runs the search. Throws for resolve errors.</summary>
    private async Task<MtuResult> ProbeOneAsync(string host, LocalInterface? chosen, IProgress<ProbeAttempt>? progress, CancellationToken ct)
    {
        bool? v6 = _family.SelectedIndex switch { 1 => false, 2 => true, _ => null };
        var ip = await NetInfo.ResolveAsync(host, v6, ct) ?? throw new InvalidOperationException($"Could not resolve '{host}'.");
        if (v6 is bool want && (ip.AddressFamily == AddressFamily.InterNetworkV6) != want)
            throw new InvalidOperationException($"'{host}' has no {(want ? "IPv6" : "IPv4")} address.");
        var ifc = chosen is not null && chosen.Address!.AddressFamily == ip.AddressFamily ? chosen : NetInfo.InterfaceFor(ip);
        var opts = new SearchOptions { TriesPerSize = (int)_tries.Value, Timeout = TimeSpan.FromMilliseconds((double)_timeout.Value), LocalMtu = ifc?.Mtu };
        return await new MtuSearcher(new IcmpProbe(ifc?.Address), opts).RunAsync(ip, progress, ct);
    }

    private void ShowResult(MtuResult r)
    {
        switch (r.Outcome)
        {
            case MtuOutcome.Found:
                _verdict.Text = $"Path MTU {r.PathMtu}  ·  suggested MSS {r.RecommendedMss}";
                _verdict.ForeColor = r.SilentDropSuspected ? Color.DarkOrange : Color.SeaGreen;
                break;
            case MtuOutcome.NoReply: _verdict.Text = "No reply — MTU can't be measured"; _verdict.ForeColor = Color.Firebrick; break;
            case MtuOutcome.Unreachable: _verdict.Text = "Destination unreachable"; _verdict.ForeColor = Color.Firebrick; break;
            default: _verdict.Text = "Cancelled"; _verdict.ForeColor = SystemColors.GrayText; break;
        }
        _details.Text = Describe(r);
    }

    private static string Describe(MtuResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Target: {r.Target} ({(r.IsV6 ? "IPv6" : "IPv4")})");
        if (r.PathMtu is int mtu)
        {
            sb.AppendLine($"Largest payload that passed: {r.MaxPayload} bytes (+{MtuSearcher.HeaderOverhead(r.IsV6)} header = path MTU {mtu})");
            sb.AppendLine($"Suggested TCP MSS: {r.RecommendedMss}");
            if (r.LocalInterfaceMtu is int l)
                sb.AppendLine(mtu < l ? $"Local interface MTU is {l}: something on the path is smaller by {l - mtu} bytes." : $"Local interface MTU is {l}: path is not smaller than the local link.");
        }
        foreach (var n in r.Notes) sb.AppendLine("Note: " + n);
        return sb.ToString().TrimEnd();
    }

    // ---------------- batch ----------------

    private async Task RunBatchAsync()
    {
        if (_cts != null) return;
        var targets = _batchInput.Lines.Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).Distinct().ToList();
        if (targets.Count == 0) { MessageBox.Show(this, "Enter at least one target (one per line).", Text); return; }
        _cts = new CancellationTokenSource();
        SetBusy(true, batch: true);
        _grid.Rows.Clear();
        try
        {
            int n = 0;
            foreach (var t in targets)
            {
                _cts.Token.ThrowIfCancellationRequested();
                _status.Text = $"Batch {++n}/{targets.Count}: {t}";
                int row = _grid.Rows.Add(t, "", "Working…", "", "", "", "", "");
                try
                {
                    var r = await ProbeOneAsync(t, null, null, _cts.Token);
                    if (r.Outcome == MtuOutcome.Cancelled) { _grid.Rows[row].Cells[2].Value = "Cancelled"; break; }
                    _grid.Rows[row].SetValues(t, r.Target, r.Outcome, r.PathMtu, r.MaxPayload, r.RecommendedMss, r.LocalInterfaceMtu, string.Join(" ", r.Notes));
                }
                catch (OperationCanceledException) { _grid.Rows[row].Cells[2].Value = "Cancelled"; break; }
                catch (Exception ex) { _grid.Rows[row].SetValues(t, "", "Error", "", "", "", "", ex.Message); }
            }
        }
        catch (OperationCanceledException) { }
        finally { _cts.Dispose(); _cts = null; SetBusy(false, batch: true); _status.Text = "Ready"; }
    }

    // ---------------- helpers ----------------

    private void SetBusy(bool busy, bool batch = false)
    {
        _start.Enabled = !busy; _cancel.Enabled = busy && !batch;
        _batchRun.Enabled = !busy; _batchCancel.Enabled = busy && batch;
        _batchCsv.Enabled = _batchCopy.Enabled = !busy && _grid.Rows.Count > 0;
        UseWaitCursor = busy;
    }

    private string GridText() => string.Join(Environment.NewLine, new[] { string.Join("\t", _grid.Columns.Cast<DataGridViewColumn>().Select(c => c.HeaderText)) }
        .Concat(_grid.Rows.Cast<DataGridViewRow>().Select(r => string.Join("\t", r.Cells.Cast<DataGridViewCell>().Select(c => c.Value?.ToString() ?? "")))));

    private string GridCsv()
    {
        static string Q(string s) => s.Contains(',') || s.Contains('"') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        return string.Join(Environment.NewLine, new[] { string.Join(",", _grid.Columns.Cast<DataGridViewColumn>().Select(c => Q(c.HeaderText))) }
            .Concat(_grid.Rows.Cast<DataGridViewRow>().Select(r => string.Join(",", r.Cells.Cast<DataGridViewCell>().Select(c => Q(c.Value?.ToString() ?? ""))))));
    }

    private void SaveText(string suggested, string text)
    {
        using var dlg = new SaveFileDialog { FileName = suggested, Filter = "Text/CSV|*.txt;*.csv|All files|*.*" };
        if (dlg.ShowDialog(this) == DialogResult.OK) File.WriteAllText(dlg.FileName, text, Encoding.UTF8);
    }
}
