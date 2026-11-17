using System.Net;
using System.Text;

namespace DhcpFinder;

public sealed class MainForm : Form
{
    private readonly CheckedListBox _adapters = new() { Dock = DockStyle.Fill, CheckOnClick = true, IntegralHeight = false };
    private readonly NumericUpDown _seconds = new() { Minimum = 2, Maximum = 60, Value = 6, Width = 60 };
    private readonly CheckBox _randomMac = new() { Text = "Use random MAC address", AutoSize = true };
    private readonly Button _scan = new() { Text = "Scan", Width = 110, Height = 32 };
    private readonly Button _refresh = new() { Text = "Refresh adapters", AutoSize = true, Height = 32 };
    private readonly Button _export = new() { Text = "Export CSV…", AutoSize = true, Height = 32, Enabled = false };
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, RowHeadersVisible = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells, BackgroundColor = SystemColors.Window,
    };
    private readonly TextBox _log = new()
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
        Font = new Font(FontFamily.GenericMonospace, 9f),
    };
    private readonly ToolStripStatusLabel _status = new("Ready");
    private readonly List<DhcpOffer> _offers = [];
    private CancellationTokenSource? _cts;

    public MainForm()
    {
        Text = "DHCP Server Finder";
        Size = new Size(1100, 720);
        MinimumSize = new Size(800, 500);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        // --- top: adapters + options ---
        var adapterBox = new GroupBox { Text = "Network adapters to scan", Dock = DockStyle.Fill, Padding = new Padding(8) };
        adapterBox.Controls.Add(_adapters);

        var opts = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(8) };
        var secsRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        secsRow.Controls.Add(new Label { Text = "Listen time (seconds):", AutoSize = true, Margin = new Padding(0, 6, 4, 0) });
        secsRow.Controls.Add(_seconds);
        var btnRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 10, 0, 0) };
        btnRow.Controls.AddRange([_scan, _refresh, _export]);
        opts.Controls.AddRange([secsRow, _randomMac, btnRow]);
        var optBox = new GroupBox { Text = "Options", Dock = DockStyle.Fill };
        optBox.Controls.Add(opts);

        var top = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2 };
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
        top.Controls.Add(adapterBox, 0, 0);
        top.Controls.Add(optBox, 1, 0);

        // --- results + log ---
        var resultsBox = new GroupBox { Text = "DHCP servers found", Dock = DockStyle.Fill, Padding = new Padding(6) };
        resultsBox.Controls.Add(_grid);
        var logBox = new GroupBox { Text = "Log", Dock = DockStyle.Fill, Padding = new Padding(6) };
        logBox.Controls.Add(_log);

        var lower = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        lower.Panel1.Controls.Add(resultsBox);
        lower.Panel2.Controls.Add(logBox);

        var main = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        main.Panel1.Controls.Add(top);
        main.Panel2.Controls.Add(lower);

        var status = new StatusStrip();
        status.Items.Add(_status);

        Controls.Add(main);
        Controls.Add(status);

        Load += (_, _) =>
        {
            main.SplitterDistance = 170;
            lower.SplitterDistance = (int)(lower.Height * 0.62);
            LoadAdapters();
        };

        SetupGrid();
        _scan.Click += async (_, _) => await ScanOrCancel();
        _refresh.Click += (_, _) => LoadAdapters();
        _export.Click += (_, _) => ExportCsv();
    }

    private void SetupGrid()
    {
        foreach (var (name, header) in new[]
        {
            ("Server", "DHCP Server"), ("Source", "Reply From"), ("Adapter", "Adapter"), ("Offered", "Offered IP"),
            ("Mask", "Subnet Mask"), ("Gateway", "Gateway"), ("Dns", "DNS Servers"), ("Domain", "Domain"),
            ("Lease", "Lease"), ("Relay", "Relay Agent"), ("Ms", "Response (ms)"),
        })
            _grid.Columns.Add(name, header);
    }

    private void LoadAdapters()
    {
        _adapters.Items.Clear();
        foreach (var a in DhcpScanner.GetAdapters())
        {
            bool likelyVirtual = a.Address.ToString().StartsWith("169.254.") ||
                a.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase) ||
                a.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) ||
                a.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase);
            _adapters.Items.Add(a, !likelyVirtual);
        }
        _status.Text = $"{_adapters.Items.Count} IPv4 adapter(s) available";
    }

    private async Task ScanOrCancel()
    {
        if (_cts is not null) { _cts.Cancel(); return; }

        var selected = _adapters.CheckedItems.Cast<AdapterInfo>().ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(this, "Select at least one adapter.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        _offers.Clear();
        _grid.Rows.Clear();
        _log.Clear();
        _export.Enabled = false;
        _scan.Text = "Cancel";
        _refresh.Enabled = false;
        _cts = new CancellationTokenSource();
        var listen = TimeSpan.FromSeconds((double)_seconds.Value);
        _status.Text = $"Scanning {selected.Count} adapter(s) for {listen.TotalSeconds:0}s…";

        void Log(string s) => BeginInvoke(() => _log.AppendText($"{DateTime.Now:HH:mm:ss}  {s}{Environment.NewLine}"));

        try
        {
            var tasks = selected.Select(a => DhcpScanner.ProbeAsync(a, listen, _randomMac.Checked, 3, Log, _cts.Token));
            var results = await Task.WhenAll(tasks);
            foreach (var o in results.SelectMany(r => r)) AddRow(o);
        }
        catch (Exception ex)
        {
            Log("Error: " + ex.Message);
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            _scan.Text = "Scan";
            _refresh.Enabled = true;
            _export.Enabled = _offers.Count > 0;
        }

        int servers = _offers.Select(o => o.ServerId).Distinct().Count();
        _status.Text = servers switch
        {
            0 => "No DHCP servers responded.",
            1 => "1 DHCP server found.",
            _ => $"{servers} DHCP servers found — check for rogue servers!",
        };
        if (servers > 1)
            foreach (DataGridViewRow r in _grid.Rows) r.DefaultCellStyle.BackColor = Color.FromArgb(255, 243, 205);
    }

    private void AddRow(DhcpOffer o)
    {
        _offers.Add(o);
        _grid.Rows.Add(o.ServerId, o.ReplySource, o.Adapter, o.OfferedIp, o.SubnetMask?.ToString() ?? "",
            Join(o.Routers), Join(o.DnsServers), o.DomainName ?? "", FormatLease(o.LeaseTime),
            o.RelayAgent?.ToString() ?? "", o.ResponseMs);
    }

    private static string Join(IEnumerable<IPAddress> a) => string.Join(", ", a);

    private static string FormatLease(TimeSpan? t) => t is null ? "" :
        t.Value.TotalDays >= 1 ? $"{t.Value.TotalDays:0.##} d" :
        t.Value.TotalHours >= 1 ? $"{t.Value.TotalHours:0.##} h" : $"{t.Value.TotalMinutes:0} min";

    private void ExportCsv()
    {
        using var dlg = new SaveFileDialog { Filter = "CSV files (*.csv)|*.csv", FileName = $"dhcp-servers-{DateTime.Now:yyyyMMdd-HHmmss}.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        static string Q(object? v) => "\"" + (v?.ToString() ?? "").Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder("Server,ReplyFrom,Adapter,OfferedIP,SubnetMask,Gateway,DNS,Domain,LeaseSeconds,RelayAgent,ResponseMs\r\n");
        foreach (var o in _offers)
            sb.AppendJoin(',', Q(o.ServerId), Q(o.ReplySource), Q(o.Adapter), Q(o.OfferedIp), Q(o.SubnetMask),
                Q(Join(o.Routers)), Q(Join(o.DnsServers)), Q(o.DomainName), Q(o.LeaseTime?.TotalSeconds),
                Q(o.RelayAgent), Q(o.ResponseMs)).Append("\r\n");
        File.WriteAllText(dlg.FileName, sb.ToString());
        _status.Text = $"Exported to {dlg.FileName}";
    }
}
