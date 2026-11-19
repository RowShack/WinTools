using System.Text;
using RadiusTester.Core;

namespace RadiusTester;

public sealed class MainForm : Form
{
    private static readonly Font Mono = new(FontFamily.GenericMonospace, 9f);
    private readonly ToolStripStatusLabel _status = new("Ready");
    private readonly ToolStripProgressBar _progress = new() { Visible = false, Width = 160 };
    private CancellationTokenSource? _cts;
    private readonly RadiusDictionary _dict = RadiusDictionary.LoadBuiltIn();
    private readonly SessionLog _log = new();
    private List<SavedProfile> _profiles = ProfileStore.Load();
    private RadiusExchange? _lastExchange;
    private ServerProfile? _lastProfile;

    // ===== server profile =====
    private readonly ComboBox _profiles_cb = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 190 };
    private readonly TextBox _host = new() { Width = 190, PlaceholderText = "radius.example.com" };
    private readonly NumericUpDown _authPort = Num(1, 65535, 1812), _acctPort = Num(1, 65535, 1813), _retries = Num(0, 10, 2);
    private readonly NumericUpDown _timeout = new() { Minimum = 0.2m, Maximum = 120, DecimalPlaces = 1, Increment = 0.5m, Value = 3, Width = 60 };
    private readonly TextBox _secret = new() { Width = 190, UseSystemPasswordChar = true };
    private readonly CheckBox _showSecret = new() { Text = "show", AutoSize = true };
    private readonly TextBox _nasIp = new() { Width = 190, PlaceholderText = "optional, e.g. 10.0.0.1" };
    private readonly TextBox _nasId = new() { Width = 190, PlaceholderText = "optional, e.g. fw01" };
    private readonly ComboBox _transport = Combo("UDP (1812/1813)", "RadSec (TLS, TCP 2083)");
    private readonly CheckBox _msgAuth = new() { Text = "Always send && validate Message-Authenticator (BlastRADIUS)", Checked = true, AutoSize = true };
    private readonly NumericUpDown _radsecPort = Num(1, 65535, 2083);
    private readonly TextBox _pfx = new() { Width = 190, PlaceholderText = "client certificate .pfx (optional)" };
    private readonly TextBox _pfxPw = new() { Width = 190, UseSystemPasswordChar = true, PlaceholderText = "pfx password" };
    private readonly TextBox _thumb = new() { Width = 190, PlaceholderText = "or thumbprint in CurrentUser\\My" };
    private readonly CheckBox _ignoreCert = new() { Text = "Ignore server certificate errors (testing only)", AutoSize = true };
    private Control _radsecRow = null!;
    private readonly GroupBox _radsecBox = new() { Text = "RadSec options", AutoSize = true };

    // ===== authenticate =====
    private readonly TextBox _user = new() { Width = 220 };
    private readonly TextBox _pass = new() { Width = 220, UseSystemPasswordChar = true };
    private readonly ComboBox _method = Combo("PAP", "CHAP", "MS-CHAPv2", "EAP-MD5");
    private readonly CheckBox _savePw = new() { Text = "save user password in profile (DPAPI)", AutoSize = true };
    private readonly ComboBox _attrName = new() { Width = 200, DropDownStyle = ComboBoxStyle.DropDown, AutoCompleteMode = AutoCompleteMode.SuggestAppend, AutoCompleteSource = AutoCompleteSource.ListItems };
    private readonly TextBox _attrValue = new() { Width = 150 };
    private readonly DataGridView _custom = new()
    {
        Dock = DockStyle.Fill, AllowUserToAddRows = false, RowHeadersVisible = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill, BackgroundColor = SystemColors.Window, ReadOnly = true,
    };
    private readonly Button _authRun = new() { Text = "Send Access-Request", Width = 160, Height = 30 };

    // ===== accounting =====
    private readonly ComboBox _acctType = Combo("Start", "Interim-Update", "Stop");
    private readonly TextBox _acctSession = new() { Width = 220 };
    private readonly TextBox _acctUser = new() { Width = 220 };
    private readonly TextBox _acctIp = new() { Width = 220, PlaceholderText = "Framed-IP-Address, e.g. 192.0.2.10" };
    private readonly TextBox _acctClass = new() { Width = 220, PlaceholderText = "text, or 0x-hex (e.g. group for FortiGate RSSO)" };
    private readonly TextBox _acctCalling = new() { Width = 220, PlaceholderText = "Calling-Station-Id (MAC or IP)" };
    private readonly NumericUpDown _acctTime = new() { Minimum = 0, Maximum = int.MaxValue, Width = 100 };
    private readonly Button _acctRun = new() { Text = "Send Accounting-Request", Width = 190, Height = 30 };

    // ===== status server / load test =====
    private readonly CheckBox _statusAcct = new() { Text = "ping the accounting port instead", AutoSize = true };
    private readonly Button _statusRun = new() { Text = "Send Status-Server", Width = 160, Height = 30 };
    private readonly NumericUpDown _loadCount = Num(1, 100000, 200), _loadRate = Num(1, 10000, 20);
    private readonly ComboBox _loadMode = Combo("Access-Request (uses Authenticate tab)", "Status-Server");
    private readonly Button _loadRun = new() { Text = "Run load test", Width = 140, Height = 30 };
    private readonly TextBox _loadOut = Output();

    private readonly List<Button> _cancels = [];
    private Button NewCancel()
    {
        var b = new Button { Text = "Cancel", Width = 90, Height = 30, Enabled = false };
        b.Click += (_, _) => _cts?.Cancel();
        _cancels.Add(b);
        return b;
    }

    // ===== results =====
    private readonly Label _verdict = new() { Dock = DockStyle.Top, Height = 54, AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(10, 0, 0, 0), Font = new Font("Segoe UI", 15f, FontStyle.Bold), Text = "No result yet", BackColor = Color.Gainsboro };
    private readonly Label _summary = new() { Dock = DockStyle.Top, Height = 44, AutoSize = false, Padding = new Padding(8, 4, 8, 0) };
    private readonly TextBox _hints = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = SystemColors.Window };
    private readonly DataGridView _attrs = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, RowHeadersVisible = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells, BackgroundColor = SystemColors.Window,
    };
    private readonly TextBox _reqHex = Output(), _repHex = Output(), _logBox = Output();

    private static NumericUpDown Num(int min, int max, int val) => new() { Minimum = min, Maximum = max, Value = val, Width = 70 };
    private static ComboBox Combo(params string[] items) { var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 220 }; c.Items.AddRange(items); c.SelectedIndex = 0; return c; }
    private static TextBox Output() => new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = Mono, BackColor = SystemColors.Window };

    public MainForm()
    {
        Text = "RADIUS Tester";
        Size = new Size(1400, 900);
        MinimumSize = new Size(1100, 700);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        _attrs.Columns.Add("dir", "Packet"); _attrs.Columns.Add("name", "Attribute"); _attrs.Columns.Add("vendor", "Vendor");
        _attrs.Columns.Add("type", "Type"); _attrs.Columns.Add("dt", "Data type"); _attrs.Columns.Add("len", "Len"); _attrs.Columns.Add("val", "Value");
        _custom.Columns.Add("n", "Attribute"); _custom.Columns.Add("v", "Value");
        RefreshAttrNames();

        var split = new SplitContainer { Dock = DockStyle.Fill, FixedPanel = FixedPanel.Panel1 };
        Load += (_, _) => split.SplitterDistance = 570;
        split.Panel1.Controls.Add(BuildLeft());
        split.Panel2.Controls.Add(BuildResults());
        var bar = new StatusStrip(); bar.Items.Add(_status); bar.Items.Add(_progress);
        Controls.Add(split); Controls.Add(bar);

        _showSecret.CheckedChanged += (_, _) => _secret.UseSystemPasswordChar = !_showSecret.Checked;
        _transport.SelectedIndexChanged += (_, _) => UpdateTransportUi();
        _profiles_cb.SelectedIndexChanged += (_, _) => LoadSelectedProfile();
        _authRun.Click += async (_, _) => await RunAsync(AuthenticateAsync);
        _acctRun.Click += async (_, _) => await RunAsync(AccountingAsync);
        _statusRun.Click += async (_, _) => await RunAsync(StatusAsync);
        _loadRun.Click += async (_, _) => await RunAsync(LoadTestAsync);
        _acctSession.Text = "RT-" + DateTime.Now.ToString("yyyyMMddHHmmss");
        FormClosing += (_, _) => _cts?.Cancel();
        UpdateTransportUi();
        RefreshProfiles();
    }

    // ================= layout =================

    private static Control Row(string label, params Control[] cs)
    {
        var f = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        f.Controls.Add(new Label { Text = label, Width = 140, TextAlign = ContentAlignment.MiddleLeft, Margin = new Padding(0, 4, 0, 4) });
        foreach (var c in cs) { c.Margin = new Padding(0, 3, 6, 3); f.Controls.Add(c); }
        return f;
    }

    private static FlowLayoutPanel Column(params Control[] cs)
    {
        var f = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(6) };
        f.Controls.AddRange(cs);
        return f;
    }

    private static Button Small(string text, Action a) { var b = new Button { Text = text, AutoSize = true }; b.Click += (_, _) => a(); return b; }

    private Control BuildLeft()
    {
        var radsecFlow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Padding = new Padding(4) };
        radsecFlow.Controls.AddRange([Row("Client cert:", _pfx, Small("…", BrowsePfx)), Row("PFX password:", _pfxPw), Row("or thumbprint:", _thumb), Row("", _ignoreCert)]);
        _radsecBox.Controls.Add(radsecFlow);

        _radsecRow = Row("RadSec port:", _radsecPort);
        var server = new GroupBox { Text = "Server profile", Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6) };
        var sf = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Dock = DockStyle.Fill };
        sf.Controls.AddRange([
            Row("Profile:", _profiles_cb, Small("Save as…", SaveProfile), Small("Delete", DeleteProfile)),
            Row("Host:", _host),
            Row("Transport:", _transport),
            Row("Auth / acct port:", _authPort, _acctPort),
            Row("Shared secret:", _secret, _showSecret),
            Row("Timeout s / retries:", _timeout, _retries),
            Row("NAS-IP-Address:", _nasIp),
            Row("NAS-Identifier:", _nasId),
            Row("", _msgAuth),
            _radsecRow,
            _radsecBox,
        ]);
        server.Controls.Add(sf);

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(AuthTab());
        tabs.TabPages.Add(AcctTab());
        tabs.TabPages.Add(StatusTab());
        tabs.TabPages.Add(LoadTab());

        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        var host = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1 };
        host.Controls.Add(server);
        tabs.Height = 430; tabs.Dock = DockStyle.Top;
        host.Controls.Add(tabs);
        scroll.Controls.Add(host);
        return scroll;
    }

    private TabPage AuthTab()
    {
        var p = new TabPage("Authenticate") { Padding = new Padding(6) };
        var addRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        addRow.Controls.AddRange([_attrName, _attrValue, Small("Add", AddCustom), Small("Remove", RemoveCustom)]);
        var gridBox = new Panel { Height = 110, Width = 520 }; gridBox.Controls.Add(_custom);
        var col = Column(
            Row("User name:", _user), Row("Password:", _pass), Row("Method:", _method), Row("", _savePw),
            new Label { Text = "Extra attributes (standard or vendor, from the dictionary):", AutoSize = true, Margin = new Padding(0, 8, 0, 2) },
            addRow, gridBox,
            Row("", Small("Load dictionary file…", LoadDictionary)),
            Row("", _authRun, NewCancel()));
        p.Controls.Add(col);
        return p;
    }

    private TabPage AcctTab()
    {
        var p = new TabPage("Accounting") { Padding = new Padding(6) };
        p.Controls.Add(Column(
            Row("Status type:", _acctType), Row("Acct-Session-Id:", _acctSession), Row("User-Name:", _acctUser), Row("Framed-IP:", _acctIp),
            Row("Class:", _acctClass), Row("Calling-Station-Id:", _acctCalling), Row("Session time (s):", _acctTime),
            new Label { Text = "Interim/Stop use the session time; Start ignores it. Accounting uses the accounting port (1813).", AutoSize = true, MaximumSize = new Size(500, 0) },
            Row("", _acctRun, NewCancel())));
        return p;
    }

    private TabPage StatusTab()
    {
        var p = new TabPage("Status-Server") { Padding = new Padding(6) };
        p.Controls.Add(Column(
            new Label { Text = "RFC 5997 'ping': a Status-Server packet with Message-Authenticator. A valid answer proves the server is up AND the shared secret matches, without any user credentials.\r\nNot every server implements it (NPS does not; FreeRADIUS needs a status virtual server).", AutoSize = true, MaximumSize = new Size(500, 0) },
            Row("", _statusAcct), Row("", _statusRun, NewCancel())));
        return p;
    }

    private TabPage LoadTab()
    {
        var p = new TabPage("Load test") { Padding = new Padding(6) };
        var outBox = new Panel { Width = 520, Height = 190 }; outBox.Controls.Add(_loadOut);
        p.Controls.Add(Column(
            new Label { Text = "Sends N requests at about X per second (no retries) and reports outcome counts and latency percentiles. Only run it against servers you are allowed to load. Access-Requests use the credentials from the Authenticate tab.", AutoSize = true, MaximumSize = new Size(500, 0) },
            Row("Requests:", _loadCount), Row("Rate (per second):", _loadRate), Row("Mode:", _loadMode), Row("", _loadRun, NewCancel()), outBox));
        return p;
    }

    private Control BuildResults()
    {
        var tabs = new TabControl { Dock = DockStyle.Fill };
        var attrPage = new TabPage("Attributes") { Padding = new Padding(4) }; attrPage.Controls.Add(_attrs);
        var reqPage = new TabPage("Request (hex)") { Padding = new Padding(4) }; reqPage.Controls.Add(_reqHex);
        var repPage = new TabPage("Reply (hex)") { Padding = new Padding(4) }; repPage.Controls.Add(_repHex);
        var logPage = new TabPage("Session log") { Padding = new Padding(4) }; logPage.Controls.Add(_logBox);
        tabs.TabPages.AddRange([attrPage, reqPage, repPage, logPage]);

        var hintsBox = new GroupBox { Text = "What this means", Dock = DockStyle.Top, Height = 170, Padding = new Padding(6) };
        hintsBox.Controls.Add(_hints);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(4) };
        buttons.Controls.AddRange([
            Small("Copy result", () => CopyText(_lastExchange == null ? "" : RadiusFormatter.Report(_lastExchange, _dict, _lastProfile!))),
            Small("Copy attributes (CSV)", () => CopyText(AttrCsv())),
            Small("Export attributes CSV…", () => Export("radius-attributes.csv", AttrCsv(), "CSV|*.csv")),
            Small("Copy session log", () => CopyText(_log.ToText())),
            Small("Export session log (TXT)…", () => Export("radius-session.txt", _log.ToText(), "Text|*.txt")),
            Small("Clear log", () => { _log.Clear(); _logBox.Clear(); }),
        ]);

        var panel = new Panel { Dock = DockStyle.Fill };
        panel.Controls.Add(tabs);
        panel.Controls.Add(hintsBox);
        panel.Controls.Add(_summary);
        panel.Controls.Add(_verdict);
        panel.Controls.Add(buttons);
        return panel;
    }

    // ================= helpers =================

    private void UpdateTransportUi()
    {
        bool radsec = _transport.SelectedIndex == 1;
        _radsecBox.Visible = radsec; _radsecRow.Visible = radsec;
        _secret.Enabled = !radsec; _showSecret.Enabled = !radsec;
        _authPort.Enabled = !radsec; _acctPort.Enabled = !radsec; _retries.Enabled = !radsec;
        if (radsec) _secret.PlaceholderText = "not used: RadSec uses the fixed secret 'radsec'"; else _secret.PlaceholderText = "";
    }

    private void RefreshAttrNames()
    {
        _attrName.Items.Clear();
        _attrName.Items.AddRange(_dict.Attributes.Where(a => a.Name is not ("User-Password" or "CHAP-Password" or "Message-Authenticator" or "Vendor-Specific"))
            .Select(a => (object)a.Name).ToArray());
    }

    private void RefreshProfiles(string? select = null)
    {
        _profiles_cb.Items.Clear();
        _profiles_cb.Items.Add("(unsaved)");
        foreach (var p in _profiles) _profiles_cb.Items.Add(p);
        _profiles_cb.SelectedItem = _profiles.FirstOrDefault(p => p.Name == select);
        if (_profiles_cb.SelectedIndex < 0) _profiles_cb.SelectedIndex = 0;
    }

    private ServerProfile ReadProfile()
    {
        if (string.IsNullOrWhiteSpace(_host.Text)) throw new FormatException("Enter the server host name or IP address.");
        bool radsec = _transport.SelectedIndex == 1;
        if (!radsec && _secret.Text.Length == 0) throw new FormatException("Enter the shared secret (a RADIUS server cannot be tested without it).");
        return new ServerProfile
        {
            Host = _host.Text.Trim(), AuthPort = (int)_authPort.Value, AcctPort = (int)_acctPort.Value, Secret = _secret.Text, TimeoutSeconds = (double)_timeout.Value,
            Retries = (int)_retries.Value, NasIp = _nasIp.Text.Trim(), NasIdentifier = _nasId.Text.Trim(), SendMessageAuthenticator = _msgAuth.Checked,
            Transport = radsec ? TransportKind.RadSec : TransportKind.Udp, RadSecPort = (int)_radsecPort.Value, ClientCertPfxPath = _pfx.Text.Trim(),
            ClientCertPfxPassword = _pfxPw.Text, ClientCertThumbprint = _thumb.Text.Trim(), IgnoreServerCertErrors = _ignoreCert.Checked,
        };
    }

    private AuthMethod Method => (AuthMethod)_method.SelectedIndex;

    private AuthRequest ReadAuth()
    {
        if (_user.Text.Length == 0) throw new FormatException("Enter a user name.");
        var extra = new List<RadiusAttribute>();
        foreach (DataGridViewRow r in _custom.Rows) extra.Add(_dict.Encode((string)r.Cells[0].Value!, (string)r.Cells[1].Value!));
        return new AuthRequest { UserName = _user.Text, Password = _pass.Text, Method = Method, Extra = extra };
    }

    private async Task RunAsync(Func<ServerProfile, CancellationToken, Task> body)
    {
        ServerProfile profile;
        try { profile = ReadProfile(); }
        catch (FormatException ex) { MessageBox.Show(this, ex.Message, "RADIUS Tester", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        _lastProfile = profile;
        SetBusy(true);
        _cts = new CancellationTokenSource();
        try { await body(profile, _cts.Token); }
        catch (OperationCanceledException) { _status.Text = "Cancelled"; }
        catch (FormatException ex) { MessageBox.Show(this, ex.Message, "RADIUS Tester", MessageBoxButtons.OK, MessageBoxIcon.Warning); _status.Text = "Ready"; }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or System.Security.Cryptography.CryptographicException or UnauthorizedAccessException or ArgumentException)
        { MessageBox.Show(this, ex.Message, "RADIUS Tester", MessageBoxButtons.OK, MessageBoxIcon.Error); _status.Text = "Error"; }
        finally { SetBusy(false); _cts?.Dispose(); _cts = null; _progress.Visible = false; }
    }

    private void SetBusy(bool busy)
    {
        foreach (var b in new[] { _authRun, _acctRun, _statusRun, _loadRun }) b.Enabled = !busy;
        foreach (var c in _cancels) c.Enabled = busy;
        if (busy) _status.Text = "Working…";
    }

    // ================= actions =================

    private async Task AuthenticateAsync(ServerProfile profile, CancellationToken ct)
    {
        var req = ReadAuth();
        var client = new RadiusClient(profile);
        var session = await client.AuthenticateAsync(req, PromptChallengeAsync, ex => BeginInvoke(() => ShowExchange(ex, profile)), ct);
        _status.Text = session.ChallengeAbandoned ? "Challenge not answered" : session.Last?.VerdictText ?? "Done";
    }

    private Task<string?> PromptChallengeAsync(ChallengePrompt p, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<string?>();
        BeginInvoke(() =>
        {
            using var dlg = new PromptDialog("Access-Challenge", string.IsNullOrWhiteSpace(p.ReplyMessage) ? "The server sent an Access-Challenge without a Reply-Message. Enter the response (e.g. OTP):" : p.ReplyMessage, true);
            tcs.TrySetResult(dlg.ShowDialog(this) == DialogResult.OK ? dlg.Value : null);
        });
        ct.Register(() => tcs.TrySetCanceled());
        return tcs.Task;
    }

    private async Task AccountingAsync(ServerProfile profile, CancellationToken ct)
    {
        var a = new AcctRequest
        {
            StatusType = _acctType.SelectedIndex + 1, SessionId = _acctSession.Text, UserName = _acctUser.Text, FramedIp = _acctIp.Text.Trim(), Class = _acctClass.Text,
            CallingStationId = _acctCalling.Text, SessionTime = _acctType.SelectedIndex == 0 ? null : (uint)_acctTime.Value,
            TerminateCause = _acctType.SelectedIndex == 2 ? 1u : null,
        };
        if (a.SessionId.Length == 0) throw new FormatException("Enter an Acct-Session-Id.");
        var ex = await new RadiusClient(profile).AccountingAsync(a, ct);
        ShowExchange(ex, profile);
    }

    private async Task StatusAsync(ServerProfile profile, CancellationToken ct)
    {
        var ex = await new RadiusClient(profile).StatusServerAsync(ct, _statusAcct.Checked);
        ShowExchange(ex, profile);
    }

    private async Task LoadTestAsync(ServerProfile profile, CancellationToken ct)
    {
        bool status = _loadMode.SelectedIndex == 1;
        var req = status ? new AuthRequest() : ReadAuth();
        if (!status && MessageBox.Show(this, $"Send {_loadCount.Value} Access-Requests at {_loadRate.Value}/s to {profile.Host}?\r\nMake sure you are allowed to load this server.", "Load test", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return;
        _progress.Visible = true; _progress.Maximum = (int)_loadCount.Value; _progress.Value = 0;
        var prog = new Progress<(int Done, int Total)>(p => { _progress.Value = Math.Min(p.Done, _progress.Maximum); _status.Text = $"Load test: {p.Done}/{p.Total}"; });
        _loadOut.Text = "Running…";
        var r = await LoadTest.RunAsync(profile, req, (int)_loadCount.Value, (double)_loadRate.Value, status, prog, ct);
        _loadOut.Text = string.Join("\r\n", [
            $"Requests sent : {r.Sent} in {r.ElapsedSeconds:0.0} s ({r.AchievedRate:0.0}/s achieved)",
            $"Accepted      : {r.Accepted}", $"Rejected      : {r.Rejected}", $"Challenged    : {r.Challenged}", $"No reply      : {r.NoReply}", $"Errors        : {r.Errors}",
            "", "Latency of answered requests (ms):",
            $"  min {r.MinMs:0.0}   mean {r.MeanMs:0.0}", $"  p50 {r.P50Ms:0.0}   p90 {r.P90Ms:0.0}", $"  p95 {r.P95Ms:0.0}   p99 {r.P99Ms:0.0}   max {r.MaxMs:0.0}"]);
        _log.Add($"Load test against {profile.Host}: {r}");
        _logBox.Text = _log.ToText();
        _status.Text = "Load test finished";
    }

    // ================= results =================

    private void ShowExchange(RadiusExchange ex, ServerProfile profile)
    {
        _lastExchange = ex; _lastProfile = profile;
        _verdict.Text = "  " + ex.VerdictText;
        (_verdict.BackColor, _verdict.ForeColor) = ex.Verdict switch
        {
            Verdict.Accept or Verdict.AccountingOk or Verdict.StatusOk => (Color.FromArgb(40, 150, 70), Color.White),
            Verdict.Challenge => (Color.FromArgb(240, 180, 40), Color.Black),
            Verdict.Other => (Color.Gray, Color.White),
            _ => (Color.FromArgb(200, 50, 50), Color.White),
        };
        var rtt = ex.Reply != null ? $"{ex.Rtt.TotalMilliseconds:0.0} ms" : "n/a";
        string Tri(bool? b, string good, string bad) => b switch { true => good, false => bad, _ => "n/a" };
        _summary.Text = $"{ex.Label}  →  {ex.Endpoint}\r\nRound-trip {rtt}, attempts {ex.Attempts}.  Response Authenticator: {Tri(ex.ResponseAuthenticatorValid, "valid", "INVALID")}.  Message-Authenticator in reply: {(ex.ReplyHasMessageAuthenticator == true ? Tri(ex.MessageAuthenticatorValid, "valid", "INVALID") : ex.Reply == null ? "n/a" : "absent")}.";
        var sb = new StringBuilder();
        if (ex.Error != null && ex.Verdict != Verdict.NetworkError) sb.AppendLine(ex.Error).AppendLine();
        foreach (var n in ex.Notes) sb.AppendLine("• " + n);
        foreach (var h in ex.Hints) sb.AppendLine(h.StartsWith('•') ? h : "• " + h);
        _hints.Text = sb.ToString().TrimEnd();

        _attrs.Rows.Clear();
        void Add(string dir, RadiusPacket p) { foreach (var a in RadiusFormatter.Decode(p, _dict)) _attrs.Rows.Add(dir, a.Name, a.Vendor, a.Type, a.DataType, a.Length, a.Value); }
        Add("→ " + RadiusCode.Name(ex.Request.Code), ex.Request);
        if (ex.Reply != null) Add("← " + RadiusCode.Name(ex.Reply.Code), ex.Reply);
        _reqHex.Text = RadiusFormatter.Hex(ex.RequestBytes);
        _repHex.Text = ex.ReplyBytes == null ? "(no reply)" : RadiusFormatter.Hex(ex.ReplyBytes);
        _log.Add(ex, _dict, profile);
        _logBox.Text = _log.ToText();
        _status.Text = $"{ex.VerdictText}  ({rtt})";
    }

    private string AttrCsv()
    {
        var sb = new StringBuilder("Packet,Attribute,Vendor,Type,DataType,Length,Value\r\n");
        string Q(object? o) => "\"" + (o?.ToString() ?? "").Replace("\"", "\"\"") + "\"";
        foreach (DataGridViewRow r in _attrs.Rows) sb.AppendLine(string.Join(",", r.Cells.Cast<DataGridViewCell>().Select(c => Q(c.Value))));
        return sb.ToString();
    }

    private void CopyText(string s) { if (s.Length > 0) { try { Clipboard.SetText(s); _status.Text = "Copied to clipboard"; } catch (System.Runtime.InteropServices.ExternalException) { _status.Text = "Clipboard busy, try again"; } } }

    private void Export(string name, string text, string filter)
    {
        using var dlg = new SaveFileDialog { FileName = name, Filter = filter + "|All files|*.*" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, text, new UTF8Encoding(true));
        _status.Text = "Saved " + dlg.FileName;
    }

    // ================= custom attributes / dictionary =================

    private void AddCustom()
    {
        var name = _attrName.Text.Trim();
        if (name.Length == 0) return;
        try { _dict.Encode(name, _attrValue.Text); }
        catch (FormatException ex) { MessageBox.Show(this, ex.Message, "Attribute", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
        _custom.Rows.Add(name, _attrValue.Text);
        _attrValue.Clear();
    }

    private void RemoveCustom() { foreach (DataGridViewRow r in _custom.SelectedRows) _custom.Rows.Remove(r); }

    private void LoadDictionary()
    {
        using var dlg = new OpenFileDialog { Title = "FreeRADIUS-format dictionary", Filter = "Dictionary files|dictionary*;*.dict;*.txt|All files|*.*" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            int before = _dict.LoadWarnings.Count;
            int n = _dict.LoadFile(dlg.FileName);
            RefreshAttrNames();
            var warn = _dict.LoadWarnings.Skip(before).Take(5).ToList();
            MessageBox.Show(this, $"Loaded {n} new attribute(s) from {Path.GetFileName(dlg.FileName)}." + (warn.Count > 0 ? "\r\n\r\nWarnings:\r\n" + string.Join("\r\n", warn) : ""), "Dictionary", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (IOException ex) { MessageBox.Show(this, ex.Message, "Dictionary", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void BrowsePfx()
    {
        using var dlg = new OpenFileDialog { Filter = "PKCS#12|*.pfx;*.p12|All files|*.*" };
        if (dlg.ShowDialog(this) == DialogResult.OK) _pfx.Text = dlg.FileName;
    }

    // ================= saved profiles =================

    private void SaveProfile()
    {
        ServerProfile p;
        try { p = ReadProfile(); } catch (FormatException ex) { MessageBox.Show(this, ex.Message); return; }
        using var dlg = new PromptDialog("Save profile", "Profile name:", false) { Value = (_profiles_cb.SelectedItem as SavedProfile)?.Name ?? _host.Text.Trim() };
        if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Value.Trim().Length == 0) return;
        var name = dlg.Value.Trim();
        _profiles.RemoveAll(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        _profiles.Add(SavedProfile.From(name, p, _user.Text, _method.Text, _savePw.Checked ? _pass.Text : null));
        ProfileStore.Save(_profiles);
        RefreshProfiles(name);
        _status.Text = "Profile saved (secrets are DPAPI-encrypted for your Windows account)";
    }

    private void DeleteProfile()
    {
        if (_profiles_cb.SelectedItem is not SavedProfile sp) return;
        if (MessageBox.Show(this, $"Delete profile '{sp.Name}'?", "Delete", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        _profiles.Remove(sp); ProfileStore.Save(_profiles); RefreshProfiles();
    }

    private void LoadSelectedProfile()
    {
        if (_profiles_cb.SelectedItem is not SavedProfile s) return;
        var (p, ok) = s.ToProfile();
        _host.Text = p.Host; _authPort.Value = p.AuthPort; _acctPort.Value = p.AcctPort; _timeout.Value = (decimal)Math.Clamp(p.TimeoutSeconds, 0.2, 120);
        _retries.Value = Math.Clamp(p.Retries, 0, 10); _nasIp.Text = p.NasIp; _nasId.Text = p.NasIdentifier; _msgAuth.Checked = p.SendMessageAuthenticator;
        _transport.SelectedIndex = (int)p.Transport; _radsecPort.Value = p.RadSecPort; _pfx.Text = p.ClientCertPfxPath; _thumb.Text = p.ClientCertThumbprint;
        _ignoreCert.Checked = p.IgnoreServerCertErrors; _secret.Text = p.Secret; _pfxPw.Text = p.ClientCertPfxPassword;
        _user.Text = s.UserName;
        int mi = _method.Items.IndexOf(s.Method); if (mi >= 0) _method.SelectedIndex = mi;
        var up = ProfileStore.Unprotect(s.ProtectedUserPassword);
        _pass.Text = up ?? ""; _savePw.Checked = !string.IsNullOrEmpty(s.ProtectedUserPassword);
        if (!ok || up == null) MessageBox.Show(this, "Some secrets in this profile could not be decrypted (it was saved by another Windows user or PC). Please re-enter them.", "Profile", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}

internal sealed class PromptDialog : Form
{
    private readonly TextBox _box = new() { Dock = DockStyle.Top };
    [System.ComponentModel.Browsable(false), System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public string Value { get => _box.Text; set => _box.Text = value; }

    public PromptDialog(string title, string prompt, bool secret)
    {
        Text = title; Size = new Size(460, 220); StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
        Font = new Font("Segoe UI", 9.5f);
        _box.UseSystemPasswordChar = false;
        var label = new Label { Text = prompt, Dock = DockStyle.Fill, Padding = new Padding(0, 0, 0, 8) };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Width = 90 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 90 };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Height = 40 };
        buttons.Controls.AddRange([cancel, ok]);
        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12) };
        body.Controls.Add(label); body.Controls.Add(_box);
        Controls.Add(body); Controls.Add(buttons);
        AcceptButton = ok; CancelButton = cancel;
        if (secret) Shown += (_, _) => _box.Focus();
    }
}
