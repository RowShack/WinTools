using System.DirectoryServices.Protocols;
using System.Text;
using AuthMailTest.Core;

namespace AuthMailTest;

public sealed class MainForm : Form
{
    private static readonly Font Mono = new(FontFamily.GenericMonospace, 9f);
    private readonly ToolStripStatusLabel _status = new("Ready");
    private CancellationTokenSource? _cts;
    private List<SavedProfile> _profiles = ProfileStore.Load();

    // ===== LDAP controls =====
    private readonly TextBox _lHost = new() { Width = 280, PlaceholderText = "dc1.corp.example.com" };
    private readonly ComboBox _lMode = Combo("LDAP (389)", "LDAPS (636)", "StartTLS (389)");
    private readonly NumericUpDown _lPort = new() { Minimum = 1, Maximum = 65535, Value = 389, Width = 70 };
    private readonly ComboBox _lBind = Combo("Negotiate / Kerberos", "Simple (DN or UPN + password)", "Anonymous");
    private readonly TextBox _lUser = new() { Width = 280, PlaceholderText = "empty = current Windows user (Negotiate)" };
    private readonly TextBox _lPass = new() { Width = 280, UseSystemPasswordChar = true };
    private readonly CheckBox _lIgnore = new() { Text = "Ignore certificate errors (testing only)", AutoSize = true };
    private readonly CheckBox _lSearch = new() { Text = "Run a test search after binding", AutoSize = true };
    private readonly TextBox _lBase = new() { Width = 280, PlaceholderText = "DC=corp,DC=example,DC=com" };
    private readonly TextBox _lFilter = new() { Width = 280, Text = "(sAMAccountName=jsmith)" };
    private readonly TextBox _lAttrs = new() { Width = 280, Text = "cn,distinguishedName,mail" };
    private readonly ComboBox _lScope = Combo("Subtree", "One level", "Base");
    private readonly Button _lRun = new() { Text = "Test LDAP", Width = 120, Height = 30 };
    private readonly Button _lCancel = new() { Text = "Cancel", Width = 80, Height = 30, Enabled = false };
    private readonly TextBox _lDomain = new() { Width = 200, PlaceholderText = "corp.example.com" };
    private readonly Button _lFindDc = new() { Text = "Find DCs (DNS SRV)", AutoSize = true };
    private readonly ListBox _lDcs = new() { Height = 70, Width = 330, IntegralHeight = false };
    private readonly TextBox _lSteps = Output();
    private readonly TextBox _lCert = Output();
    private readonly Label _lVerdict = Verdict();
    private readonly DataGridView _lGrid = Grid();
    private readonly ComboBox _lProfiles = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 200 };

    // ===== SMTP controls =====
    private readonly TextBox _sHost = new() { Width = 280, PlaceholderText = "smtp.example.com" };
    private readonly NumericUpDown _sPort = new() { Minimum = 1, Maximum = 65535, Value = 25, Width = 70 };
    private readonly ComboBox _sSec = Combo("None (plain)", "SSL on connect (465)", "STARTTLS (587/25)");
    private readonly TextBox _sUser = new() { Width = 280, PlaceholderText = "optional" };
    private readonly TextBox _sPass = new() { Width = 280, UseSystemPasswordChar = true };
    private readonly TextBox _sFrom = new() { Width = 280, PlaceholderText = "sender@example.com" };
    private readonly TextBox _sTo = new() { Width = 280, PlaceholderText = "recipient@example.org" };
    private readonly CheckBox _sIgnore = new() { Text = "Ignore certificate errors (testing only)", AutoSize = true };
    private readonly Button _sRun = new() { Text = "Test SMTP / relay", Width = 140, Height = 30 };
    private readonly Button _sSend = new() { Text = "Send test email…", Width = 130, Height = 30 };
    private readonly Button _sCancel = new() { Text = "Cancel", Width = 80, Height = 30, Enabled = false };
    private readonly TextBox _sSteps = Output();
    private readonly TextBox _sTranscript = Output();
    private readonly TextBox _sCert = Output();
    private readonly Label _sVerdict = Verdict();
    private readonly ComboBox _sProfiles = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 200 };
    private SmtpResult? _sLast;

    private static ComboBox Combo(params string[] items) { var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 200 }; c.Items.AddRange(items); c.SelectedIndex = 0; return c; }
    private static TextBox Output() => new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = Mono, BackColor = SystemColors.Window };
    private static Label Verdict() => new() { Dock = DockStyle.Top, AutoSize = false, Height = 56, Padding = new Padding(6), Font = new Font("Segoe UI", 10f, FontStyle.Bold), Text = "" };
    private static DataGridView Grid() => new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToResizeRows = false, RowHeadersVisible = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells, BackgroundColor = SystemColors.Window,
    };

    public MainForm()
    {
        Text = "Auth & Mail Test";
        Size = new Size(1250, 820);
        MinimumSize = new Size(1000, 640);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.AddRange([BuildLdapTab(), BuildSmtpTab()]);
        var bar = new StatusStrip(); bar.Items.Add(_status);
        Controls.Add(tabs); Controls.Add(bar);

        _lGrid.Columns.Add("dn", "Distinguished name"); _lGrid.Columns.Add("attrs", "Attributes");
        _lMode.SelectedIndexChanged += (_, _) => _lPort.Value = LdapRequest.DefaultPort((LdapMode)_lMode.SelectedIndex);
        _lBind.SelectedIndexChanged += (_, _) => { _lUser.Enabled = _lBind.SelectedIndex != 2; _lPass.Enabled = _lBind.SelectedIndex != 2; };
        _sSec.SelectedIndexChanged += (_, _) => _sPort.Value = SmtpRequest.DefaultPort((SmtpSecurity)_sSec.SelectedIndex);
        _lRun.Click += async (_, _) => await RunLdapAsync();
        _lCancel.Click += (_, _) => _cts?.Cancel();
        _lFindDc.Click += async (_, _) => await FindDcsAsync();
        _lDcs.DoubleClick += (_, _) => { if (_lDcs.SelectedItem is DcLocator.DcRecord d) _lHost.Text = d.Host; };
        _sRun.Click += async (_, _) => await RunSmtpAsync();
        _sSend.Click += async (_, _) => await SendMailAsync();
        _sCancel.Click += (_, _) => _cts?.Cancel();
        _lProfiles.SelectedIndexChanged += (_, _) => LoadProfile(_lProfiles, "ldap");
        _sProfiles.SelectedIndexChanged += (_, _) => LoadProfile(_sProfiles, "smtp");
        RefreshProfiles();
    }

    // ================= layout =================

    private static Control Form(params (string label, Control c)[] rows)
    {
        var t = new TableLayoutPanel { AutoSize = true, ColumnCount = 2, Dock = DockStyle.Top };
        foreach (var (l, c) in rows)
        {
            t.Controls.Add(new Label { Text = l, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 10, 6) });
            t.Controls.Add(c);
        }
        return t;
    }

    private static Control Flow(params Control[] cs)
    {
        var f = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 3, 0, 3) };
        f.Controls.AddRange(cs);
        return f;
    }

    private static GroupBox Box(string title, Control c, DockStyle dock = DockStyle.Fill, int? height = null)
    {
        var g = new GroupBox { Text = title, Dock = dock, Padding = new Padding(6) };
        if (height is int h) g.Height = h;
        g.Controls.Add(c);
        return g;
    }

    private TabPage BuildLdapTab()
    {
        var page = new TabPage("LDAP / LDAPS") { Padding = new Padding(8) };
        var hostRow = Flow(_lHost, new Label { Text = "port", AutoSize = true, Margin = new Padding(6, 6, 4, 0) }, _lPort);
        var saveBtns = Flow(_lProfiles, SmallButton("Save as…", () => SaveProfile("ldap")), SmallButton("Delete", () => DeleteProfile(_lProfiles, "ldap")));
        var buttons = Flow(_lRun, _lCancel, SmallButton("Export result…", () => Export("ldap-result.txt", LdapReport())));
        var dcRow = Flow(_lDomain, _lFindDc);
        var left = new Panel { Dock = DockStyle.Left, Width = 520, AutoScroll = true };
        var form = Form(
            ("Profile:", saveBtns), ("Server:", hostRow), ("Security:", _lMode), ("Bind:", _lBind), ("User:", _lUser), ("Password:", _lPass),
            ("", _lIgnore), ("", _lSearch), ("Base DN:", _lBase), ("Filter:", _lFilter), ("Attributes:", _lAttrs), ("Scope:", _lScope), ("", buttons),
            ("Domain:", dcRow), ("DCs found:", _lDcs));
        left.Controls.Add(form);

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 230 };
        var top = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
        top.Panel1.Controls.Add(Box("Steps", _lSteps));
        top.Panel2.Controls.Add(Box("Server certificate", _lCert));
        split.Panel1.Controls.Add(top);
        split.Panel2.Controls.Add(Box("Search results (double-click a row to read all attributes)", _lGrid));
        _lGrid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) MessageBox.Show(this, _lGrid.Rows[e.RowIndex].Cells[1].Value?.ToString()?.Replace("; ", Environment.NewLine) ?? "", _lGrid.Rows[e.RowIndex].Cells[0].Value?.ToString()); };

        var right = new Panel { Dock = DockStyle.Fill };
        right.Controls.Add(split);
        right.Controls.Add(_lVerdict);
        page.Controls.Add(right); page.Controls.Add(left);
        return page;
    }

    private TabPage BuildSmtpTab()
    {
        var page = new TabPage("SMTP") { Padding = new Padding(8) };
        var hostRow = Flow(_sHost, new Label { Text = "port", AutoSize = true, Margin = new Padding(6, 6, 4, 0) }, _sPort);
        var saveBtns = Flow(_sProfiles, SmallButton("Save as…", () => SaveProfile("smtp")), SmallButton("Delete", () => DeleteProfile(_sProfiles, "smtp")));
        var buttons = Flow(_sRun, _sSend, _sCancel);
        var buttons2 = Flow(SmallButton("Export transcript…", () => Export("smtp-transcript.txt", SmtpReport())), SmallButton("Copy transcript", () => { if (_sLast != null) Clipboard.SetText(SmtpReport()); }));
        var left = new Panel { Dock = DockStyle.Left, Width = 520, AutoScroll = true };
        left.Controls.Add(Form(("Profile:", saveBtns), ("Server:", hostRow), ("Security:", _sSec), ("User:", _sUser), ("Password:", _sPass),
            ("Mail from:", _sFrom), ("Rcpt to:", _sTo), ("", _sIgnore), ("", buttons), ("", buttons2)));
        left.Controls.Add(new Label
        {
            Dock = DockStyle.Bottom, Height = 90, Padding = new Padding(4), ForeColor = SystemColors.GrayText,
            Text = "Relay test: sends MAIL FROM and RCPT TO only, then RSET. No message is sent. 'Send test email' sends one real message after you confirm.",
        });

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 200 };
        var top = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical };
        top.Panel1.Controls.Add(Box("Steps", _sSteps));
        top.Panel2.Controls.Add(Box("Server certificate", _sCert));
        split.Panel1.Controls.Add(top);
        split.Panel2.Controls.Add(Box("SMTP conversation (passwords hidden)", _sTranscript));
        var right = new Panel { Dock = DockStyle.Fill };
        right.Controls.Add(split); right.Controls.Add(_sVerdict);
        page.Controls.Add(right); page.Controls.Add(left);
        return page;
    }

    private static Button SmallButton(string text, Action click) { var b = new Button { Text = text, AutoSize = true }; b.Click += (_, _) => click(); return b; }

    // ================= LDAP =================

    private LdapRequest BuildLdap() => new()
    {
        Host = _lHost.Text.Trim(), Port = (int)_lPort.Value, Mode = (LdapMode)_lMode.SelectedIndex, Bind = (LdapBind)_lBind.SelectedIndex,
        User = _lUser.Text.Trim(), Password = _lPass.Text, IgnoreCertErrors = _lIgnore.Checked, DoSearch = _lSearch.Checked,
        BaseDn = _lBase.Text.Trim(), Filter = _lFilter.Text.Trim(), Attributes = _lAttrs.Text.Trim(),
        Scope = _lScope.SelectedIndex switch { 1 => SearchScope.OneLevel, 2 => SearchScope.Base, _ => SearchScope.Subtree },
    };

    private LdapResult? _lLast;

    private async Task RunLdapAsync()
    {
        if (_cts != null) return;
        var req = BuildLdap();
        if (req.Host.Length == 0) { _lHost.Focus(); return; }
        if (req.Bind == LdapBind.Simple && req.Mode == LdapMode.Ldap389 &&
            MessageBox.Show(this, "A simple bind over plain LDAP (389) sends the password across the network UNENCRYPTED.\n\nContinue anyway?", "Unencrypted password", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        _cts = new CancellationTokenSource();
        _lRun.Enabled = false; _lCancel.Enabled = true; UseWaitCursor = true;
        _lSteps.Clear(); _lCert.Clear(); _lGrid.Rows.Clear(); _lVerdict.Text = "Working…"; _lVerdict.ForeColor = SystemColors.ControlText;
        try
        {
            var progress = new Progress<TestStep>(s => _lSteps.AppendText(s + Environment.NewLine));
            var r = await LdapTester.RunAsync(req, progress, _cts.Token);
            _lLast = r;
            _lCert.Text = CertText(r.Cert);
            foreach (var e in r.Entries) _lGrid.Rows.Add(e.Dn, string.Join("; ", e.Attributes.Select(a => $"{a.Key}={a.Value}")));
            _lVerdict.Text = r.Success ? "Success" + (r.Entries.Count > 0 ? $" — {r.Entries.Count} entries" : "") : "Failed — " + (r.Explanation ?? r.Steps.LastOrDefault()?.Detail ?? "");
            _lVerdict.ForeColor = r.Success ? Color.SeaGreen : Color.Firebrick;
            _status.Text = r.Success ? "LDAP test passed" : "LDAP test failed";
        }
        catch (OperationCanceledException) { _lVerdict.Text = "Cancelled"; }
        catch (Exception ex) { _lVerdict.Text = "Error: " + ex.Message; _lVerdict.ForeColor = Color.Firebrick; }
        finally { _cts.Dispose(); _cts = null; _lRun.Enabled = true; _lCancel.Enabled = false; UseWaitCursor = false; }
    }

    private async Task FindDcsAsync()
    {
        _lFindDc.Enabled = false; _lDcs.Items.Clear();
        try
        {
            var dcs = await DcLocator.FindAsync(_lDomain.Text);
            foreach (var d in dcs) _lDcs.Items.Add(d);
            _status.Text = $"{dcs.Count} domain controller(s) found. Double-click one to use it as the server.";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Find DCs", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        finally { _lFindDc.Enabled = true; }
    }

    private string LdapReport()
    {
        if (_lLast == null) return "";
        var sb = new StringBuilder();
        sb.AppendLine($"LDAP test {DateTime.Now:yyyy-MM-dd HH:mm:ss} — {_lHost.Text}:{_lPort.Value}");
        foreach (var s in _lLast.Steps) sb.AppendLine(s.ToString());
        if (_lLast.Explanation != null) sb.AppendLine("Explanation: " + _lLast.Explanation);
        sb.AppendLine(); sb.AppendLine(CertText(_lLast.Cert));
        foreach (var e in _lLast.Entries) sb.AppendLine($"{e.Dn}: {string.Join("; ", e.Attributes.Select(a => $"{a.Key}={a.Value}"))}");
        return sb.ToString();
    }

    // ================= SMTP =================

    private SmtpRequest BuildSmtp() => new()
    {
        Host = _sHost.Text.Trim(), Port = (int)_sPort.Value, Security = (SmtpSecurity)_sSec.SelectedIndex,
        User = _sUser.Text.Trim(), Password = _sPass.Text, MailFrom = _sFrom.Text.Trim(), RcptTo = _sTo.Text.Trim(), IgnoreCertErrors = _sIgnore.Checked,
    };

    private async Task RunSmtpAsync()
    {
        if (_cts != null) return;
        var req = BuildSmtp();
        if (req.Host.Length == 0) { _sHost.Focus(); return; }
        _cts = new CancellationTokenSource();
        _sRun.Enabled = _sSend.Enabled = false; _sCancel.Enabled = true; UseWaitCursor = true;
        _sSteps.Clear(); _sTranscript.Clear(); _sCert.Clear(); _sVerdict.Text = "Working…"; _sVerdict.ForeColor = SystemColors.ControlText;
        try
        {
            var progress = new Progress<TestStep>(s => _sSteps.AppendText(s + Environment.NewLine));
            var r = await SmtpTester.RunAsync(req, progress, _cts.Token);
            _sLast = r;
            _sTranscript.Text = r.TranscriptText;
            _sCert.Text = CertText(r.Cert);
            var msg = new StringBuilder(r.Success ? "Success" : "Failed");
            if (r.Relay != RelayOutcome.NotTested) msg.Append($" — relay test: {r.Relay}");
            foreach (var h in r.Hints.Where(h => h.Length > 0)) msg.Append("\n").Append(h);
            if (r.RelayDetail != null) msg.Append("\n").Append(r.RelayDetail);
            _sVerdict.Height = 24 + 20 * msg.ToString().Split('\n').Length + 20;
            _sVerdict.Text = msg.ToString();
            _sVerdict.ForeColor = r.Success ? Color.SeaGreen : Color.Firebrick;
            _status.Text = r.Success ? "SMTP test passed" : "SMTP test failed";
        }
        catch (OperationCanceledException) { _sVerdict.Text = "Cancelled"; }
        catch (Exception ex) { _sVerdict.Text = "Error: " + ex.Message; _sVerdict.ForeColor = Color.Firebrick; }
        finally { _cts.Dispose(); _cts = null; _sRun.Enabled = _sSend.Enabled = true; _sCancel.Enabled = false; UseWaitCursor = false; }
    }

    private async Task SendMailAsync()
    {
        var req = BuildSmtp();
        if (req.Host.Length == 0 || req.MailFrom.Length == 0 || req.RcptTo.Length == 0)
        { MessageBox.Show(this, "Server, 'Mail from' and 'Rcpt to' are all required to send a test email.", Text); return; }
        if (MessageBox.Show(this, $"Send ONE real test email?\n\nFrom: {req.MailFrom}\nTo: {req.RcptTo}\nVia: {req.Host}:{req.Port}", "Send test email",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        _sRun.Enabled = _sSend.Enabled = false; UseWaitCursor = true;
        try
        {
            await Mailer.SendTestAsync(req, "Test message from WinTools Auth & Mail Test",
                $"This is a test message sent from {Environment.MachineName} at {DateTime.Now:yyyy-MM-dd HH:mm:ss}.\r\nIf you received it, SMTP delivery works.", CancellationToken.None);
            _sVerdict.Text = "Test email accepted by the server for delivery."; _sVerdict.ForeColor = Color.SeaGreen;
            _status.Text = "Test email sent";
        }
        catch (Exception ex)
        {
            _sVerdict.Text = "Sending failed: " + ex.Message + "\n" + SmtpHints.ForException(ex, req.Port); _sVerdict.ForeColor = Color.Firebrick;
        }
        finally { _sRun.Enabled = _sSend.Enabled = true; UseWaitCursor = false; }
    }

    private string SmtpReport()
    {
        if (_sLast == null) return "";
        var sb = new StringBuilder();
        sb.AppendLine($"SMTP test {DateTime.Now:yyyy-MM-dd HH:mm:ss} — {_sHost.Text}:{_sPort.Value}");
        foreach (var s in _sLast.Steps) sb.AppendLine(s.ToString());
        foreach (var h in _sLast.Hints.Where(h => h.Length > 0)) sb.AppendLine("Hint: " + h);
        if (_sLast.RelayDetail != null) sb.AppendLine("Relay: " + _sLast.RelayDetail);
        sb.AppendLine(); sb.AppendLine(CertText(_sLast.Cert));
        sb.AppendLine("--- conversation ---"); sb.AppendLine(_sLast.TranscriptText);
        return sb.ToString();
    }

    // ================= shared =================

    private static string CertText(CertDetails? c)
    {
        if (c == null) return "(no certificate — connection isn't encrypted or handshake didn't get that far)";
        var sb = new StringBuilder();
        sb.AppendLine($"Subject:    {c.Subject}");
        sb.AppendLine($"Issuer:     {c.Issuer}");
        sb.AppendLine($"Valid:      {c.NotBefore:yyyy-MM-dd} to {c.NotAfter:yyyy-MM-dd}  ({(c.DaysLeft >= 0 ? c.DaysLeft + " days left" : "EXPIRED " + (-c.DaysLeft) + " days ago")})");
        sb.AppendLine($"Protocol:   {c.Protocol}");
        sb.AppendLine($"Thumbprint: {c.Thumbprint}");
        if (c.SubjectAltNames.Count > 0) sb.AppendLine("SANs:       " + string.Join(", ", c.SubjectAltNames));
        if (c.Chain.Count > 0) { sb.AppendLine("Chain:"); foreach (var x in c.Chain) sb.AppendLine("  " + x); }
        sb.AppendLine(c.Problems.Count == 0 ? "Validation: trusted" : "Validation problems:");
        foreach (var p in c.Problems) sb.AppendLine("  - " + p);
        return sb.ToString();
    }

    private void Export(string name, string text)
    {
        if (text.Length == 0) return;
        using var d = new SaveFileDialog { FileName = name, Filter = "Text|*.txt|All files|*.*" };
        if (d.ShowDialog(this) == DialogResult.OK) File.WriteAllText(d.FileName, text, Encoding.UTF8);
    }

    // ================= profiles =================

    private void RefreshProfiles(string? selectLdap = null, string? selectSmtp = null)
    {
        foreach (var (combo, kind, sel) in new[] { (_lProfiles, "ldap", selectLdap), (_sProfiles, "smtp", selectSmtp) })
        {
            combo.Items.Clear(); combo.Items.Add("(unsaved)");
            foreach (var p in _profiles.Where(p => p.Kind == kind)) combo.Items.Add(p);
            combo.SelectedIndex = 0;
            if (sel != null) { var m = _profiles.FirstOrDefault(p => p.Kind == kind && p.Name == sel); if (m != null) combo.SelectedItem = m; }
        }
    }

    private Dictionary<string, string> LdapFields() => new()
    {
        ["host"] = _lHost.Text, ["port"] = _lPort.Value.ToString(), ["mode"] = _lMode.SelectedIndex.ToString(), ["bind"] = _lBind.SelectedIndex.ToString(),
        ["user"] = _lUser.Text, ["ignore"] = _lIgnore.Checked.ToString(), ["search"] = _lSearch.Checked.ToString(), ["base"] = _lBase.Text,
        ["filter"] = _lFilter.Text, ["attrs"] = _lAttrs.Text, ["scope"] = _lScope.SelectedIndex.ToString(), ["domain"] = _lDomain.Text,
    };

    private Dictionary<string, string> SmtpFields() => new()
    {
        ["host"] = _sHost.Text, ["port"] = _sPort.Value.ToString(), ["sec"] = _sSec.SelectedIndex.ToString(), ["user"] = _sUser.Text,
        ["from"] = _sFrom.Text, ["to"] = _sTo.Text, ["ignore"] = _sIgnore.Checked.ToString(),
    };

    private void SaveProfile(string kind)
    {
        string? name = Ask("Save profile", "Profile name (an existing name is overwritten). The password is stored encrypted for your Windows account only.");
        if (string.IsNullOrWhiteSpace(name)) return;
        name = name.Trim();
        _profiles.RemoveAll(p => p.Kind == kind && p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        string pass = kind == "ldap" ? _lPass.Text : _sPass.Text;
        _profiles.Add(new SavedProfile
        {
            Name = name, Kind = kind, Fields = kind == "ldap" ? LdapFields() : SmtpFields(),
            ProtectedPassword = pass.Length > 0 ? ProfileStore.Protect(pass) : null,
        });
        try { ProfileStore.Save(_profiles); } catch (Exception ex) { MessageBox.Show(this, "Couldn't save: " + ex.Message, Text); }
        RefreshProfiles(kind == "ldap" ? name : null, kind == "smtp" ? name : null);
    }

    private void DeleteProfile(ComboBox combo, string kind)
    {
        if (combo.SelectedItem is not SavedProfile p) return;
        if (MessageBox.Show(this, $"Delete profile \"{p.Name}\"?", Text, MessageBoxButtons.YesNo) != DialogResult.Yes) return;
        _profiles.Remove(p);
        ProfileStore.Save(_profiles);
        RefreshProfiles();
    }

    private void LoadProfile(ComboBox combo, string kind)
    {
        if (combo.SelectedItem is not SavedProfile p) return;
        string F(string k) => p.Fields.TryGetValue(k, out var v) ? v : "";
        static void Idx(ComboBox c, string v) { if (int.TryParse(v, out int i) && i >= 0 && i < c.Items.Count) c.SelectedIndex = i; }
        string? pass = ProfileStore.Unprotect(p.ProtectedPassword);
        if (pass == null) MessageBox.Show(this, "The saved password can't be decrypted (the profile was saved by another Windows user or PC). Re-enter it.", Text);
        if (kind == "ldap")
        {
            _lHost.Text = F("host"); Idx(_lMode, F("mode")); if (decimal.TryParse(F("port"), out var port)) _lPort.Value = Math.Clamp(port, 1, 65535); Idx(_lBind, F("bind"));
            _lUser.Text = F("user"); _lPass.Text = pass ?? ""; _lIgnore.Checked = F("ignore") == "True"; _lSearch.Checked = F("search") == "True";
            _lBase.Text = F("base"); _lFilter.Text = F("filter"); _lAttrs.Text = F("attrs"); Idx(_lScope, F("scope")); _lDomain.Text = F("domain");
        }
        else
        {
            _sHost.Text = F("host"); Idx(_sSec, F("sec")); if (decimal.TryParse(F("port"), out var port)) _sPort.Value = Math.Clamp(port, 1, 65535);
            _sUser.Text = F("user"); _sPass.Text = pass ?? ""; _sFrom.Text = F("from"); _sTo.Text = F("to"); _sIgnore.Checked = F("ignore") == "True";
        }
    }

    private string? Ask(string title, string label)
    {
        using var f = new Form
        {
            Text = title, FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false, MinimizeBox = false, ClientSize = new Size(420, 130), Font = Font,
        };
        var lbl = new Label { Text = label, Left = 12, Top = 10, Width = 396, Height = 44 };
        var tb = new TextBox { Left = 12, Top = 58, Width = 396 };
        var ok = new Button { Text = "OK", Left = 248, Top = 92, Width = 76, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancel", Left = 332, Top = 92, Width = 76, DialogResult = DialogResult.Cancel };
        f.Controls.AddRange([lbl, tb, ok, cancel]); f.AcceptButton = ok; f.CancelButton = cancel;
        return f.ShowDialog(this) == DialogResult.OK ? tb.Text : null;
    }
}
