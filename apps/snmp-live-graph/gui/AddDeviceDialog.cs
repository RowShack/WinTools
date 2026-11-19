using SnmpLiveGraph.Core;

namespace SnmpLiveGraph;

/// <summary>Collects SNMP settings for one device and can test them (sysName / sysDescr / uptime).</summary>
public sealed class AddDeviceDialog : Form
{
    private readonly TextBox _name = new() { Width = 260, PlaceholderText = "optional label" };
    private readonly TextBox _host = new() { Width = 260, PlaceholderText = "IP address or host name" };
    private readonly NumericUpDown _port = new() { Minimum = 1, Maximum = 65535, Value = 161, Width = 70 };
    private readonly ComboBox _ver = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private readonly TextBox _community = new() { Width = 260, UseSystemPasswordChar = true, Text = "public" };
    private readonly TextBox _user = new() { Width = 260 };
    private readonly ComboBox _auth = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private readonly TextBox _authPass = new() { Width = 260, UseSystemPasswordChar = true };
    private readonly ComboBox _priv = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private readonly TextBox _privPass = new() { Width = 260, UseSystemPasswordChar = true };
    private readonly Label _testResult = new() { AutoSize = false, Height = 54, Width = 400, ForeColor = SystemColors.GrayText };
    private readonly Button _test = new() { Text = "Test", Width = 90 };
    private readonly List<Control> _v2Only = [], _v3Only = [];

    public SnmpTarget Result { get; private set; } = new();
    public SystemInfo? Info { get; private set; }

    public AddDeviceDialog(SnmpTarget? existing = null)
    {
        Text = "SNMP device";
        Font = new Font("Segoe UI", 9.5f);
        FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(12);

        _ver.Items.AddRange(["SNMP v2c", "SNMP v3"]); _ver.SelectedIndex = 0;
        _auth.Items.AddRange(["None", "SHA", "SHA-256"]); _auth.SelectedIndex = 1;
        _priv.Items.AddRange(["None", "AES-128"]); _priv.SelectedIndex = 1;

        var t = new TableLayoutPanel { AutoSize = true, ColumnCount = 2 };
        void Row(string l, Control c, List<Control>? group = null)
        {
            var lbl = new Label { Text = l, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 10, 6) };
            t.Controls.Add(lbl); t.Controls.Add(c);
            group?.Add(lbl); group?.Add(c);
        }
        var hostRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        hostRow.Controls.AddRange([_host, new Label { Text = "port", AutoSize = true, Margin = new Padding(6, 6, 4, 0) }, _port]);
        Row("Name:", _name); Row("Device:", hostRow); Row("Version:", _ver);
        Row("Community:", _community, _v2Only);
        Row("User name:", _user, _v3Only); Row("Authentication:", _auth, _v3Only); Row("Auth password:", _authPass, _v3Only);
        Row("Privacy:", _priv, _v3Only); Row("Privacy password:", _privPass, _v3Only);

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Bottom, Margin = new Padding(0, 10, 0, 0) };
        var ok = new Button { Text = "Add", Width = 90, DialogResult = DialogResult.None };
        var cancel = new Button { Text = "Cancel", Width = 90, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => { if (TryBuild(out var tgt)) { Result = tgt; DialogResult = DialogResult.OK; } };
        _test.Click += async (_, _) => await TestAsync();
        buttons.Controls.AddRange([cancel, ok, _test]);

        var root = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        root.Controls.AddRange([t, _testResult, buttons]);
        Controls.Add(root);
        AcceptButton = ok; CancelButton = cancel;
        _ver.SelectedIndexChanged += (_, _) => UpdateVisibility();
        _auth.SelectedIndexChanged += (_, _) => UpdateVisibility();
        UpdateVisibility();

        if (existing != null)
        {
            _name.Text = existing.Name; _host.Text = existing.Host; _port.Value = existing.Port; _ver.SelectedIndex = (int)existing.Version;
            _community.Text = existing.Community; _user.Text = existing.User; _auth.SelectedIndex = (int)existing.Auth; _authPass.Text = existing.AuthPassword;
            _priv.SelectedIndex = (int)existing.Priv; _privPass.Text = existing.PrivPassword;
        }
    }

    private void UpdateVisibility()
    {
        bool v3 = _ver.SelectedIndex == 1;
        foreach (var c in _v2Only) c.Visible = !v3;
        foreach (var c in _v3Only) c.Visible = v3;
        bool hasAuth = v3 && _auth.SelectedIndex != 0;
        _authPass.Enabled = hasAuth; _priv.Enabled = hasAuth; _privPass.Enabled = hasAuth && _priv.SelectedIndex != 0;
    }

    private bool TryBuild(out SnmpTarget t)
    {
        t = new SnmpTarget
        {
            Name = _name.Text.Trim(), Host = _host.Text.Trim(), Port = (int)_port.Value, Version = (SnmpVersion)_ver.SelectedIndex,
            Community = _community.Text, User = _user.Text.Trim(), Auth = (AuthProto)_auth.SelectedIndex, AuthPassword = _authPass.Text,
            Priv = (PrivProto)_priv.SelectedIndex, PrivPassword = _privPass.Text,
        };
        string? err = null;
        if (t.Host.Length == 0) err = "Enter the device address.";
        else if (t.Version == SnmpVersion.V2c && t.Community.Length == 0) err = "Enter the community string.";
        else if (t.Version == SnmpVersion.V3 && t.User.Length == 0) err = "SNMPv3 needs a user name.";
        else if (t.Version == SnmpVersion.V3 && t.Auth != AuthProto.None && t.AuthPassword.Length < 8) err = "SNMPv3 authentication passwords must be at least 8 characters.";
        else if (t.Version == SnmpVersion.V3 && t.Auth != AuthProto.None && t.Priv != PrivProto.None && t.PrivPassword.Length < 8) err = "SNMPv3 privacy passwords must be at least 8 characters.";
        if (err != null) { MessageBox.Show(this, err, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
        return true;
    }

    private async Task TestAsync()
    {
        if (!TryBuild(out var t)) return;
        _test.Enabled = false; _testResult.ForeColor = SystemColors.GrayText; _testResult.Text = "Contacting device…";
        try
        {
            Info = await new SnmpSession(t).GetSystemInfoAsync(default);
            _testResult.ForeColor = Color.SeaGreen;
            _testResult.Text = $"OK — {Info.Name}\n{Truncate(Info.Description, 90)}\nUptime {Info.UpTimeText}";
        }
        catch (Exception ex) { _testResult.ForeColor = Color.Firebrick; _testResult.Text = ex.Message; }
        finally { _test.Enabled = true; }
    }

    private static string Truncate(string s, int n) { s = s.Replace("\r", " ").Replace("\n", " "); return s.Length <= n ? s : s[..n] + "…"; }
}
