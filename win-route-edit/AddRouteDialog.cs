namespace WinRouteEdit;

/// <summary>Collects and validates one route (used for both live routes and profile routes).</summary>
public sealed class AddRouteDialog : Form
{
    private readonly TextBox _dest = new() { Width = 240, PlaceholderText = "10.20.0.0/16  or  10.20.0.0/255.255.0.0" };
    private readonly TextBox _gw = new() { Width = 240, PlaceholderText = "192.168.1.1  (0.0.0.0 = on-link)" };
    private readonly NumericUpDown _metric = new() { Minimum = 0, Maximum = 9999, Value = 1, Width = 80 };
    private readonly ComboBox _if = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 240 };
    private readonly CheckBox _persist = new() { Text = "Persistent (survives reboot)", AutoSize = true };

    public ProfileRoute Result { get; private set; } = new();

    public AddRouteDialog(string title, IReadOnlyList<InterfaceInfo> interfaces, ProfileRoute? existing = null)
    {
        Text = title;
        Font = new Font("Segoe UI", 9.5f);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(12);

        _if.Items.Add("Automatic (interface that reaches the gateway)");
        foreach (var i in interfaces) _if.Items.Add(i);
        _if.SelectedIndex = 0;

        if (existing != null)
        {
            _dest.Text = existing.Prefix; _gw.Text = existing.NextHop;
            _metric.Value = Math.Clamp(existing.Metric, 0, 9999); _persist.Checked = existing.Persistent;
            var match = interfaces.FirstOrDefault(i => i.Index == existing.IfIndex);
            if (match != null) _if.SelectedItem = match;
        }

        var grid = new TableLayoutPanel { AutoSize = true, ColumnCount = 2 };
        void Row(string label, Control c)
        {
            grid.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 12, 6) });
            c.Margin = new Padding(0, 3, 0, 3);
            grid.Controls.Add(c);
        }
        Row("Destination:", _dest);
        Row("Gateway:", _gw);
        Row("Metric:", _metric);
        Row("Interface:", _if);
        grid.Controls.Add(new Label());
        grid.Controls.Add(_persist);

        var ok = new Button { Text = "OK", DialogResult = DialogResult.None, Width = 90 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Width = 90 };
        ok.Click += (_, _) => TryAccept();
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Bottom, AutoSize = true, Margin = new Padding(0, 12, 0, 0) };
        buttons.Controls.AddRange([cancel, ok]);

        var root = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        root.Controls.AddRange([grid, buttons]);
        Controls.Add(root);
        AcceptButton = ok; CancelButton = cancel;
    }

    private void TryAccept()
    {
        if (!RouteService.TryParsePrefix(_dest.Text, out var cidr, out var err)) { Warn(err, _dest); return; }
        if (!RouteService.TryIPv4(_gw.Text, out var gw)) { Warn("Gateway is not a valid IPv4 address (use 0.0.0.0 for on-link).", _gw); return; }
        int? ifIndex = _if.SelectedItem is InterfaceInfo i ? i.Index : null;
        if (ifIndex is null && gw.Equals(System.Net.IPAddress.Any)) { Warn("Pick an interface for an on-link (0.0.0.0) route.", _if); return; }

        Result = new ProfileRoute { Prefix = cidr, NextHop = gw.ToString(), Metric = (int)_metric.Value, IfIndex = ifIndex, Persistent = _persist.Checked };
        DialogResult = DialogResult.OK;
    }

    private void Warn(string msg, Control focus)
    {
        MessageBox.Show(this, msg, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        focus.Focus();
    }
}
