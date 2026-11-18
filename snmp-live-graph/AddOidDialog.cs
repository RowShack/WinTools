using SnmpLiveGraph.Core;

namespace SnmpLiveGraph;

/// <summary>Picks a numeric OID (from a preset or typed) to graph for the selected device, and tests it live.</summary>
public sealed class AddOidDialog : Form
{
    private readonly SnmpSession _session;
    private readonly ComboBox _preset = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 380 };
    private readonly TextBox _name = new() { Width = 380, PlaceholderText = "label shown on the tile" };
    private readonly TextBox _oid = new() { Width = 380, PlaceholderText = "numeric OID, e.g. 1.3.6.1.4.1.12356.101.4.1.3.0" };
    private readonly TextBox _unit = new() { Width = 80 };
    private readonly NumericUpDown _scale = new() { DecimalPlaces = 4, Minimum = -1_000_000, Maximum = 1_000_000, Value = 1, Width = 90 };
    private readonly CheckBox _counter = new() { Text = "Treat as a counter and show its rate per second", AutoSize = true };
    private readonly Label _note = new() { AutoSize = false, Width = 520, Height = 38, ForeColor = SystemColors.GrayText };
    private readonly Label _result = new() { AutoSize = false, Width = 520, Height = 60 };
    private readonly Button _test = new() { Text = "Test", Width = 90 };

    public CustomOidSpec Result { get; private set; } = new();

    public AddOidDialog(SnmpSession session, string deviceName)
    {
        _session = session;
        Text = "Graph an OID — " + deviceName;
        Font = new Font("Segoe UI", 9.5f);
        FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(12);

        _preset.Items.Add("(custom OID)");
        foreach (var p in OidPresets.All) _preset.Items.Add(p);
        _preset.SelectedIndex = 0;
        _preset.SelectedIndexChanged += (_, _) =>
        {
            if (_preset.SelectedItem is not OidPreset p) { _note.Text = ""; return; }
            _name.Text = p.Name; _oid.Text = p.Oid; _unit.Text = p.Unit; _counter.Checked = p.AsCounter; _scale.Value = 1; _note.Text = p.Note;
            _result.Text = "";
        };

        var t = new TableLayoutPanel { AutoSize = true, ColumnCount = 2 };
        void Row(string l, Control c)
        {
            t.Controls.Add(new Label { Text = l, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 10, 6) });
            t.Controls.Add(c);
        }
        var misc = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        misc.Controls.AddRange([_unit, new Label { Text = "multiply by", AutoSize = true, Margin = new Padding(12, 6, 4, 0) }, _scale]);
        Row("Preset:", _preset); Row("Label:", _name); Row("OID:", _oid); Row("Unit:", misc);
        t.Controls.Add(new Label()); t.Controls.Add(_counter);

        var ok = new Button { Text = "Add", Width = 90 };
        var cancel = new Button { Text = "Cancel", Width = 90, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Bottom };
        buttons.Controls.AddRange([cancel, ok, _test]);
        var root = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        root.Controls.AddRange([t, _note, _result, buttons]);
        Controls.Add(root);
        AcceptButton = ok; CancelButton = cancel;

        _test.Click += async (_, _) => await TestAsync();
        ok.Click += (_, _) =>
        {
            if (CustomOidSpec.Validate(_oid.Text) is { } err) { MessageBox.Show(this, err, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            Result = Build();
            DialogResult = DialogResult.OK;
        };
    }

    private CustomOidSpec Build() => new()
    {
        Oid = CustomOidSpec.Normalise(_oid.Text), Name = _name.Text.Trim(), Unit = _unit.Text.Trim(), AsCounter = _counter.Checked, Scale = (double)_scale.Value,
    };

    /// <summary>Reads the OID once from the device. Table columns without a row index are resolved to the first row.</summary>
    private async Task TestAsync()
    {
        if (CustomOidSpec.Validate(_oid.Text) is { } err) { Show(err, false); return; }
        _test.Enabled = false; Show("Reading from the device…", null);
        try
        {
            var spec = Build();
            var r = await OidProbe.ProbeAsync(_session, spec.Oid, spec.Scale, default);
            if (!r.Reading.Ok) { Show(r.Reading.Problem!, false); return; }
            if (r.ResolvedOid != spec.Oid) _oid.Text = r.ResolvedOid;
            string extra = r.Instances > 1 ? $" The OID is a table column with {r.Instances} rows; the first row ({r.ResolvedOid}) was selected. Edit the OID to pick another row." : "";
            string hint = spec.AsCounter ? " (this is the raw counter; the graph shows its rate)" : "";
            Show($"OK — current value {r.Reading.Value:0.###}{(spec.Unit.Length > 0 ? " " + spec.Unit : "")}{hint}.{extra}", true);
        }
        catch (Exception ex) { Show(ex.Message, false); }
        finally { _test.Enabled = true; }
    }

    private void Show(string msg, bool? ok)
    {
        _result.Text = msg;
        _result.ForeColor = ok == true ? Color.SeaGreen : ok == false ? Color.Firebrick : SystemColors.GrayText;
    }
}
