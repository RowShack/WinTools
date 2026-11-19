using FortiFlow.Core;

namespace FortiFlow;

/// <summary>Builds the 'diagnose debug flow' command sequence for a given filter.</summary>
public sealed class CommandPage : UserControl
{
    readonly TextBox _vdom = new() { Width = 180, PlaceholderText = "empty = no VDOM filter; root or index" };
    readonly TextBox _src = new() { Width = 180, PlaceholderText = "e.g. 192.0.2.10" };
    readonly TextBox _dst = new() { Width = 180, PlaceholderText = "e.g. 198.51.100.5" };
    readonly TextBox _port = new() { Width = 70, PlaceholderText = "optional" };
    readonly ComboBox _portScope = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
    readonly ComboBox _proto = new() { Width = 110 };
    readonly NumericUpDown _count = new() { Minimum = 1, Maximum = 100000, Value = 20, Width = 80 };
    readonly CheckBox _both = new() { Text = "Show replies too (use addr when only one address is given)", AutoSize = true, Checked = true };
    readonly TextBox _start = Output();
    readonly TextBox _stop = Output();
    readonly Label _msg = new() { AutoSize = true, MaximumSize = new Size(900, 0) };

    static TextBox Output() => new()
    {
        Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, Font = new Font("Consolas", 10f), ScrollBars = ScrollBars.Vertical,
        BackColor = Color.White, WordWrap = false,
    };

    public CommandPage()
    {
        Dock = DockStyle.Fill;
        Padding = new Padding(10);
        _portScope.Items.AddRange(["destination", "source", "either"]); _portScope.SelectedIndex = 0;
        _proto.Items.AddRange(["any", "tcp", "udp", "icmp"]); _proto.SelectedIndex = 0;

        var form = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 4, Padding = new Padding(0, 0, 0, 6) };
        void Row(string a, Control ca, string b, Control cb)
        {
            int r = form.RowCount++;
            form.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            form.Controls.Add(new Label { Text = a, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 8, 6) }, 0, r);
            form.Controls.Add(ca, 1, r);
            form.Controls.Add(new Label { Text = b, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(24, 6, 8, 6) }, 2, r);
            form.Controls.Add(cb, 3, r);
        }
        var portBox = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        portBox.Controls.AddRange([_port, _portScope]);
        Row("Source address", _src, "VDOM", _vdom);
        Row("Destination address", _dst, "Protocol", _proto);
        Row("Port", portBox, "Packets to trace", _count);
        form.RowCount++;
        form.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        form.Controls.Add(_both, 1, form.RowCount - 1);
        form.SetColumnSpan(_both, 3);

        var outputs = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2 };
        outputs.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 62));
        outputs.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38));
        outputs.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        outputs.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        outputs.Controls.Add(Header("1. Start the trace", _start), 0, 0);
        outputs.Controls.Add(Header("2. Stop and reset (always run this afterwards)", _stop), 1, 0);
        outputs.Controls.Add(_start, 0, 1);
        outputs.Controls.Add(_stop, 1, 1);

        var notes = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Padding = new Padding(0, 8, 0, 0) };
        notes.Controls.Add(new Label { Text = "Notes", Font = new Font("Segoe UI", 9f, FontStyle.Bold), AutoSize = true });
        foreach (var n in CommandGenerator.Notes)
            notes.Controls.Add(new Label { Text = "•  " + n, AutoSize = true, MaximumSize = new Size(1000, 0), Margin = new Padding(0, 2, 0, 2) });

        _msg.Margin = new Padding(0, 4, 0, 4);
        var msgHost = new Panel { Dock = DockStyle.Top, AutoSize = true };
        msgHost.Controls.Add(_msg);

        Controls.Add(outputs);
        Controls.Add(msgHost);
        Controls.Add(form);
        Controls.Add(notes);
        Controls.SetChildIndex(outputs, 0);

        foreach (var c in new Control[] { _vdom, _src, _dst, _port })
            c.TextChanged += (_, _) => Regenerate();
        _portScope.SelectedIndexChanged += (_, _) => Regenerate();
        _proto.SelectedIndexChanged += (_, _) => Regenerate();
        _proto.TextChanged += (_, _) => Regenerate();
        _count.ValueChanged += (_, _) => Regenerate();
        _both.CheckedChanged += (_, _) => Regenerate();
        Resize += (_, _) =>
        {
            _msg.MaximumSize = new Size(Math.Max(300, ClientSize.Width - 40), 0);
            foreach (var l in notes.Controls.OfType<Label>()) l.MaximumSize = new Size(Math.Max(300, ClientSize.Width - 40), 0);
        };
        Regenerate();
    }

    Control Header(string text, TextBox target)
    {
        var p = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 8, 2) };
        var copy = new Button { Text = "Copy", AutoSize = true };
        copy.Click += (_, _) => { if (target.Text.Length > 0) Clipboard.SetText(target.Text); };
        p.Controls.Add(new Label { Text = text, AutoSize = true, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Margin = new Padding(0, 6, 8, 0) });
        p.Controls.Add(copy);
        return p;
    }

    void Regenerate()
    {
        var r = CommandGenerator.Generate(new CommandRequest
        {
            Vdom = _vdom.Text, Source = _src.Text, Destination = _dst.Text, Port = _port.Text,
            PortScope = (PortScope)_portScope.SelectedIndex, Protocol = _proto.Text, Count = (int)_count.Value, BothDirections = _both.Checked,
        });
        if (!r.Ok)
        {
            _start.Text = ""; _stop.Text = "";
            _msg.ForeColor = Color.Firebrick;
            _msg.Text = r.Error;
            return;
        }
        _start.Text = r.StartText;
        _stop.Text = r.StopText;
        _msg.ForeColor = Color.DarkOrange;
        _msg.Text = string.Join(Environment.NewLine, r.Warnings.Select(w => "⚠ " + w));
    }

    public void Fill(string src, string dst, string port, string proto)
    {
        _src.Text = src; _dst.Text = dst; _port.Text = port; _proto.Text = proto;
    }
}
