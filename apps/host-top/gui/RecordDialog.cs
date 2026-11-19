namespace HostTop;

/// <summary>Asks for how many minutes to record and where to write the CSV.</summary>
public sealed class RecordDialog : Form
{
    private readonly NumericUpDown _minutes = new() { Minimum = 1, Maximum = 1440, Value = 10, Width = 70 };
    private readonly TextBox _path = new() { Width = 340 };
    public int Minutes => (int)_minutes.Value;
    public string FilePath => _path.Text.Trim();

    public RecordDialog()
    {
        Text = "Record to CSV"; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false; StartPosition = FormStartPosition.CenterParent;
        AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(12); Font = new Font("Segoe UI", 9.5f);
        _path.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), $"host-top-{DateTime.Now:yyyyMMdd-HHmm}.csv");
        var browse = new Button { Text = "Browse…", AutoSize = true };
        browse.Click += (_, _) =>
        {
            using var d = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = Path.GetFileName(_path.Text) };
            if (d.ShowDialog(this) == DialogResult.OK) _path.Text = d.FileName;
        };
        var ok = new Button { Text = "Start recording", AutoSize = true, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        AcceptButton = ok; CancelButton = cancel;
        var t = new TableLayoutPanel { AutoSize = true, ColumnCount = 3, RowCount = 3 };
        t.Controls.Add(new Label { Text = "Minutes:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        t.Controls.Add(_minutes, 1, 0);
        t.Controls.Add(new Label { Text = "File:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
        t.Controls.Add(_path, 1, 1); t.Controls.Add(browse, 2, 1);
        t.Controls.Add(new Label { Text = "One line per active remote host per second: time, host, down/up bytes per second, connections, processes.", AutoSize = true, MaximumSize = new Size(480, 0), ForeColor = SystemColors.GrayText }, 0, 2);
        t.SetColumnSpan(t.GetControlFromPosition(0, 2)!, 3);
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft };
        buttons.Controls.Add(cancel); buttons.Controls.Add(ok);
        var root = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown };
        root.Controls.Add(t); root.Controls.Add(buttons);
        Controls.Add(root);
        FormClosing += (_, e) =>
        {
            if (DialogResult == DialogResult.OK && FilePath.Length == 0) { e.Cancel = true; MessageBox.Show(this, "Choose a file name."); }
        };
    }
}
