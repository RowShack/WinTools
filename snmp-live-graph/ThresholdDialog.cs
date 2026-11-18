using SnmpLiveGraph.Core;

namespace SnmpLiveGraph;

/// <summary>Sets the optional utilisation % and errors/s alarm levels of one interface tile.</summary>
public sealed class ThresholdDialog : Form
{
    private readonly CheckBox _useUtil = new() { Text = "Utilisation above", AutoSize = true };
    private readonly NumericUpDown _util = new() { DecimalPlaces = 1, Minimum = 0.1m, Maximum = 999, Value = 80, Width = 80 };
    private readonly CheckBox _useErr = new() { Text = "Errors per second (in + out) above", AutoSize = true };
    private readonly NumericUpDown _err = new() { DecimalPlaces = 2, Minimum = 0, Maximum = 1_000_000, Value = 1, Width = 80 };

    public Threshold Result { get; private set; } = new();

    public ThresholdDialog(Threshold? existing, long highSpeedMbps)
    {
        Text = "Thresholds";
        Font = new Font("Segoe UI", 9.5f);
        FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; Padding = new Padding(12);

        if (existing?.UtilPercent is double u) { _useUtil.Checked = true; _util.Value = (decimal)Math.Clamp(u, 0.1, 999); }
        if (existing?.ErrorsPerSec is double e) { _useErr.Checked = true; _err.Value = (decimal)Math.Clamp(e, 0, 1_000_000); }

        var note = new Label
        {
            AutoSize = true, MaximumSize = new Size(380, 0), ForeColor = SystemColors.GrayText,
            Text = highSpeedMbps > 0
                ? "Shown as dashed lines on the chart. While the latest sample is above a level, the tile turns red."
                : "This interface reports no link speed, so a utilisation level can't be evaluated or drawn. Errors/s still work.",
        };
        _useUtil.Enabled = _util.Enabled = highSpeedMbps > 0;
        if (highSpeedMbps <= 0) _useUtil.Checked = false;

        var grid = new TableLayoutPanel { AutoSize = true, ColumnCount = 3 };
        grid.Controls.Add(_useUtil); grid.Controls.Add(_util); grid.Controls.Add(new Label { Text = "%", AutoSize = true, Margin = new Padding(2, 6, 0, 0) });
        grid.Controls.Add(_useErr); grid.Controls.Add(_err); grid.Controls.Add(new Label { Text = "/s", AutoSize = true, Margin = new Padding(2, 6, 0, 0) });

        var ok = new Button { Text = "OK", Width = 90, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancel", Width = 90, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Bottom };
        buttons.Controls.AddRange([cancel, ok]);
        var root = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        root.Controls.AddRange([grid, note, buttons]);
        Controls.Add(root);
        AcceptButton = ok; CancelButton = cancel;
        ok.Click += (_, _) => Result = new Threshold
        {
            UtilPercent = _useUtil.Checked ? (double)_util.Value : null,
            ErrorsPerSec = _useErr.Checked ? (double)_err.Value : null,
        };
    }
}
