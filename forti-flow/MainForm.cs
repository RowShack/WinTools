namespace FortiFlow;

public sealed class MainForm : Form
{
    public readonly AnalyzerPage Analyzer = new();
    public readonly CommandPage Commands = new();
    public readonly TabControl Tabs = new() { Dock = DockStyle.Fill };

    public MainForm()
    {
        Text = "FortiFlow - FortiGate debug flow explainer";
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(1180, 760);
        MinimumSize = new Size(900, 560);
        StartPosition = FormStartPosition.CenterScreen;

        var t1 = new TabPage("Explain debug flow output") { Padding = new Padding(0) };
        t1.Controls.Add(Analyzer);
        var t2 = new TabPage("Command generator");
        t2.Controls.Add(Commands);
        Tabs.TabPages.AddRange([t1, t2]);
        Controls.Add(Tabs);
    }
}
