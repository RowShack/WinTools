using System.Diagnostics;

namespace WinRouteEdit;

public sealed class MainForm : Form
{
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false, AllowUserToResizeRows = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = true, RowHeadersVisible = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells, BackgroundColor = SystemColors.Window,
    };
    private readonly ToolStripButton _refresh = new("Refresh") { DisplayStyle = ToolStripItemDisplayStyle.Text };
    private readonly ToolStripButton _add = new("Add route…") { DisplayStyle = ToolStripItemDisplayStyle.Text };
    private readonly ToolStripButton _delete = new("Delete selected") { DisplayStyle = ToolStripItemDisplayStyle.Text };
    private readonly ToolStripComboBox _profile = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 180 };
    private readonly ToolStripButton _apply = new("Apply") { DisplayStyle = ToolStripItemDisplayStyle.Text };
    private readonly ToolStripButton _remove = new("Remove") { DisplayStyle = ToolStripItemDisplayStyle.Text };
    private readonly ToolStripButton _manage = new("Manage…") { DisplayStyle = ToolStripItemDisplayStyle.Text };
    private readonly ToolStripTextBox _filter = new() { Width = 160, ToolTipText = "Filter routes" };
    private readonly TabControl _tabs = new() { Dock = DockStyle.Top, Height = 30, Padding = new Point(18, 4) };
    private readonly ToolStripStatusLabel _status = new("Ready");
    private readonly Panel _banner = new() { Dock = DockStyle.Top, Height = 34, BackColor = Color.FromArgb(255, 244, 206), Visible = false };

    private List<RouteEntry> _routes = [];
    private List<InterfaceInfo> _interfaces = [];
    private List<RouteProfile> _profiles = ProfileStore.Load();
    private readonly bool _isAdmin = RouteService.IsAdmin();
    private bool _busy;
    private DateTime _lastRefresh;
    private bool V6 => _tabs.SelectedIndex == 1;

    public MainForm()
    {
        Text = "Win-Route-Edit";
        Size = new Size(1150, 680);
        MinimumSize = new Size(800, 400);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);

        var tools = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(6, 4, 6, 4) };
        tools.Items.AddRange([
            _refresh, new ToolStripSeparator(), _add, _delete, new ToolStripSeparator(),
            new ToolStripLabel("Profile:"), _profile, _apply, _remove, _manage, new ToolStripSeparator(),
            new ToolStripLabel("Filter:"), _filter,
        ]);

        var warn = new Label
        {
            Text = "Not running as administrator — you can view routes but not change them.",
            AutoSize = true, Location = new Point(10, 8), ForeColor = Color.FromArgb(102, 77, 3),
        };
        var elevate = new Button { Text = "Restart as administrator", AutoSize = true, Dock = DockStyle.Right };
        elevate.Click += (_, _) => Elevate();
        _banner.Controls.AddRange([warn, elevate]);
        _banner.Visible = !_isAdmin;

        var statusBar = new StatusStrip();
        statusBar.Items.Add(_status);

        BuildColumns();
        _tabs.TabPages.Add("IPv4");
        _tabs.TabPages.Add("IPv6");
        Controls.Add(_grid);
        Controls.Add(_tabs);
        Controls.Add(_banner);
        Controls.Add(tools);
        Controls.Add(statusBar);
        _grid.BringToFront();

        var menu = new ContextMenuStrip();
        var copy = new ToolStripMenuItem("Copy rows");
        var toProfile = new ToolStripMenuItem("Add selected routes to profile…");
        menu.Items.AddRange([copy, toProfile]);
        copy.Click += (_, _) => CopyRows();
        toProfile.Click += (_, _) => SaveSelectionToProfile();
        _grid.ContextMenuStrip = menu;

        _refresh.Click += async (_, _) => await ReloadAsync();
        _add.Click += async (_, _) => await AddAsync();
        _delete.Click += async (_, _) => await DeleteAsync();
        _apply.Click += async (_, _) => await ApplyProfileAsync(remove: false);
        _remove.Click += async (_, _) => await ApplyProfileAsync(remove: true);
        _manage.Click += async (_, _) => await ManageAsync();
        _filter.TextChanged += (_, _) => Render();
        _tabs.SelectedIndexChanged += (_, _) => Render();
        _grid.SelectionChanged += (_, _) => UpdateButtons();
        _grid.SortCompare += GridSortCompare;
        _grid.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Delete) await DeleteAsync(); else if (e.KeyCode == Keys.F5) await ReloadAsync(); };
        _profile.SelectedIndexChanged += (_, _) => UpdateButtons();
        Shown += async (_, _) => await ReloadAsync();

        RefreshProfileList();
        UpdateButtons();
    }

    private void BuildColumns()
    {
        _grid.Columns.Add("dest", "Destination");
        _grid.Columns.Add("gw", "Gateway");
        _grid.Columns.Add("if", "Interface");
        _grid.Columns.Add("rm", "Route metric");
        _grid.Columns.Add("im", "Interface metric");
        _grid.Columns.Add("tm", "Total metric");
        _grid.Columns.Add("proto", "Origin");
        _grid.Columns.Add("persist", "Persistent");
        _grid.Columns.Add("active", "Active");
        foreach (DataGridViewColumn c in _grid.Columns) c.SortMode = DataGridViewColumnSortMode.Automatic;
        foreach (var n in new[] { "rm", "im", "tm" }) _grid.Columns[n]!.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;
    }

    // ---------- loading / rendering ----------

    private async Task ReloadAsync()
    {
        if (_busy) return;
        SetBusy(true, "Reading routing table…");
        try
        {
            var routesTask = RouteService.GetRoutesAsync();
            var ifTask = RouteService.GetInterfacesAsync();
            _routes = await routesTask;
            _interfaces = await ifTask;
            _lastRefresh = DateTime.Now;
            Render();
        }
        catch (Exception ex) { _status.Text = "Failed to read routes."; Error("Couldn't read the routing table", ex); }
        finally { SetBusy(false); }
    }

    private void Render()
    {
        string f = _filter.Text.Trim();
        var key = SelectedKeys();
        var view = _routes.Where(r => r.IsV6 == V6).Where(r => f.Length == 0 ||
            $"{r.Prefix} {r.NextHop} {r.IfAlias} {r.Protocol}".Contains(f, StringComparison.OrdinalIgnoreCase));

        _grid.Rows.Clear();
        foreach (var r in view)
        {
            int i = _grid.Rows.Add(r.Prefix, r.IsOnLink ? "On-link" : r.NextHop, $"{r.IfAlias} (#{r.IfIndex})", r.RouteMetric,
                r.IfMetric, r.TotalMetric, r.Protocol, r.Persistent ? "Yes" : "", r.Active ? "" : "No (saved only)");
            var row = _grid.Rows[i];
            row.Tag = r;
            if (r.Prefix is "0.0.0.0/0" or "::/0") row.DefaultCellStyle.Font = new Font(Font, FontStyle.Bold);
            if (!r.Active) row.DefaultCellStyle.ForeColor = SystemColors.GrayText;
            else if (r.Persistent) row.DefaultCellStyle.BackColor = Color.FromArgb(232, 244, 255);
            if (key.Contains((r.Prefix, r.NextHop, r.IfIndex))) row.Selected = true;
        }
        var mine = _routes.Where(r => r.IsV6 == V6).ToList();
        _status.Text = $"{(V6 ? "IPv6" : "IPv4")}: {mine.Count} routes  ·  {mine.Count(r => r.Persistent)} persistent  ·  refreshed {_lastRefresh:HH:mm:ss}";
        if (_grid.SortedColumn is null) _grid.Sort(_grid.Columns["dest"]!, System.ComponentModel.ListSortDirection.Ascending);
        UpdateButtons();
    }

    private HashSet<(string, string, int)> SelectedKeys() =>
        _grid.SelectedRows.Cast<DataGridViewRow>().Select(r => r.Tag).OfType<RouteEntry>()
            .Select(r => (r.Prefix, r.NextHop, r.IfIndex)).ToHashSet();

    private List<RouteEntry> SelectedRoutes() =>
        _grid.SelectedRows.Cast<DataGridViewRow>().Select(r => r.Tag).OfType<RouteEntry>().ToList();

    private void GridSortCompare(object? s, DataGridViewSortCompareEventArgs e)
    {
        if (e.Column.Name == "dest")
        {
            e.SortResult = RouteService.SortKey(e.CellValue1?.ToString() ?? "").CompareTo(RouteService.SortKey(e.CellValue2?.ToString() ?? ""));
            e.Handled = true;
        }
        else if (e.Column.Name is "rm" or "im" or "tm")
        {
            e.SortResult = Convert.ToInt32(e.CellValue1).CompareTo(Convert.ToInt32(e.CellValue2));
            e.Handled = true;
        }
    }

    // ---------- actions ----------

    private async Task AddAsync()
    {
        using var d = new AddRouteDialog("Add route", _interfaces.Where(i => i.V6 == V6).ToList(), null, V6);
        if (d.ShowDialog(this) != DialogResult.OK) return;
        var r = d.Result;
        await Run($"Adding {r.Prefix}…", async () =>
        {
            await RouteService.AddRouteAsync(r.Prefix, r.NextHop, r.Metric, r.IfIndex, r.Persistent);
            return $"Added {r.Prefix} via {r.NextHop}";
        });
    }

    private async Task DeleteAsync()
    {
        var sel = SelectedRoutes();
        if (sel.Count == 0 || !_isAdmin) return;
        string list = string.Join("\n", sel.Take(8).Select(r => $"  {r.Prefix} via {(r.IsOnLink ? "on-link" : r.NextHop)}  [{r.IfAlias}]"))
            + (sel.Count > 8 ? $"\n  … and {sel.Count - 8} more" : "");
        bool risky = sel.Any(r => r.Prefix is "0.0.0.0/0" or "::/0");
        string warn = risky ? "\n\nThis includes a DEFAULT ROUTE — deleting it can cut off internet access." : "";
        if (MessageBox.Show(this, $"Delete {sel.Count} route(s)?\n\n{list}{warn}", "Delete routes",
                MessageBoxButtons.YesNo, risky ? MessageBoxIcon.Warning : MessageBoxIcon.Question) != DialogResult.Yes) return;

        await Run("Deleting routes…", async () =>
        {
            var errors = new List<string>();
            foreach (var r in sel)
            {
                try { await RouteService.DeleteRouteAsync(r); }
                catch (Exception ex) { errors.Add($"{r.Prefix} via {r.NextHop}: {ex.Message}"); }
            }
            if (errors.Count > 0) throw new InvalidOperationException(string.Join("\n", errors));
            return $"Deleted {sel.Count} route(s)";
        });
    }

    private async Task ApplyProfileAsync(bool remove)
    {
        if (_profile.SelectedItem is not RouteProfile p) return;
        if (remove && MessageBox.Show(this, $"Remove the {p.Routes.Count} route(s) of profile \"{p.Name}\" from this PC?", "Remove profile routes",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        await Run(remove ? $"Removing {p.Name}…" : $"Applying {p.Name}…", async () =>
        {
            var errors = remove ? await ProfileStore.RemoveAsync(p) : await ProfileStore.ApplyAsync(p);
            if (errors.Count > 0) throw new InvalidOperationException(string.Join("\n", errors));
            return $"{(remove ? "Removed" : "Applied")} profile \"{p.Name}\"";
        });
    }

    private async Task ManageAsync()
    {
        string? sel = (_profile.SelectedItem as RouteProfile)?.Name;
        using var d = new ProfilesDialog(_profiles, _interfaces.DistinctBy(i => i.Index).ToList(), sel);
        d.ShowDialog(this);
        RefreshProfileList(sel);
        await Task.CompletedTask;
    }

    private void SaveSelectionToProfile()
    {
        var sel = SelectedRoutes().Where(r => !r.IsOnLink || r.IfIndex > 0).ToList();
        if (sel.Count == 0) return;
        var names = _profiles.Select(p => p.Name).ToList();
        string? name = Prompt("Add to profile", "Profile name (existing names are added to, new names are created):",
            (_profile.SelectedItem as RouteProfile)?.Name ?? "");
        if (string.IsNullOrWhiteSpace(name)) return;
        var p = _profiles.FirstOrDefault(x => x.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase));
        if (p is null) { p = new RouteProfile { Name = name.Trim() }; _profiles.Add(p); }
        foreach (var r in sel)
            p.Routes.Add(new ProfileRoute { Prefix = r.Prefix, NextHop = r.NextHop, Metric = r.RouteMetric, IfIndex = r.IfIndex, Persistent = r.Persistent });
        try { ProfileStore.Save(_profiles); _status.Text = $"Added {sel.Count} route(s) to profile \"{p.Name}\""; }
        catch (Exception ex) { Error("Couldn't save profiles", ex); }
        RefreshProfileList(p.Name);
    }

    private string? Prompt(string title, string label, string initial)
    {
        using var f = new Form
        {
            Text = title, FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false, MinimizeBox = false, ClientSize = new Size(400, 120), Font = Font,
        };
        var lbl = new Label { Text = label, Left = 12, Top = 10, Width = 376, Height = 36 };
        var tb = new TextBox { Left = 12, Top = 48, Width = 376, Text = initial };
        var ok = new Button { Text = "OK", Left = 228, Top = 82, Width = 76, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancel", Left = 312, Top = 82, Width = 76, DialogResult = DialogResult.Cancel };
        f.Controls.AddRange([lbl, tb, ok, cancel]); f.AcceptButton = ok; f.CancelButton = cancel;
        return f.ShowDialog(this) == DialogResult.OK ? tb.Text : null;
    }

    private void CopyRows()
    {
        var sel = SelectedRoutes();
        if (sel.Count == 0) return;
        Clipboard.SetText(string.Join(Environment.NewLine,
            sel.Select(r => $"{r.Prefix}\t{r.NextHop}\t{r.IfAlias}\t{r.TotalMetric}\t{(r.Persistent ? "persistent" : "")}")));
    }

    // ---------- helpers ----------

    /// <summary>Runs a modifying action, then refreshes. Exceptions are shown to the user.</summary>
    private async Task Run(string busyText, Func<Task<string>> action)
    {
        if (_busy) return;
        SetBusy(true, busyText);
        string status;
        try { status = await action(); }
        catch (Exception ex) { status = "Failed"; Error("Route change failed", ex); }
        SetBusy(false);
        await ReloadAsync();
        if (status != "Failed") _status.Text = status + "  ·  " + _status.Text;
    }

    private void Error(string title, Exception ex) =>
        MessageBox.Show(this, ex.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);

    private void SetBusy(bool busy, string? text = null)
    {
        _busy = busy;
        UseWaitCursor = busy;
        if (text != null) _status.Text = text;
        UpdateButtons();
    }

    private void RefreshProfileList(string? select = null)
    {
        _profiles = _profiles.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
        _profile.Items.Clear();
        foreach (var p in _profiles) _profile.Items.Add(p);
        var pick = _profiles.FirstOrDefault(p => p.Name == select);
        if (pick != null) _profile.SelectedItem = pick; else if (_profiles.Count > 0) _profile.SelectedIndex = 0;
        UpdateButtons();
    }

    private void UpdateButtons()
    {
        bool can = _isAdmin && !_busy;
        _refresh.Enabled = !_busy;
        _add.Enabled = can;
        _delete.Enabled = can && _grid.SelectedRows.Count > 0;
        _apply.Enabled = _remove.Enabled = can && _profile.SelectedItem is RouteProfile;
        _manage.Enabled = !_busy;
    }

    private void Elevate()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
            Close();
        }
        catch (System.ComponentModel.Win32Exception) { /* user cancelled UAC */ }
    }
}
