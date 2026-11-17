namespace WinRouteEdit;

/// <summary>Create, rename, delete and edit route profiles.</summary>
public sealed class ProfilesDialog : Form
{
    private readonly List<RouteProfile> _profiles;
    private readonly IReadOnlyList<InterfaceInfo> _interfaces;
    private readonly ListBox _list = new() { Dock = DockStyle.Fill, IntegralHeight = false };
    private readonly ListView _routes = new()
    {
        Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = true, HideSelection = false,
    };
    private readonly Button _newP = new() { Text = "New…", AutoSize = true };
    private readonly Button _renameP = new() { Text = "Rename…", AutoSize = true };
    private readonly Button _delP = new() { Text = "Delete", AutoSize = true };
    private readonly Button _addR = new() { Text = "Add route…", AutoSize = true };
    private readonly Button _editR = new() { Text = "Edit…", AutoSize = true };
    private readonly Button _delR = new() { Text = "Remove route", AutoSize = true };

    public ProfilesDialog(List<RouteProfile> profiles, IReadOnlyList<InterfaceInfo> interfaces, string? select = null)
    {
        _profiles = profiles; _interfaces = interfaces;
        Text = "Manage route profiles";
        Font = new Font("Segoe UI", 9.5f);
        Size = new Size(820, 480); MinimumSize = new Size(640, 360);
        StartPosition = FormStartPosition.CenterParent;

        foreach (var (name, w) in new[] { ("Destination", 150), ("Gateway", 120), ("Metric", 60), ("Interface", 150), ("Persistent", 80) })
            _routes.Columns.Add(name, w);

        var left = new GroupBox { Text = "Profiles", Dock = DockStyle.Fill, Padding = new Padding(6) };
        var leftBtns = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true };
        leftBtns.Controls.AddRange([_newP, _renameP, _delP]);
        left.Controls.Add(_list); left.Controls.Add(leftBtns);

        var right = new GroupBox { Text = "Routes in selected profile", Dock = DockStyle.Fill, Padding = new Padding(6) };
        var rightBtns = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true };
        rightBtns.Controls.AddRange([_addR, _editR, _delR]);
        right.Controls.Add(_routes); right.Controls.Add(rightBtns);

        var split = new SplitContainer { Dock = DockStyle.Fill, SplitterDistance = 240 };
        split.Panel1.Controls.Add(left); split.Panel2.Controls.Add(right);
        var close = new Button { Text = "Close", DialogResult = DialogResult.OK, Width = 90 };
        var bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Padding = new Padding(6) };
        bottom.Controls.Add(close);
        Controls.Add(split); Controls.Add(bottom);
        AcceptButton = close;

        _newP.Click += (_, _) => NewProfile();
        _renameP.Click += (_, _) => RenameProfile();
        _delP.Click += (_, _) => DeleteProfile();
        _addR.Click += (_, _) => AddRoute();
        _editR.Click += (_, _) => EditRoute();
        _delR.Click += (_, _) => RemoveRoutes();
        _routes.DoubleClick += (_, _) => EditRoute();
        _list.SelectedIndexChanged += (_, _) => { ShowRoutes(); UpdateButtons(); };
        _routes.SelectedIndexChanged += (_, _) => UpdateButtons();
        FormClosing += (_, _) => Persist();

        RefreshList(select);
    }

    private RouteProfile? Current => _list.SelectedItem as RouteProfile;

    private void RefreshList(string? select = null)
    {
        _list.Items.Clear();
        foreach (var p in _profiles.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)) _list.Items.Add(p);
        var pick = _list.Items.Cast<RouteProfile>().FirstOrDefault(p => p.Name == select);
        if (pick != null) _list.SelectedItem = pick; else if (_list.Items.Count > 0) _list.SelectedIndex = 0;
        ShowRoutes(); UpdateButtons();
    }

    private void ShowRoutes()
    {
        _routes.Items.Clear();
        if (Current is null) return;
        foreach (var r in Current.Routes)
        {
            string ifc = r.IfIndex is int i ? (_interfaces.FirstOrDefault(x => x.Index == i)?.ToString() ?? $"#{i}") : "Automatic";
            _routes.Items.Add(new ListViewItem([r.Prefix, r.NextHop, r.Metric.ToString(), ifc, r.Persistent ? "Yes" : "No"]) { Tag = r });
        }
    }

    private void UpdateButtons()
    {
        bool has = Current != null;
        _renameP.Enabled = _delP.Enabled = _addR.Enabled = has;
        _editR.Enabled = has && _routes.SelectedItems.Count == 1;
        _delR.Enabled = has && _routes.SelectedItems.Count > 0;
    }

    private string? AskName(string title, string initial)
    {
        using var f = new Form
        {
            Text = title, FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false, MinimizeBox = false, ClientSize = new Size(340, 90), Font = Font,
        };
        var tb = new TextBox { Left = 12, Top = 12, Width = 316, Text = initial };
        var ok = new Button { Text = "OK", Left = 168, Top = 50, Width = 76, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancel", Left = 252, Top = 50, Width = 76, DialogResult = DialogResult.Cancel };
        f.Controls.AddRange([tb, ok, cancel]); f.AcceptButton = ok; f.CancelButton = cancel;
        if (f.ShowDialog(this) != DialogResult.OK) return null;
        string name = tb.Text.Trim();
        if (name.Length == 0) return null;
        if (_profiles.Any(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && p != Current))
        { MessageBox.Show(this, "A profile with that name already exists.", Text); return null; }
        return name;
    }

    private void NewProfile()
    {
        if (AskName("New profile", "") is not { } name) return;
        _profiles.Add(new RouteProfile { Name = name });
        Persist(); RefreshList(name);
    }

    private void RenameProfile()
    {
        if (Current is null || AskName("Rename profile", Current.Name) is not { } name) return;
        Current.Name = name; Persist(); RefreshList(name);
    }

    private void DeleteProfile()
    {
        if (Current is null) return;
        if (MessageBox.Show(this, $"Delete profile \"{Current.Name}\"? Routes already applied to this PC are not touched.", Text,
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        _profiles.Remove(Current); Persist(); RefreshList();
    }

    private void AddRoute()
    {
        if (Current is null) return;
        using var d = new AddRouteDialog("Add route to profile", _interfaces);
        if (d.ShowDialog(this) != DialogResult.OK) return;
        Current.Routes.Add(d.Result); Persist(); ShowRoutes();
    }

    private void EditRoute()
    {
        if (Current is null || _routes.SelectedItems.Count != 1) return;
        var r = (ProfileRoute)_routes.SelectedItems[0].Tag!;
        using var d = new AddRouteDialog("Edit profile route", _interfaces, r);
        if (d.ShowDialog(this) != DialogResult.OK) return;
        int idx = Current.Routes.IndexOf(r);
        Current.Routes[idx] = d.Result; Persist(); ShowRoutes();
    }

    private void RemoveRoutes()
    {
        if (Current is null) return;
        foreach (ListViewItem it in _routes.SelectedItems) Current.Routes.Remove((ProfileRoute)it.Tag!);
        Persist(); ShowRoutes(); UpdateButtons();
    }

    private void Persist()
    {
        try { ProfileStore.Save(_profiles); }
        catch (Exception ex) { MessageBox.Show(this, "Couldn't save profiles: " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }
}
