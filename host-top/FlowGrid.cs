using HostTop.Core;

namespace HostTop;

public sealed class GridColumn
{
    public string Header = "";
    public Func<FlowRow, string> Text = _ => "";
    /// <summary>Raw value for CSV export (defaults to <see cref="Text"/>).</summary>
    public Func<FlowRow, string>? Export;
    public Comparison<FlowRow>? Compare;
    public bool Right;
    public int Width = 90;
    public bool Spark;
    public Func<bool>? Visible;
}

/// <summary>Virtual-mode grid over <see cref="FlowRow"/>s: sort by any column, filter, keeps the selected row across refreshes.</summary>
public sealed class FlowGrid : DataGridView
{
    private readonly List<GridColumn> _cols;
    private List<FlowRow> _rows = [];
    private int _sortCol = -1;
    private bool _desc = true;
    private string? _selectedId;
    private bool _restoring;

    public IReadOnlyList<FlowRow> Rows2 => _rows;
    public event Action<FlowRow?>? RowSelected;
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public Func<FlowRow, string?>? ExtraSearch { get; set; }

    public FlowGrid(IEnumerable<GridColumn> cols, int defaultSort)
    {
        _cols = cols.ToList();
        VirtualMode = true; ReadOnly = true; AllowUserToAddRows = false; AllowUserToResizeRows = false; RowHeadersVisible = false;
        SelectionMode = DataGridViewSelectionMode.FullRowSelect; MultiSelect = false; BackgroundColor = SystemColors.Window;
        Dock = DockStyle.Fill; AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None; RowTemplate.Height = 24;
        AllowUserToResizeColumns = true; BorderStyle = BorderStyle.None; CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        EnableHeadersVisualStyles = true;
        DoubleBuffered = true;
        foreach (var c in _cols)
        {
            var col = new DataGridViewTextBoxColumn { HeaderText = c.Header, Width = c.Width, SortMode = DataGridViewColumnSortMode.Programmatic, Resizable = DataGridViewTriState.True };
            col.DefaultCellStyle.Alignment = c.Right ? DataGridViewContentAlignment.MiddleRight : DataGridViewContentAlignment.MiddleLeft;
            if (c.Spark) { col.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill; col.MinimumWidth = 120; }
            Columns.Add(col);
        }
        _sortCol = defaultSort;
        UpdateColumnVisibility();
    }

    public void UpdateColumnVisibility()
    {
        for (int i = 0; i < _cols.Count; i++) Columns[i].Visible = _cols[i].Visible?.Invoke() ?? true;
        UpdateGlyphs();
    }

    private void UpdateGlyphs()
    {
        for (int i = 0; i < Columns.Count; i++)
            Columns[i].HeaderCell.SortGlyphDirection = i == _sortCol ? (_desc ? SortOrder.Descending : SortOrder.Ascending) : SortOrder.None;
    }

    protected override void OnColumnHeaderMouseClick(DataGridViewCellMouseEventArgs e)
    {
        base.OnColumnHeaderMouseClick(e);
        if (_cols[e.ColumnIndex].Spark) return;
        if (_sortCol == e.ColumnIndex) _desc = !_desc; else { _sortCol = e.ColumnIndex; _desc = !_cols[e.ColumnIndex].Right ? false : true; }
        var snap = _rows; _rows = Sort(snap); UpdateGlyphs(); Refill();
    }

    private List<FlowRow> Sort(List<FlowRow> rows)
    {
        if (_sortCol < 0 || _cols[_sortCol].Compare is not { } cmp) return rows;
        var l = rows.ToList();
        l.Sort((a, b) => _desc ? cmp(b, a) : cmp(a, b));
        return l;
    }

    public void SetData(IReadOnlyList<FlowRow> data, string? filter, Func<FlowRow, bool>? predicate = null)
    {
        var f = data.Where(r => (predicate?.Invoke(r) ?? true) && RowFilter.Matches(r.SearchText + " " + (ExtraSearch?.Invoke(r) ?? ""), filter)).ToList();
        _rows = Sort(f);
        Refill();
    }

    private void Refill()
    {
        _restoring = true;
        try
        {
            if (RowCount != _rows.Count) RowCount = _rows.Count;
            Invalidate();
            ClearSelection();
            if (_selectedId != null)
            {
                int idx = _rows.FindIndex(r => r.Id == _selectedId);
                if (idx >= 0) Rows[idx].Selected = true;
            }
        }
        finally { _restoring = false; }
        RowSelected?.Invoke(Selected);
    }

    public FlowRow? Selected => _selectedId == null ? null : _rows.FirstOrDefault(r => r.Id == _selectedId);

    protected override void OnSelectionChanged(EventArgs e)
    {
        base.OnSelectionChanged(e);
        if (_restoring) return;
        _selectedId = SelectedRows.Count > 0 && SelectedRows[0].Index < _rows.Count ? _rows[SelectedRows[0].Index].Id : null;
        RowSelected?.Invoke(Selected);
    }

    protected override void OnCellValueNeeded(DataGridViewCellValueEventArgs e)
    {
        if (e.RowIndex >= 0 && e.RowIndex < _rows.Count && e.ColumnIndex < _cols.Count && !_cols[e.ColumnIndex].Spark)
            e.Value = _cols[e.ColumnIndex].Text(_rows[e.RowIndex]);
        base.OnCellValueNeeded(e);
    }

    protected override void OnCellPainting(DataGridViewCellPaintingEventArgs e)
    {
        if (e.RowIndex >= 0 && e.RowIndex < _rows.Count && e.ColumnIndex >= 0 && _cols[e.ColumnIndex].Spark)
        {
            e.PaintBackground(e.ClipBounds, true);
            var r = _rows[e.RowIndex];
            var rect = Rectangle.Inflate(e.CellBounds, -3, -3);
            Sparkline.Draw(e.Graphics!, rect, r.DownHistory, r.UpHistory, Sparkline.Max(r.DownHistory, r.UpHistory));
            e.Handled = true;
            return;
        }
        base.OnCellPainting(e);
    }

    public (List<string> Headers, List<List<string>> Rows) ExportTable()
    {
        var cols = _cols.Where(c => !c.Spark && (c.Visible?.Invoke() ?? true)).ToList();
        return (cols.Select(c => c.Header).ToList(), _rows.Select(r => cols.Select(c => (c.Export ?? c.Text)(r)).ToList()).ToList());
    }
}
