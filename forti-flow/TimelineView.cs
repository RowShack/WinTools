using FortiFlow.Core;

namespace FortiFlow;

/// <summary>Right-hand pane: the summary header and the step cards of one packet (or all packets of one session).</summary>
public sealed class TimelineView : Panel
{
    public static readonly Color Green = Color.FromArgb(46, 158, 79), Red = Color.FromArgb(211, 51, 51),
        Blue = Color.FromArgb(45, 111, 214), Grey = Color.FromArgb(128, 128, 128);

    readonly FlowLayoutPanel _flow = new()
    {
        Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(8),
    };
    static readonly Dictionary<(string, float, FontStyle), Font> Fonts = new();
    static Font F(string family, float size, FontStyle style = FontStyle.Regular)
    {
        var k = (family, size, style);
        if (!Fonts.TryGetValue(k, out var f)) Fonts[k] = f = new Font(family, size, style);
        return f;
    }
    int _cardW = 700, _inner = 670;
    const int MaxSessionPackets = 8;
    readonly List<Control> _cards = new();
    readonly List<Label> _wraps = new();
    readonly List<Control> _wide = new();

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public bool CollapsePolicyChecks { get; set; } = true;

    public TimelineView()
    {
        BackColor = SystemColors.ControlLight;
        _flow.BackColor = SystemColors.ControlLight;
        Controls.Add(_flow);
        _flow.Resize += (_, _) => LayoutCards();
    }

    public static Color VerdictColor(Verdict v) => v switch
    {
        Verdict.Forwarded => Green, Verdict.Dropped => Red, Verdict.LocalIn => Blue, _ => Grey,
    };

    static Color CardColor(string card) => card switch
    {
        "received" => Color.FromArgb(70, 90, 120), "session" => Color.FromArgb(130, 80, 170), "route" => Color.FromArgb(0, 140, 150),
        "policy" => Color.FromArgb(230, 140, 20), "policy-check" => Color.FromArgb(240, 190, 110), "nat" => Color.FromArgb(200, 60, 140),
        "ipsec" => Color.FromArgb(70, 70, 180), "offload" => Color.FromArgb(110, 140, 170), "egress" => Green, "drop" => Red,
        "detail" => Color.FromArgb(190, 190, 190), _ => Color.FromArgb(150, 150, 150),
    };

    public void Clear(string? message = null)
    {
        _flow.SuspendLayout();
        ClearCards();
        if (message != null) Add(Message(message));
        _flow.ResumeLayout();
        LayoutCards();
    }

    void ClearCards()
    {
        foreach (var c in _cards) c.Dispose();
        _cards.Clear(); _wraps.Clear(); _wide.Clear();
    }

    public void ShowPacket(PacketTrace p)
    {
        _flow.SuspendLayout();
        ClearCards();
        AddPacket(p, true);
        _flow.ResumeLayout();
        LayoutCards();
        _flow.AutoScrollPosition = new Point(0, 0);
    }

    public void ShowSession(SessionGroup s, Func<PacketTrace, bool> visible)
    {
        _flow.SuspendLayout();
        ClearCards();
        var pk = s.Packets.Where(visible).ToList();
        var o = s.Packets.FirstOrDefault(x => x.Direction == "original") ?? s.Packets[0];
        var title = Lbl($"Session {s.Id}", 13, true, VerdictColor(s.Verdict));
        var table = new System.Text.StringBuilder();
        foreach (var p in pk)
            table.AppendLine($"#{p.Index,-5} {(p.Direction == "reply" ? "reply   " : p.Direction == "original" ? "original" : "        ")}  {Exporter.VerdictText(p.Verdict),-9}  {p.Time}  {p.VerdictTitle}");
        var lines = new List<Control> { title, Wrap($"{o.ProtoName} {o.Src}:{o.SrcPort} → {o.Dst}:{o.DstPort}   ({s.Packets.Count} packets in this paste)", bold: true) };
        var tbl = new TextBox
        {
            Multiline = true, ReadOnly = true, WordWrap = false, Font = F("Consolas", 9f), BackColor = Color.White, Text = table.ToString().TrimEnd(),
            ScrollBars = pk.Count > 12 ? ScrollBars.Both : ScrollBars.None, Height = Math.Min(pk.Count, 12) * 15 + 10, Width = _inner, Margin = new Padding(0, 2, 0, 2),
        };
        _wide.Add(tbl); tbl.Disposed += (_, _) => _wide.Remove(tbl);
        lines.Add(tbl);
        if (pk.Count < s.Packets.Count) lines.Add(Wrap($"{s.Packets.Count - pk.Count} packet(s) hidden by the current filters.", gray: true));
        if (pk.Count > MaxSessionPackets) lines.Add(Wrap($"Timelines are shown for the first {MaxSessionPackets} packets only, to keep the window fast. Select any other packet in Packets mode for its full timeline.", bold: true));
        Add(Card(VerdictColor(s.Verdict), lines, 8));
        foreach (var p in pk.Take(MaxSessionPackets))
        {
            Add(Banner($"Packet {p.Label}   —   {Exporter.VerdictText(p.Verdict)}", VerdictColor(p.Verdict)));
            AddPacket(p, false);
        }
        _flow.ResumeLayout();
        LayoutCards();
        _flow.AutoScrollPosition = new Point(0, 0);
    }

    static string Short(string s) => s.Length <= 90 ? s : s[..87] + "…";

    void AddPacket(PacketTrace p, bool withHeader)
    {
        if (withHeader) AddHeader(p);
        foreach (var s in p.Steps)
        {
            if (s.Card == "policy-check" && !CollapsePolicyChecks)
                foreach (var ch in s.Children) Add(StepCard(ch));
            else Add(StepCard(s));
        }
    }

    void AddHeader(PacketTrace p)
    {
        var col = VerdictColor(p.Verdict);
        var ctrls = new List<Control>
        {
            Lbl(p.VerdictTitle, 13, true, col),
            Wrap(p.HasHeader ? $"{p.ProtoName} {p.Src}:{p.SrcPort} → {p.Dst}:{p.DstPort}   on {p.Iface}" + (p.Flags.Length > 0 ? $"   [{p.Flags}]" : "") : "No 'received a packet' line was found for this block (the export may have cut it off).", bold: true),
        };
        var meta = new List<string>();
        if (p.Time != null) meta.Add(p.Time);
        if (p.TraceId != null) meta.Add($"trace_id {p.TraceId}");
        if (p.SessionId != null) meta.Add($"session {p.SessionId} ({p.Direction})");
        if (meta.Count > 0) ctrls.Add(Wrap(string.Join("   ·   ", meta), gray: true));
        if (p.Explanation.Length > 0) ctrls.Add(Wrap(p.Explanation));
        if (p.Deciding?.Lines.FirstOrDefault() is { } dl)
        {
            var d = Wrap("Deciding line:  " + dl.Text, mono: true);
            d.BackColor = Color.FromArgb(255, 245, 170); d.Padding = new Padding(4);
            ctrls.Add(d);
        }
        if (p.NextCheck.Length > 0) ctrls.Add(Wrap("Suggested next check:  " + p.NextCheck, bold: true));
        foreach (var n in p.Notes) ctrls.Add(Wrap("Note: " + n, gray: true));
        if (p.DecidedByUnverifiedRule) ctrls.Add(Badge("unverified rule - the pattern behind this verdict has not been confirmed against a real sample"));
        Add(Card(col, ctrls, 8));
    }

    Control StepCard(Step s)
    {
        var ctrls = new List<Control>();
        var title = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        var tl = Lbl(s.Title, 9.5f, true, s.Card == "unknown" ? Color.DimGray : Color.Black);
        tl.Margin = new Padding(0, 0, 8, 0);
        title.Controls.Add(tl);
        if (s.IsDeciding) title.Controls.Add(Pill("◀ deciding line", Color.FromArgb(150, 110, 0), Color.FromArgb(255, 235, 130)));
        if (!s.Verified) title.Controls.Add(Pill("unverified rule", Color.White, Color.FromArgb(214, 120, 20)));
        else if (s.Versions.Length > 0) title.Controls.Add(Pill("FortiOS " + string.Join(", ", s.Versions), Color.DimGray, Color.FromArgb(235, 235, 235)));
        ctrls.Add(title);

        if (s.Card == "unknown") ctrls.Add(Wrap(s.Detail, mono: true, gray: true));
        else if (s.Card != "detail" && s.Detail.Length > 0) ctrls.Add(Wrap(s.Detail));
        if (s.Card == "policy-check" && s.Children.Count > 0) ctrls.Add(Wrap("Collapsed: uncheck 'collapse policy checks' in the toolbar to see each check as its own card.", gray: true));

        if (s.Lines.Count > 0 && s.Card != "unknown")
        {
            string closed = $"show raw line{(s.Lines.Count == 1 ? "" : "s")} ({s.Lines.Count})";
            var link = new LinkLabel { Text = "▸ " + closed, AutoSize = true, Margin = new Padding(0, 2, 0, 2) };
            TextBox? raw = null;
            link.LinkClicked += (_, _) =>
            {
                if (raw == null)
                {
                    raw = new TextBox
                    {
                        Multiline = true, ReadOnly = true, Font = F("Consolas", 9f), BackColor = Color.White, WordWrap = false,
                        ScrollBars = s.Lines.Count > 8 ? ScrollBars.Vertical : ScrollBars.None,
                        Text = string.Join(Environment.NewLine, s.Lines.Select(l => l.Raw.Replace("\n", " "))),
                        Height = Math.Min(s.Lines.Count, 8) * 17 + 8, Margin = new Padding(0, 2, 0, 0),
                    };
                    var host = link.Parent!;
                    host.Controls.Add(raw);
                    host.Controls.SetChildIndex(raw, host.Controls.GetChildIndex(link) + 1);
                    _wide.Add(raw);
                    raw.Disposed += (_, _) => _wide.Remove(raw);
                }
                else raw.Visible = !raw.Visible;
                link.Text = raw.Visible ? "▾ hide raw lines" : "▸ " + closed;
                LayoutCards();
            };
            ctrls.Add(link);
        }

        var stripe = CardColor(s.Card);
        var card = Card(stripe, ctrls, 5);
        if (s.IsDeciding) card.BackColor = Color.FromArgb(255, 250, 210);
        else if (s.Card == "detail") card.BackColor = Color.FromArgb(246, 246, 246);
        return card;
    }

    // ---------- small building blocks ----------

    void Add(Control c) { _cards.Add(c); _flow.Controls.Add(c); }

    Control Message(string text) => Card(Grey, new List<Control> { Wrap(text, gray: true) }, 5);

    Control Banner(string text, Color col)
    {
        var l = Lbl(text, 10, true, Color.White);
        l.BackColor = col; l.Padding = new Padding(8, 4, 8, 4); l.AutoSize = true; l.Margin = new Padding(0, 10, 0, 4); l.MinimumSize = new Size(_cardW, 0);
        _wraps.Add(l);
        return l;
    }

    Control Card(Color stripe, List<Control> content, int stripeWidth)
    {
        var card = new CardPanel(stripe, stripeWidth)
        {
            FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(stripeWidth + 10, 6, 8, 6), BackColor = Color.White, Margin = new Padding(0, 0, 0, 5),
        };
        card.SuspendLayout();
        foreach (var c in content) { if (c is Label) c.Margin = new Padding(0, 1, 0, 1); card.Controls.Add(c); }
        card.MinimumSize = new Size(_cardW, 0); card.MaximumSize = new Size(_cardW, 0);
        card.ResumeLayout(true);
        return card;
    }

    sealed class CardPanel : FlowLayoutPanel
    {
        readonly Color _stripe; readonly int _w;
        public CardPanel(Color stripe, int w) { _stripe = stripe; _w = w; DoubleBuffered = true; ResizeRedraw = true; }
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            using var b = new SolidBrush(_stripe);
            e.Graphics.FillRectangle(b, 0, 0, _w, Height);
        }
    }

    Label Lbl(string text, float size, bool bold, Color color)
    {
        var l = new Label
        {
            Text = text, AutoSize = true, ForeColor = color,
            Font = F("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular), Margin = new Padding(0, 1, 0, 1), MaximumSize = new Size(_inner, 0),
        };
        _wraps.Add(l);
        return l;
    }

    Label Wrap(string text, bool bold = false, bool mono = false, bool gray = false)
    {
        var l = new Label
        {
            Text = text, AutoSize = true,
            Font = mono ? F("Consolas", 9f) : F("Segoe UI", 9f, bold ? FontStyle.Bold : FontStyle.Regular),
            ForeColor = gray ? Color.DimGray : Color.Black, Margin = new Padding(0, 1, 0, 1), MaximumSize = new Size(_inner, 0),
        };
        _wraps.Add(l);
        return l;
    }

    static Label Pill(string text, Color fore, Color back) => new()
    {
        Text = text, AutoSize = true, ForeColor = fore, BackColor = back, Font = F("Segoe UI", 8f), Padding = new Padding(4, 1, 4, 1), Margin = new Padding(0, 1, 6, 0),
    };

    Control Badge(string text)
    {
        var l = Wrap(text, bold: true);
        l.BackColor = Color.FromArgb(255, 226, 190); l.Padding = new Padding(4); l.ForeColor = Color.FromArgb(120, 60, 0);
        return l;
    }

    void LayoutCards()
    {
        if (_flow.ClientSize.Width < 100) return;
        int w = _flow.ClientSize.Width - _flow.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth;
        if (w == _cardW && !_wide.Any()) return;
        _cardW = w; _inner = w - 30;
        _flow.SuspendLayout();
        foreach (var c in _cards)
        {
            c.MinimumSize = new Size(w, 0);
            c.MaximumSize = new Size(w, 0);
        }
        int inner = _inner;
        foreach (var l in _wraps) l.MaximumSize = new Size(inner, 0);
        foreach (var t in _wide) t.Width = inner;
        _flow.ResumeLayout(true);
    }
}
