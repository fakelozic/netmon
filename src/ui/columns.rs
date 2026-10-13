//! Allocates packet-list columns while protecting the sentence.
//! packets.rs supplies values; layout.rs allocates the list's rows.
//! Read Columns::new for the ordered reductions on narrow terminals.
//! Ports distinguish applications that share an IP address, so To keeps its port.
use ratatui::layout::Rect;

/// Column rectangles in explain::ui::COLUMN_LABELS order; zero width hides a column.
pub(super) struct Columns {
    /// No, Time, From, To, Proto, Bytes, then sentence, matching COLUMN_LABELS.
    pub(super) cells: [Rect; 7],
    /// Relative time uses three decimal places when endpoint padding is exhausted.
    pub(super) compact_time: bool,
    /// One cell shares its width between both endpoint values.
    pub(super) combined: bool,
}

impl Columns {
    /// Keeps packet number, protocol and sentence visible, dropping metadata in order.
    pub(super) fn new(inner: Rect, number_width: u16, clock_time: bool) -> Self {
        let mut widths = [number_width, 13, 22, 22, 8, 7, 0];
        // Thirty-two sentence cells leave a useful phrase at medium widths.
        // Reduce bytes, endpoint padding and time precision before combining endpoints.
        let fits = |widths: &[u16; 7]| {
            widths.iter().copied().sum::<u16>().saturating_add(32) <= inner.width
        };
        if !fits(&widths) {
            widths[5] = 0;
        }
        if !fits(&widths) {
            widths[2] = 18;
            widths[3] = 18;
        }
        let compact_time = !clock_time && !fits(&widths);
        if compact_time {
            widths[1] = 10;
        }
        let combined = !fits(&widths);
        if combined {
            widths[2] = 0;
            widths[3] = 30;
        }
        // Very large packet numbers can consume twenty digits. Keep them intact
        // while giving the sentence at least four cells even at the minimum size.
        let fixed = widths[0] + widths[1] + widths[4];
        widths[3] = widths[3].min(inner.width.saturating_sub(fixed.saturating_add(4)));
        widths[6] = inner.width.saturating_sub(widths.iter().copied().sum());
        let mut x = inner.x;
        let cells = widths.map(|width| {
            let cell = Rect {
                x,
                width,
                height: 1,
                ..inner
            };
            x = x.saturating_add(width);
            cell
        });
        Self {
            cells,
            compact_time,
            combined,
        }
    }
}
