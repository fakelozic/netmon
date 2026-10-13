//! Construct inert Markdown from values supplied by packets or callers.
//! Secret removal stays with callers; file creation stays in `session`.
//! Read `escape` before assembling headings, lists or tables.

use crate::text::sanitise;

/// Sanitise a value and escape Markdown/HTML punctuation for inline text.
/// CR/LF become spaces; other nonprintable/non-ASCII bytes use `\xNN`.
/// URL scheme colons, www-prefix dots and at-signs are encoded too, preventing
/// automatic URL/email links while numeric addresses/timestamps stay readable.
/// Do not escape an already escaped value a second time.
pub fn escape(text: &str) -> String {
    let text = sanitise(text.replace(['\r', '\n'], " ").as_bytes());
    let mut result = String::new();
    let mut chars = text.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '&' => result.push_str("&amp;"),
            ':' if chars.peek().is_some_and(|(_, next)| *next == '/') => result.push_str("&#58;"),
            '.' if text
                .get(index.saturating_sub(3)..index)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("www")) =>
            {
                result.push_str("&#46;")
            }
            '@' => result.push_str("&#64;"),
            '\\' | '|' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '#' | '!' | '~' => {
                result.push('\\');
                result.push(ch);
            }
            _ => result.push(ch),
        }
    }
    result
}

/// Build one table row, including a final newline, from unescaped cell values.
/// Empty cells remain empty. Each cell is sanitised/escaped independently so
/// pipes or newlines in a value cannot add columns or rows.
pub fn table_row(cells: &[&str]) -> String {
    let mut row = String::from("|");
    for cell in cells {
        row.push(' ');
        row.push_str(&escape(cell));
        row.push_str(" |");
    }
    row.push('\n');
    row
}

/// Build a fenced `text` block with sanitised content and preserved line breaks.
/// The fence is longer than every content backtick run, so content cannot close
/// it and introduce HTML, links or images. Left angle brackets become `\x3C`
/// so the file also contains no raw HTML tags when inspected outside a viewer.
pub fn fenced_block(text: &str) -> String {
    let content = text.replace('\r', "");
    let content = content
        .split('\n')
        .map(|line| sanitise(line.as_bytes()).replace('<', "\\x3C"))
        .collect::<Vec<_>>()
        .join("\n");
    let longest = content
        .split(|ch| ch != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    // CommonMark requires at least three backticks; one extra prevents breakout.
    let fence = "`".repeat(longest.saturating_add(1).max(3));
    format!(
        "{fence}text\n{content}{}{fence}\n",
        if content.ends_with('\n') { "" } else { "\n" }
    )
}

/// Escapes an assembled explanation whose outside values are already sanitised.
/// Only the fixed microsecond unit is kept as Unicode; arbitrary Unicode remains escaped.
pub(crate) fn explanation(text: &str) -> String {
    text.split("µs").map(escape).collect::<Vec<_>>().join("µs")
}
