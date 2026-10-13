//! Wraps display wording into a countable list of terminal lines.
//! Wording belongs to explain::ui; this module only decides where lines break.
//! Read wrapped_lines first when changing scroll limits.
// Count wrapped lines ourselves: ratatui's rendered-line-info feature is not
// enabled in this project's fixed dependency set. All external text is ASCII
// escaped, and the explanation vocabulary uses single-column characters.
/// Wraps single-column display wording; returns owned lines for exact scroll limits.
pub(super) fn wrapped_lines(
    lines: Vec<ratatui::text::Line<'_>>,
    width: u16,
) -> Vec<ratatui::text::Line<'static>> {
    let width = usize::from(width).max(1);
    let mut output = Vec::new();
    for line in lines {
        let style = line.style;
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        let mut rest = text.as_str();
        while rest.chars().count() > width {
            let end = rest
                .char_indices()
                .nth(width)
                .map_or(rest.len(), |(i, _)| i);
            let prefix = rest.get(..end).unwrap_or_default();
            let split = prefix
                .rfind(char::is_whitespace)
                .filter(|i| *i > 0)
                .unwrap_or(end);
            output.push(ratatui::text::Line::styled(
                rest.get(..split).unwrap_or_default().to_owned(),
                style,
            ));
            rest = rest.get(split..).unwrap_or_default().trim_start();
        }
        output.push(ratatui::text::Line::styled(rest.to_owned(), style));
    }
    output
}
