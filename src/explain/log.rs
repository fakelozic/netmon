//! Readable wording for session logs and their output problems.
//! File management belongs to `crate::log`; packet explanations belong to
//! `crate::explain::sentence`. Read `event` first for the timeline format.

use crate::log::{Clock, EventKind, markdown};
use crate::text::{number, sanitise};
use std::{fmt::Display, io};

/// Fallback file stem when filtering an export name leaves no usable characters.
pub(crate) const EXPORT_STEM: &str = "export";
/// Problem reported when a numbered output name would wrap its suffix.
pub(crate) const NAME_LIMIT: &str = "Cannot choose another file name: the suffix limit is reached.";
/// Problem reported when packet metadata cannot be represented in pcapng.
pub(crate) const INVALID_PACKET: &str =
    "Cannot record this packet: its size, link type or timestamp does not fit the capture format.";

/// Returns fixed Markdown for the event kind, emphasizing alerts.
pub(crate) fn kind(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Open => "Open",
        EventKind::Close => "Close",
        EventKind::Dns => "DNS",
        EventKind::Alert => "**Alert**",
        EventKind::Note => "Note",
    }
}

/// Formats a second-resolution session folder name; UTC adds a trailing `Z`.
pub(crate) fn folder(c: Clock, utc: bool) -> String {
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}{}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        if utc { "Z" } else { "" }
    )
}

/// Formats calendar fields as an ISO 8601 timestamp with milliseconds.
/// UTC adds `Z`; a local clock has no zone suffix and must be supplied by the caller.
pub(crate) fn time(c: Clock, utc: bool) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}{}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        c.millis,
        if utc { "Z" } else { "" }
    )
}

/// Formats the fixed title, start time and table header of a session timeline.
pub(crate) fn events_header(c: Clock, utc: bool) -> String {
    format!(
        "# netmon events\n\nStarted: {}\n\n| Time | Kind | What happened |\n| --- | --- | --- |\n",
        markdown::escape(&time(c, utc))
    )
}

/// Formats one Markdown table row, escaping every supplied value.
/// The caller must remove secrets before supplying the event description.
pub(crate) fn event(c: Clock, event_kind: EventKind, text: &str) -> String {
    format!(
        "| {} | {} | {} |\n",
        markdown::escape(&format!(
            "{:02}:{:02}:{:02}.{:03}",
            c.hour, c.minute, c.second, c.millis
        )),
        kind(event_kind),
        markdown::explanation(text)
    )
}

/// Describes an output error after sanitising both the filename and error text.
pub(crate) fn write_problem(file: &str, error: &io::Error) -> String {
    format!(
        "Cannot write {}: {}.",
        sanitise(file.as_bytes()),
        sanitise(error.to_string().as_bytes())
    )
}

/// Describes a rejected JSON line; `file` must be an internal, printable filename.
pub(crate) fn line_problem(file: &str) -> String {
    format!("Cannot write {file}: a JSON line contains a line break.")
}

/// Argument help for the saved-capture logging example.
pub const DEMO_USAGE: &str = "Usage: logdemo <CAPTURE> <BASE_DIR>";
/// Example failure when no first packet exists from which to name a session.
pub const DEMO_EMPTY: &str = "The capture contains no packets.";
/// Example failure when recording cannot start and no specific problem is kept.
pub const DEMO_RECORDING: &str = "The recording cannot start.";
/// Example failure when a packet still cannot fit after starting a fresh file.
pub const DEMO_PACKET_LIMIT: &str = "A packet does not fit within the recording size limit.";

/// Reports progress as a packet count, formatted with thousands separators.
pub fn demo_note(packets: u64) -> String {
    format!("Records {} packets so far.", number(packets))
}

/// Formats an example failure with sanitised error text suitable for a terminal.
pub fn demo_problem(error: &dyn Display) -> String {
    format!(
        "Logging example fails: {}",
        sanitise(error.to_string().as_bytes())
    )
}

/// Minimal report for the logging-library example; the pipeline writes the full report.
/// `packets` is the number of captured packets successfully passed to the session.
pub fn demo_summary(packets: u64) -> String {
    format!(
        "# netmon logging example\n\n- Packets: {}\n\nOpen events.md for the timeline and packets.jsonl for packet summaries.\n",
        markdown::escape(&number(packets))
    )
}
