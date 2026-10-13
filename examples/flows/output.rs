//! Output assembly shared by the capture example and its golden checks.
//! Sentence wording stays in `explain::flows`; standalone columns stay in `render`.
//! Read `line` for one row, then `ladder` for one conversation's complete output.
use netmon::capture::RawPacket;
use netmon::decode::Decoded;
use netmon::explain;
use netmon::flow::{Flow, Observation, Tracker};
use netmon::names::Names;
use netmon::render::{self, Mode};
use std::time::Duration;

/// Keep the standalone listing columns and replace only the final sentence.
/// `first` is the capture's first epoch timestamp; the returned row ends in a newline.
pub(super) fn line(
    raw: &RawPacket,
    d: &Decoded,
    first: Duration,
    obs: &Observation,
    tracker: &Tracker,
) -> String {
    let row = render::packet(raw, d, first, Mode::Default);
    let suffix = format!("{}\n", explain::sentence(d));
    // A suffix replacement preserves the engine's columns without duplicating layout code.
    let prefix = row.strip_suffix(&suffix).unwrap_or(&row);
    format!(
        "{prefix}{}\n",
        explain::flows::sentence(
            d,
            obs,
            obs.flow.and_then(|id| tracker.flow(id)),
            tracker.names()
        )
    )
}

/// Format one conversation's title, status, and ladder, with a leading blank line.
pub(super) fn ladder(flow: &Flow, names: &Names) -> String {
    format!(
        "\n{}\n{}\n{}",
        explain::flows::flow_title(flow, names),
        explain::flows::flow_status(flow),
        explain::flows::story(flow, names)
    )
}
