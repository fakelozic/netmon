//! Public entry point for one session's private log files.
//! JSON encoding lives in `json`, calendar conversion in `clock`,
//! file management in `session`, and raw packet recording in `record`.
//! Start with `Session::create` and `Options` to choose the output policy.

mod clock;
mod json;
pub mod markdown;
mod markdown_files;
mod record;
mod session;

pub use clock::{Clock, ClockFn, utc_clock};
pub use json::{Json, JsonValue};
pub use session::{Session, default_base};

use std::path::PathBuf;

/// Output policy for a session. Defaults use UTC, omit per-packet logs, and cap
/// each raw capture at 200,000,000 bytes, including pcapng headers and padding.
pub struct Options {
    /// Parent folder in which `Session::create` makes a private session folder.
    pub base: PathBuf,
    /// Converts packet time since the Unix epoch into calendar fields.
    pub clock: ClockFn,
    /// Must be true when `clock` returns UTC; adds `Z` to folder and log times.
    pub utc: bool,
    /// Enables `packets.jsonl`; false leaves that file absent.
    pub log_packets: bool,
    /// Maximum bytes per raw capture file. Below 28, no file can be started.
    pub max_capture_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            base: default_base(),
            clock: utc_clock,
            utc: true,
            log_packets: false,
            // Use a decimal 200 MB cap to bound disk use by each raw recording.
            max_capture_bytes: 200_000_000,
        }
    }
}

/// Category written in the Kind column of `events.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A connection opens; the caller decides which packets establish it.
    Open,
    /// A connection ends; the caller supplies its reason and totals.
    Close,
    /// A DNS lookup translates a name into an address or reports a failure.
    Dns,
    /// An alert rule reports an observation worth inspecting.
    Alert,
    /// A session observation outside the other categories.
    Note,
}

/// Raw recording state. Only `On` accepts packets; text logs work in every state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recording {
    /// Initial state, or reached by `stop_recording` after a successful flush.
    /// `start_recording` opens the next numbered capture file.
    Off,
    /// A capture is open. Reached by a successful `start_recording`; a packet
    /// exceeding the cap ends it as `Full`, and a write error ends it as `Failed`.
    On,
    /// The next packet would exceed the cap, or the cap cannot fit a header.
    /// The rejected packet is not saved. Restarting opens the next file if it fits.
    Full,
    /// Creating, encoding, writing, or flushing a capture failed. Terminal for
    /// this session: recording calls cannot restart it; the first problem remains available.
    Failed,
}
