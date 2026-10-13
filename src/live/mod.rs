//! Public capture inputs for live monitoring or saved-file playback.
//! source.rs owns workers and child cleanup; capture::Reader decodes file records.
//! Start with Source::file for playback or Source::dumpcap for a live interface.
//! A capture interface is a local network endpoint observed by dumpcap.
mod source;
use crate::{capture::RawPacket, explain::ui, text};
pub use source::Source;
pub(crate) use source::{ChildHandle, kill};
use std::{fmt, process::Command};
/// A capture interface name with an optional human-readable description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    /// Sanitized description without surrounding parentheses; empty when not supplied.
    pub description: String,
}
/// A sanitized capture startup or interface-discovery error.
#[derive(Debug)]
pub struct LiveError(String);
impl fmt::Display for LiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LiveError {}
fn failure(e: impl fmt::Display) -> LiveError {
    LiveError(text::sanitise(e.to_string().as_bytes()))
}
/// Parses numbered dumpcap -D lines, ignoring malformed rows.
/// Returns at most 4,096 sanitized interfaces; empty means no usable rows.
pub fn parse_interfaces(output: &str) -> Vec<Interface> {
    // Bound discovery metadata independently of packet storage.
    output
        .lines()
        .filter_map(|line| {
            let (number, rest) = line.trim().split_once('.')?;
            number.parse::<usize>().ok()?;
            let rest = rest.trim();
            let (name, description) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            if name.is_empty() {
                return None;
            }
            Some(Interface {
                name: text::sanitise(name.as_bytes()),
                description: text::sanitise(
                    description
                        .trim()
                        .trim_start_matches('(')
                        .trim_end_matches(')')
                        .as_bytes(),
                ),
            })
        })
        .take(4096)
        .collect()
}
/// Runs dumpcap -D and returns its sanitized interface list.
/// This blocks and belongs on a worker when called from a screen.
pub fn list_interfaces() -> Result<Vec<Interface>, LiveError> {
    let output = Command::new("dumpcap").arg("-D").output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            failure(ui::INSTALL_DUMPCAP)
        } else {
            failure(e)
        }
    })?;
    if !output.status.success() {
        return Err(failure(ui::capture_failed(&text::sanitise(&output.stderr))));
    }
    Ok(parse_interfaces(&String::from_utf8_lossy(&output.stdout)))
}
/// Selects the first ordinary interface, then lo as fallback.
/// Returns None when only excluded interfaces are listed.
pub fn default_interface(list: &[Interface]) -> Option<&Interface> {
    // Virtual, diagnostic, and loopback devices are not the preferred first view;
    // loopback remains usable when no ordinary network interface is present.
    list.iter()
        .find(|i| {
            i.name != "lo"
                && i.name != "any"
                && ![
                    "bluetooth",
                    "usbmon",
                    "nflog",
                    "nfqueue",
                    "docker",
                    "br-",
                    "veth",
                ]
                .iter()
                .any(|p| i.name.starts_with(p))
        })
        .or_else(|| list.iter().find(|i| i.name == "lo"))
}
/// An ordered worker event; exactly one Ended or Failed follows normal reading.
#[derive(Debug)]
pub enum Message {
    /// One captured packet in file order; timestamps are supplied by capture::Reader.
    Packet(RawPacket),
    /// The reader reached the end and any capture child exited successfully.
    Ended,
    /// A sanitized failure message; already-delivered packets remain usable.
    Failed(String),
}
