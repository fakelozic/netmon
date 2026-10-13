//! Manage private session output on disk.
//! Raw packet encoding lives in `record`; JSON escaping lives in `json`.
//! Readable wording lives in `crate::explain::log`. Read `Session::create` first.

use super::{EventKind, Json, Options, Recording};
use crate::capture::RawPacket;
use crate::decode::Decoded;
use crate::{explain::log as wording, text};
use pcap_file::pcapng::PcapNgWriter;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Returns `$XDG_STATE_HOME/netmon` when nonempty, otherwise
/// `$HOME/.local/state/netmon`. Missing or empty `HOME` falls back to `.`.
/// This reads environment configuration only; it creates no folders.
pub fn default_base() -> PathBuf {
    if let Some(base) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        PathBuf::from(base).join("netmon")
    } else {
        PathBuf::from(
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| ".".into()),
        )
        .join(".local/state/netmon")
    }
}

enum LogFile {
    Unused,
    Open(BufWriter<File>),
    Failed,
}

impl LogFile {
    fn write(&mut self, path: &Path, line: &str) -> io::Result<()> {
        // Retrying a partial write could duplicate bytes or join two JSON records.
        // Only this file is disabled; the session's other files can keep working.
        if matches!(self, Self::Failed) {
            return Ok(());
        }
        let result = (|| {
            if matches!(self, Self::Unused) {
                *self = Self::Open(BufWriter::new(private_file(path)?));
            }
            if let Self::Open(file) = self {
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.disable();
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        let result = match self {
            Self::Open(file) => file.flush(),
            _ => Ok(()),
        };
        if result.is_err() {
            self.disable();
        }
        result
    }

    fn disable(&mut self) {
        if let Self::Open(file) = std::mem::replace(self, Self::Failed) {
            // BufWriter::Drop would retry pending writes. A failed file must stay disabled.
            let _ = file.into_parts();
        }
    }
}

/// Exclusively creates a mode-0600 file; an existing path returns an I/O error.
pub(super) fn private_file(path: &Path) -> io::Result<File> {
    // Logs reveal the computer's peers, and raw packets may hold private data.
    // 0600 prevents other accounts from reading them; create_new forbids overwrites.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    // Set exact modes even when the caller uses an unusually restrictive umask.
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Keeps a sanitised error description only when no earlier output problem exists.
pub(super) fn remember_problem(problem: &mut Option<String>, file: &str, error: &io::Error) {
    // Keep the first cause: later failures must not replace the diagnostic that
    // explains why output first stopped. Failed writers themselves become no-ops.
    if problem.is_none() {
        *problem = Some(wording::write_problem(file, error));
    }
}

/// Advances the output suffix without wrapping; exhaustion returns an I/O error.
pub(super) fn next_suffix(suffix: u64) -> io::Result<u64> {
    // A suffix must never wrap and reuse a name already chosen by this session.
    suffix
        .checked_add(1)
        .ok_or_else(|| io::Error::other(wording::NAME_LIMIT))
}

/// Formats a name using a suffix from `next_suffix`; 1 leaves the name unsuffixed.
pub(super) fn numbered(stem: &str, suffix: u64, extension: &str) -> String {
    if suffix == 1 {
        format!("{stem}{extension}")
    } else {
        format!("{stem}-{suffix}{extension}")
    }
}

/// Owns one private output folder and its lazily opened buffered log files.
/// Callers supply secret-free text and complete JSON lines; `packet` logs summary
/// fields only, while `record` preserves raw bytes. Each failed writer stays
/// disabled without stopping other writers. `Drop` flushes remaining buffers.
pub struct Session {
    pub(super) options: Options,
    pub(super) dir: PathBuf,
    events: LogFile,
    started: Duration,
    flows: LogFile,
    alerts: LogFile,
    packets: LogFile,
    /// Open raw writer, present only while recording accepts packets.
    pub(super) capture: Option<PcapNgWriter<BufWriter<File>>>,
    /// Basename used to associate capture errors with their file.
    pub(super) capture_name: String,
    /// Last chosen file suffix; zero means no capture name has been chosen.
    pub(super) capture_suffix: u64,
    /// Encoded bytes in this capture, including headers and four-byte padding.
    pub(super) capture_bytes: u64,
    pub(super) recording: Recording,
    pub(super) problem: Option<String>,
}

impl Session {
    /// Creates a unique session folder using `started`, time since the Unix epoch,
    /// and `options.clock`. Existing names get `-2`, `-3`, and later suffixes.
    /// The folder is mode 0700; files stay absent until first use. Creation errors
    /// return to the caller because there is no session in which to keep them.
    pub fn create(options: Options, started: Duration) -> io::Result<Session> {
        // 0700 keeps peers and traffic private, including their file names.
        // Setting the session's exact mode also restores owner access under a strict umask.
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&options.base)?;
        let name = wording::folder((options.clock)(started), options.utc);
        let mut suffix = 1;
        let dir = loop {
            let dir = options.base.join(numbered(&name, suffix, ""));
            match DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    fs::set_permissions(&dir, Permissions::from_mode(0o700))?;
                    break dir;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    suffix = next_suffix(suffix)?
                }
                Err(error) => return Err(error),
            }
        };
        Ok(Self {
            options,
            dir,
            events: LogFile::Unused,
            started,
            flows: LogFile::Unused,
            alerts: LogFile::Unused,
            packets: LogFile::Unused,
            capture: None,
            capture_name: String::new(),
            capture_suffix: 0,
            capture_bytes: 0,
            recording: Recording::Off,
            problem: None,
        })
    }

    /// Returns the session folder, which exists after a successful `create`.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Appends one readable event at `ts`, time since the Unix epoch.
    /// Controls are escaped; line breaks become spaces. The caller removes secrets.
    /// Write failures are kept by `problem` and disable only `events.md`.
    pub fn event(&mut self, ts: Duration, kind: EventKind, text: &str) {
        let result = (|| {
            if matches!(self.events, LogFile::Unused) {
                let header =
                    wording::events_header((self.options.clock)(self.started), self.options.utc);
                self.events
                    .write(&self.dir.join("events.md"), header.trim_end_matches('\n'))?;
            }
            let row = wording::event((self.options.clock)(ts), kind, text);
            self.events
                .write(&self.dir.join("events.md"), row.trim_end_matches('\n'))
        })();
        if let Err(error) = result {
            remember_problem(&mut self.problem, "events.md", &error);
        }
    }

    /// Appends a complete, secret-free JSON record to `flows.jsonl`.
    /// The caller supplies valid JSON; raw CR or LF rejects the line and sets
    /// `problem` without disabling future valid lines. I/O failure disables this file.
    pub fn flow_line(&mut self, json: &str) {
        self.json_line(json, false);
    }
    /// Appends a complete, secret-free JSON record to `alerts.jsonl`.
    /// The same validation and isolated I/O failure rules as `flow_line` apply.
    pub fn alert_line(&mut self, json: &str) {
        self.json_line(json, true);
    }

    fn json_line(&mut self, json: &str, alert: bool) {
        let (file, name) = if alert {
            (&mut self.alerts, "alerts.jsonl")
        } else {
            (&mut self.flows, "flows.jsonl")
        };
        // JSONL uses line breaks as record boundaries. Accepting a raw CR or LF
        // would let one supplied record insert another or corrupt that boundary.
        if json.contains(['\n', '\r']) {
            if self.problem.is_none() {
                self.problem = Some(wording::line_problem(name));
            }
            return;
        }
        if let Err(error) = file.write(&self.dir.join(name), json) {
            remember_problem(&mut self.problem, name, &error);
        }
    }

    /// Appends a packet summary when `Options::log_packets` is true.
    /// `d` must describe `raw`, and `sentence` must already exclude secrets.
    /// Packet time is since the Unix epoch; absent addresses and ports are omitted.
    /// Controls in the sentence are escaped. Raw payload is never included.
    pub fn packet(&mut self, raw: &RawPacket, d: &Decoded, sentence: &str) {
        if !self.options.log_packets {
            return;
        }
        let summary = &d.summary;
        let src = summary.src.as_ref().map(text::address);
        let dst = summary.dst.as_ref().map(text::address);
        // Ports identify the sending and receiving applications within their hosts.
        // Readable logs retain these summary fields, never arbitrary payload bytes.
        let line = Json::object()
            .num("no", raw.number)
            .str(
                "time",
                &wording::time((self.options.clock)(raw.ts), self.options.utc),
            )
            .opt_str("src", src.as_deref())
            .opt_str("dst", dst.as_deref())
            .opt_num("src_port", summary.src_port.map(u64::from))
            .opt_num("dst_port", summary.dst_port.map(u64::from))
            .str("proto", summary.proto.name())
            .num("bytes", u64::from(summary.wire_len))
            .str("info", &text::sanitise(sentence.as_bytes()))
            .finish();
        if let Err(error) = self.packets.write(&self.dir.join("packets.jsonl"), &line) {
            remember_problem(&mut self.problem, "packets.jsonl", &error);
        }
    }

    /// Flushes all open writers, leaving unused files absent.
    /// A failure disables that writer and is kept by `problem`; other writers
    /// still flush. A failed capture moves to `Recording::Failed`.
    pub fn flush(&mut self) {
        for (file, name) in [
            (&mut self.events, "events.md"),
            (&mut self.flows, "flows.jsonl"),
            (&mut self.alerts, "alerts.jsonl"),
            (&mut self.packets, "packets.jsonl"),
        ] {
            if let Err(error) = file.flush() {
                remember_problem(&mut self.problem, name, &error);
            }
        }
        if let Some(writer) = self.capture.as_mut()
            && let Err(error) = writer.get_mut().flush()
        {
            self.capture_failed(error);
        }
    }

    /// Returns the first output problem as sanitised readable text, or `None`
    /// when no problem has been observed. Reading it does not clear it.
    /// Buffered I/O errors may first appear during `flush`.
    pub fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.flush();
    }
}
