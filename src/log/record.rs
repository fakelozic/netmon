//! Write capped pcapng files for a session's raw packets.
//! Session folders and text logs belong to `session`; decoded explanations
//! belong to `crate::explain`. Read `Session::start_recording` first.

use super::Recording;
use super::session::{Session, next_suffix, numbered, private_file, remember_problem};
use crate::capture::{LinkType, RawPacket};
use crate::explain::log as wording;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use std::borrow::Cow;
use std::io::{self, BufWriter, Write};

impl Session {
    /// Starts the next numbered pcapng file and returns the resulting state.
    /// `On` and `Failed` remain unchanged. `Off` or `Full` can start a new file;
    /// a cap below the 28-byte section header gives `Full` without creating one.
    /// Creation errors give `Failed` and are kept by `problem`.
    pub fn start_recording(&mut self) -> Recording {
        if matches!(self.recording, Recording::On | Recording::Failed) {
            return self.recording;
        }
        // The section header alone is 28 bytes. Do not create a file exceeding the cap.
        if self.options.max_capture_bytes < 28 {
            self.recording = Recording::Full;
            return self.recording;
        }
        let result = (|| {
            self.capture_suffix = next_suffix(self.capture_suffix)?;
            self.capture_name = numbered("capture", self.capture_suffix, ".pcapng");
            let file = private_file(&self.dir.join(&self.capture_name))?;
            let writer = PcapNgWriter::new(BufWriter::new(file)).map_err(pcap_error)?;
            self.capture = Some(writer);
            self.capture_bytes = 28;
            Ok(())
        })();
        match result {
            Ok(()) => self.recording = Recording::On,
            Err(error) => self.capture_failed(error),
        }
        self.recording
    }

    /// Flushes and closes the current capture, then becomes `Off` unless a failure
    /// has occurred. The next start chooses a fresh numbered file.
    pub fn stop_recording(&mut self) {
        self.finish_capture();
        if self.recording != Recording::Failed {
            self.recording = Recording::Off;
        }
    }

    /// Returns the raw recording state; it does not flush buffered bytes.
    pub fn recording(&self) -> Recording {
        self.recording
    }

    /// Records the captured bytes, original length, link type, and Unix timestamp.
    /// Does nothing unless `On`. A packet exceeding the cap is not written and
    /// gives `Full`; the caller must restart and retry that packet to retain it.
    /// Values outside pcapng's ranges give `Failed`, never a panic.
    pub fn record(&mut self, raw: &RawPacket) {
        if self.recording != Recording::On {
            return;
        }
        if let Err(error) = self.write_packet(raw) {
            self.capture_failed(error);
        }
    }

    fn write_packet(&mut self, raw: &RawPacket) -> io::Result<()> {
        // A link type tells a reader which header begins each captured packet.
        let link = match raw.link {
            LinkType::Ethernet => 1,
            LinkType::LinuxSll => 113,
            LinkType::LinuxSll2 => 276,
            LinkType::RawIp => 101,
            LinkType::Other(link) => link,
        };
        let packet_bytes = packet_size(raw, link)?;
        let Some(writer) = self.capture.as_mut() else {
            return Ok(());
        };
        // At most 65,536 interfaces: each u16 link type appears exactly once.
        let existing = writer
            .interfaces()
            .iter()
            .position(|i| u32::from(i.linktype) == link);
        // IDB: 12-byte frame + 8-byte body + 8-byte resolution option + 4-byte end option.
        let added = packet_bytes
            .checked_add(if existing.is_some() { 0 } else { 32 })
            .ok_or_else(invalid_packet)?;
        let next_size = self
            .capture_bytes
            .checked_add(added)
            .ok_or_else(invalid_packet)?;
        // Check the whole addition before either block is written, so the cap
        // never leaves a partial packet or a dangling interface for a rejected packet.
        if next_size > self.options.max_capture_bytes {
            self.finish_capture();
            if self.recording != Recording::Failed {
                self.recording = Recording::Full;
            }
            return Ok(());
        }
        let interface_id = match existing {
            Some(index) => index as u32,
            None => {
                let index = writer.interfaces().len() as u32;
                writer
                    .write_pcapng_block(InterfaceDescriptionBlock {
                        linktype: link.into(),
                        // Zero declares no snapshot limit; each packet keeps all captured bytes.
                        snaplen: 0,
                        // pcap-file 2.0 writes raw nanoseconds. Without if_tsresol=9,
                        // readers assume microseconds and show times 1,000 times too large.
                        options: vec![InterfaceDescriptionOption::IfTsResol(9)],
                    })
                    .map_err(pcap_error)?;
                index
            }
        };
        writer
            .write_pcapng_block(EnhancedPacketBlock {
                interface_id,
                timestamp: raw.ts,
                original_len: raw.orig_len,
                data: Cow::Borrowed(&raw.data),
                options: vec![],
            })
            .map_err(pcap_error)?;
        self.capture_bytes = next_size;
        Ok(())
    }

    /// Disables recording permanently, preserving the session's first output problem.
    pub(super) fn capture_failed(&mut self, error: io::Error) {
        remember_problem(&mut self.problem, &self.capture_name, &error);
        self.recording = Recording::Failed;
        if let Some(writer) = self.capture.take() {
            // into_parts discards pending bytes without BufWriter::Drop retrying
            // the failed write and possibly leaving another partial block.
            let _ = writer.into_inner().into_parts();
        }
    }

    fn finish_capture(&mut self) {
        if let Some(mut writer) = self.capture.take() {
            if let Err(error) = writer.get_mut().flush() {
                remember_problem(&mut self.problem, &self.capture_name, &error);
                self.recording = Recording::Failed;
            }
            // Even after a failed flush, dropping this buffer must not retry it.
            let _ = writer.into_inner().into_parts();
        }
    }
}

fn packet_size(raw: &RawPacket, link: u32) -> io::Result<u64> {
    let len = u64::try_from(raw.data.len()).map_err(|_| invalid_packet())?;
    // pcapng link types are u16; block sizes are u32; timestamps are u64 ticks.
    // Check these before pcap-file can narrow or overflow a caller's values.
    if link > u32::from(u16::MAX) || raw.ts.as_nanos() > u128::from(u64::MAX) {
        return Err(invalid_packet());
    }
    // Enhanced packets need 32 header/trailer bytes and data padded to four bytes.
    len.checked_add((4 - len % 4) % 4)
        .and_then(|n| n.checked_add(32))
        .filter(|&n| n <= u64::from(u32::MAX))
        .ok_or_else(invalid_packet)
}

fn invalid_packet() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, wording::INVALID_PACKET)
}

fn pcap_error(error: pcap_file::PcapError) -> io::Error {
    // Preserve an underlying I/O error's kind so callers can identify its cause.
    match error {
        pcap_file::PcapError::IoError(error) => error,
        other => io::Error::other(other),
    }
}
