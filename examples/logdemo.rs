//! Demonstrate session logging with packets from a saved synthetic capture.
//! Capture parsing belongs to `netmon::capture`; output policy belongs to
//! `netmon::log`. Read `run` first for the packet-to-session sequence.

use netmon::capture::Reader;
use netmon::decode::{Detail, decode};
use netmon::explain::{self, log as wording};
use netmon::log::{EventKind, Options, Recording, Session};
use netmon::text::sanitise;
use std::{error::Error, io, path::PathBuf, process::ExitCode};

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let capture = args.next().ok_or(wording::DEMO_USAGE)?;
    let base = args.next().ok_or(wording::DEMO_USAGE)?;
    if args.next().is_some() {
        return Err(wording::DEMO_USAGE.into());
    }
    let mut reader = Reader::open(&PathBuf::from(capture))?;
    // The first packet's Unix timestamp names the session, so replaying a saved
    // capture does not substitute the current time for its historical traffic.
    let first = reader.next().ok_or(wording::DEMO_EMPTY)??;
    let mut session = Session::create(
        Options {
            base: base.into(),
            log_packets: true,
            ..Options::default()
        },
        first.ts,
    )?;
    // Raw recording saves the packet bytes, while packet logs describe their meaning.
    if session.start_recording() != Recording::On {
        return Err(io::Error::other(session.problem().unwrap_or(wording::DEMO_RECORDING)).into());
    }
    let mut packets = 0u64;
    for raw in std::iter::once(Ok(first)).chain(reader) {
        let raw = raw?;
        packets = packets.saturating_add(1);
        log_packet(&mut session, &raw)?;
        if raw.number.is_multiple_of(25) {
            // Sparse notes make progress visible without duplicating every packet line.
            session.event(raw.ts, EventKind::Note, &wording::demo_note(raw.number));
        }
    }
    session.write_summary(&wording::demo_summary(packets));
    session.flush();
    if let Some(problem) = session.problem() {
        return Err(io::Error::other(problem).into());
    }
    println!("{}", sanitise(session.dir().to_string_lossy().as_bytes()));
    Ok(())
}

fn log_packet(
    session: &mut Session,
    raw: &netmon::capture::RawPacket,
) -> Result<(), Box<dyn Error>> {
    let decoded = decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
    session.packet(raw, &decoded, &explain::sentence(&decoded));
    session.record(raw);
    if session.recording() == Recording::Full {
        if session.start_recording() != Recording::On {
            return Err(
                io::Error::other(session.problem().unwrap_or(wording::DEMO_RECORDING)).into(),
            );
        }
        // Retry the packet that reached the limit, so every packet is recorded.
        session.record(raw);
        if session.recording() != Recording::On {
            return Err(
                io::Error::other(session.problem().unwrap_or(wording::DEMO_PACKET_LIMIT)).into(),
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", wording::demo_problem(&error));
            ExitCode::FAILURE
        }
    }
}
