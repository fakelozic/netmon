//! Prints alert observations from one saved capture.
//! Detection belongs to `netmon::alerts`; display wording belongs to `netmon::explain::alerts`.
//! Read `run` first for the capture-to-alert path.
//! Local addresses cannot be inferred reliably from packets, so inbound detection stays off here.

use netmon::{
    alerts::{Config, Engine},
    capture::Reader,
    decode::{Detail, decode},
    explain::alerts::{EXAMPLE_ERROR, EXAMPLE_USAGE},
    text,
};
use std::io::{self, Write};
use std::path::Path;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        return Err(EXAMPLE_USAGE.into());
    };
    if args.next().is_some() {
        return Err(EXAMPLE_USAGE.into());
    }
    let reader = Reader::open(Path::new(&path))?;
    let mut engine = Engine::new(Config::default());
    let mut output = io::BufWriter::new(io::stdout().lock());
    for raw in reader {
        let raw = raw?;
        let decoded = decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
        for alert in engine.observe(&raw, &decoded) {
            write!(output, "{alert}")?;
        }
    }
    output.flush()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "{EXAMPLE_ERROR}: {}",
            text::sanitise(error.to_string().as_bytes())
        );
        std::process::exit(1);
    }
}
