//! Saved-capture demonstration of contextual packet explanations.
//! Tracker behavior stays in `flow`; all wording stays in `explain::flows`.
//! Read `run` for the ordered packet observations and optional ladders.
use netmon::capture::Reader;
use netmon::decode::{self, Detail};
use netmon::explain;
use netmon::flow::Tracker;
use netmon::render::{self, Mode};
use netmon::text;
use std::io::{self, Write};
use std::path::Path;

#[path = "flows/output.rs"]
mod output;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = None;
    let mut stories = false;
    for arg in std::env::args_os().skip(1) {
        if arg == "--stories" {
            stories = true;
        } else if file.is_none() {
            file = Some(arg);
        } else {
            return Err(explain::flows::EXAMPLE_USAGE.into());
        }
    }
    let file = file.ok_or(explain::flows::EXAMPLE_USAGE)?;
    let reader = Reader::open(Path::new(&file))?;
    let mut tracker = Tracker::new();
    let mut first = None;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output.write_all(render::header(Mode::Default).as_bytes())?;
    for raw in reader {
        let raw = raw?;
        let d = decode::decode(raw.link, &raw.data, raw.orig_len, Detail::Summary);
        let obs = tracker.observe(&raw, &d);
        output.write_all(
            output::line(&raw, &d, *first.get_or_insert(raw.ts), &obs, &tracker).as_bytes(),
        )?;
    }
    if stories {
        for flow in tracker.flows() {
            output.write_all(output::ladder(flow, tracker.names()).as_bytes())?;
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", text::sanitise(error.to_string().as_bytes()));
        std::process::exit(1);
    }
}
