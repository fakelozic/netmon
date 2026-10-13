//! Replay a capture through the pipeline without a terminal screen.
//! Capture parsing stays in `netmon::capture`; processing stays in `Pipeline`.
//! Read `run` for file/standard-input handling and finalisation on input failure.

use netmon::capture::Reader;
use netmon::explain::pipeline as wording;
use netmon::pipeline::{Options, Pipeline};
use std::{error::Error, io, path::PathBuf, process::ExitCode, time::Duration};

struct Arguments {
    capture: PathBuf,
    options: Options,
    quiet: bool,
}

fn arguments() -> Result<Arguments, Box<dyn Error>> {
    let mut args = lexopt::Parser::from_env();
    let mut capture = None;
    let mut base = None;
    let mut record = false;
    let mut log_packets = false;
    let mut proc_root = None;
    let mut quiet = false;
    while let Some(arg) = args.next()? {
        match arg {
            lexopt::Arg::Value(value) if capture.is_none() => capture = Some(PathBuf::from(value)),
            lexopt::Arg::Long("log-dir") => base = Some(PathBuf::from(args.value()?)),
            lexopt::Arg::Long("record") => record = true,
            lexopt::Arg::Long("log-packets") => log_packets = true,
            lexopt::Arg::Long("proc") => proc_root = Some(PathBuf::from("/proc")),
            lexopt::Arg::Long("quiet") => quiet = true,
            _ => return Err(wording::HEADLESS_USAGE.into()),
        }
    }
    let log = if base.is_some() || record || log_packets {
        let mut log = netmon::log::Options {
            log_packets,
            ..netmon::log::Options::default()
        };
        if let Some(base) = base {
            log.base = base;
        }
        Some(log)
    } else {
        None
    };
    Ok(Arguments {
        capture: capture.ok_or(wording::HEADLESS_USAGE)?,
        quiet,
        options: Options {
            log,
            record,
            proc_root,
            alerts: netmon::alerts::Config::default(),
        },
    })
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = arguments()?;
    let mut reader = if args.capture.as_os_str() == "-" {
        Reader::from_stream(Box::new(io::stdin()))?
    } else {
        Reader::open(&args.capture)?
    };
    let first = reader.next().transpose()?;
    let started = first.as_ref().map(|raw| raw.ts).unwrap_or(Duration::ZERO);
    let mut pipeline = Pipeline::new(args.options, started);
    let mut packets = 0u64;
    let mut conversations = 0u64;
    let mut last_tick = started;
    let mut input_problem = None;
    for raw in first.map(Ok).into_iter().chain(reader) {
        let raw = match raw {
            Ok(raw) => raw,
            Err(error) => {
                input_problem = Some(error);
                break;
            }
        };
        let row = pipeline.push(&raw);
        // Every new flow has exactly one captured packet. Counting that evidence
        // stays correct when IDs skip occupied values after wrapping or are evicted.
        if row
            .flow
            .and_then(|id| pipeline.tracker().flow(id))
            .is_some_and(|flow| flow.packets[0].saturating_add(flow.packets[1]) == 1)
        {
            conversations = conversations.saturating_add(1);
        }
        packets = packets.saturating_add(1);
        if !args.quiet {
            println!(
                "{}",
                wording::headless_row(
                    row.number,
                    [row.ts, started],
                    [&row.src_label, &row.dst_label],
                    row.app.as_deref(),
                    &row.sentence
                )
            );
        }
        if raw.ts.saturating_sub(last_tick) >= Duration::from_secs(1) {
            last_tick = raw.ts;
            pipeline.tick(raw.ts);
        }
    }
    pipeline.finish();
    println!(
        "{}",
        wording::headless_summary(
            packets,
            conversations,
            pipeline.alert_count(),
            pipeline
                .session()
                .map(|session| session.dir().to_string_lossy())
                .as_deref()
        )
    );
    if let Some(error) = input_problem {
        return Err(error.into());
    }
    if let Some(problem) = pipeline.problem() {
        return Err(io::Error::other(problem).into());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", wording::headless_problem(&*error));
            ExitCode::FAILURE
        }
    }
}
