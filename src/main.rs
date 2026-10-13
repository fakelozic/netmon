//! Dispatches command-line modes.
//! UI state belongs to ui; plain-text packet explanations belong to render.
//! Read run first for terminal checks before any live capture starts.
use lexopt::{Arg, ValueExt};
use netmon::{
    capture::{CaptureError, Reader},
    explain::ui as words,
    render::{Mode, Renderer},
    ui::ScreenOptions,
};
use std::{
    io::{self, IsTerminal, Write},
    path::Path,
};
fn run() -> Result<u8, Box<dyn std::error::Error>> {
    let mut parser = lexopt::Parser::from_env();
    let mut options = ScreenOptions::default();
    match parser.next()? {
        Some(Arg::Long("help") | Arg::Short('h')) => {
            print_text(words::HELP)?;
            return Ok(0);
        }
        Some(Arg::Long("version")) => {
            print_text(concat!("netmon ", env!("CARGO_PKG_VERSION"), "\n"))?;
            return Ok(0);
        }
        Some(Arg::Value(value)) => {
            match value.to_string_lossy().as_ref() {
                "glossary" => {
                    let term = match parser.next()? {
                        Some(Arg::Value(v)) => v.to_string_lossy().to_lowercase(),
                        None => String::new(),
                        Some(a) => return Err(a.unexpected().into()),
                    };
                    if let Some(a) = parser.next()? {
                        return Err(a.unexpected().into());
                    }
                    let mut out = io::stdout().lock();
                    for (name, definition) in netmon::explain::GLOSSARY {
                        if name.to_lowercase().contains(&term) {
                            writeln!(out, "{name}: {definition}")?;
                        }
                    }
                    out.flush()?;
                }
                "explain" => explain(&mut parser)?,
                "web" => web_command(&mut parser)?,
                "interfaces" => {
                    if let Some(a) = parser.next()? {
                        return Err(a.unexpected().into());
                    }
                    let mut out = io::stdout().lock();
                    for interface in netmon::live::list_interfaces()? {
                        writeln!(out, "{}  {}", interface.name, interface.description)?;
                    }
                    out.flush()?;
                }
                command => {
                    return Err(format!("{}: {command}", netmon::explain::COMMAND_ERROR).into());
                }
            }
            return Ok(0);
        }
        Some(arg) => {
            let flag = screen_flag(arg)?;
            screen_option(flag, &mut parser, &mut options)?;
        }
        None => {}
    }
    while let Some(arg) = parser.next()? {
        if matches!(arg, Arg::Long("help") | Arg::Short('h')) {
            print_text(words::HELP)?;
            return Ok(0);
        }
        let flag = screen_flag(arg)?;
        screen_option(flag, &mut parser, &mut options)?;
    }
    if options.file.is_some() && (options.interface.is_some() || options.capture_filter.is_some()) {
        return Err(words::SCREEN_OPTIONS_ERROR.into());
    }
    if !io::stdout().is_terminal() {
        eprintln!("netmon: {}", words::SCREEN_REQUIRES_TERMINAL);
        return Ok(2);
    }
    netmon::ui::run(options)?;
    Ok(0)
}
fn screen_flag(arg: Arg<'_>) -> Result<&'static str, Box<dyn std::error::Error>> {
    match arg {
        Arg::Short('i') | Arg::Long("interface") => Ok("interface"),
        Arg::Short('r') | Arg::Long("read") => Ok("read"),
        Arg::Short('f') | Arg::Long("capture-filter") => Ok("capture-filter"),
        Arg::Long("max-packets") => Ok("max-packets"),
        a => Err(a.unexpected().into()),
    }
}
fn screen_option(
    flag: &str,
    parser: &mut lexopt::Parser,
    options: &mut ScreenOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    match flag {
        "interface" => options.interface = Some(parser.value()?.string()?),
        "read" => options.file = Some(parser.value()?.into()),
        "capture-filter" => options.capture_filter = Some(parser.value()?.string()?),
        "max-packets" => {
            options.max_packets = parser.value()?.parse()?;
            if !(1..=netmon::store::DEFAULT_MAX_PACKETS).contains(&options.max_packets) {
                return Err(words::MAX_PACKETS_ERROR.into());
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
fn explain(parser: &mut lexopt::Parser) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = None;
    let mut mode = Mode::Default;
    while let Some(arg) = parser.next()? {
        let selected = match arg {
            Arg::Value(v) if file.is_none() => {
                file = Some(v);
                continue;
            }
            Arg::Long("tsv") => Mode::Tsv,
            Arg::Long("fields") => Mode::Fields,
            Arg::Long("packet") => {
                let n = parser.value()?.parse::<u64>()?;
                if n == 0 {
                    return Err(netmon::explain::PACKET_NUMBER_ERROR.into());
                }
                Mode::Packet(n)
            }
            Arg::Long("help") | Arg::Short('h') => {
                print_text(words::HELP)?;
                return Ok(());
            }
            a => return Err(a.unexpected().into()),
        };
        if mode != Mode::Default {
            return Err(netmon::explain::MODE_ERROR.into());
        }
        mode = selected;
    }
    let file = file.ok_or(netmon::explain::FILE_ERROR)?;
    let reader = if file == "-" {
        Reader::from_stream(Box::new(io::stdin()))?
    } else {
        Reader::open(Path::new(&file))?
    };
    let stdout = io::stdout();
    let mut renderer = Renderer::new(stdout.lock(), mode)?;
    for result in reader {
        match result {
            Ok(raw) => renderer.write_packet(&raw)?,
            Err(CaptureError::Truncated) => {
                renderer.flush()?;
                eprintln!("netmon: warning: {}", CaptureError::Truncated);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
    }
    renderer.flush()?;
    Ok(())
}
fn web_command(parser: &mut lexopt::Parser) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = netmon::web::command::Options::default();
    while let Some(arg) = parser.next()? {
        match arg {
            Arg::Short('i') | Arg::Long("interface") => {
                options.interface = Some(parser.value()?.string()?)
            }
            Arg::Short('r') | Arg::Long("read") => options.file = Some(parser.value()?.into()),
            Arg::Short('f') | Arg::Long("capture-filter") => {
                options.capture_filter = Some(parser.value()?.string()?)
            }
            Arg::Long("port") => {
                options.port = parser
                    .value()?
                    .parse()
                    .map_err(|_| netmon::explain::web::PORT_ERROR)?
            }
            Arg::Long("no-open") => options.no_open = true,
            Arg::Long("log-dir") => options.log_dir = Some(parser.value()?.into()),
            Arg::Long("record") => options.record = true,
            Arg::Long("no-log") => options.no_log = true,
            Arg::Long("max-packets") => {
                options.max_packets = parser
                    .value()?
                    .parse()
                    .map_err(|_| words::MAX_PACKETS_ERROR)?
            }
            Arg::Long("help") | Arg::Short('h') => {
                return Ok(print_text(netmon::explain::web::HELP)?);
            }
            arg => return Err(arg.unexpected().into()),
        }
    }
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let interrupt = netmon::sys::Interrupt::start(std::sync::Arc::clone(&stop))?;
    let result = netmon::web::command::run(options, stop);
    drop(interrupt);
    result
}
fn print_text(text: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(text.as_bytes())?;
    out.flush()
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => code.into(),
        Err(e)
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe) =>
        {
            0.into()
        }
        Err(e) => {
            eprintln!(
                "netmon: {}",
                netmon::text::sanitise(e.to_string().as_bytes())
            );
            1.into()
        }
    }
}
