//! Starts a complete browser session from command-line policies.
//! Argument parsing and interruption handling stay in `main`; packets stay in `api`.
//! Read `run` first for setup order and graceful capture/log shutdown.
//! A capture filter limits traffic before any display filter is applied.

use super::{
    Api, Server, Token,
    api::{Engine, Options as EngineOptions},
};
use crate::{
    explain::{ui, web as words},
    live::Source,
    log, pipeline,
    store::DEFAULT_MAX_PACKETS,
};
use std::{
    io::{self, IsTerminal, Write},
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Capture, browser and log policies for the `netmon web` command.
pub struct Options {
    /// Saved capture; None selects live capture. Cannot be combined with live options.
    pub file: Option<PathBuf>,
    /// Live interface or None for dumpcap's preferred ordinary interface.
    pub interface: Option<String>,
    /// Optional BPF capture filter for dumpcap.
    pub capture_filter: Option<String>,
    /// First candidate loopback port; default 7979 tries through 7999.
    pub port: u16,
    /// Suppress desktop browser launching.
    pub no_open: bool,
    /// Override the parent of the private session folder.
    pub log_dir: Option<PathBuf>,
    /// Start raw recording if logging is enabled.
    pub record: bool,
    /// Disable all log/session file creation, including recording.
    pub no_log: bool,
    /// Retained packets, 1 through 200,000; raw bytes also have a 256 MiB cap.
    pub max_packets: usize,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            file: None,
            interface: None,
            capture_filter: None,
            port: 7979,
            no_open: false,
            log_dir: None,
            record: false,
            no_log: false,
            max_packets: DEFAULT_MAX_PACKETS,
        }
    }
}
/// Runs until `stop` is set. Capture is stopped and logs are finished before return.
/// File mode stays available after EOF; only the session's data state becomes ended.
/// Startup failures return before browser opening; token never enters an HTTP path.
pub fn run(options: Options, stop: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    if options.file.is_some() && (options.interface.is_some() || options.capture_filter.is_some()) {
        return Err(ui::SCREEN_OPTIONS_ERROR.into());
    }
    if !(1..=DEFAULT_MAX_PACKETS).contains(&options.max_packets) {
        return Err(ui::MAX_PACKETS_ERROR.into());
    }
    if options.port == 0 {
        return Err(words::PORT_ERROR.into());
    }
    let token = Token::generate()?;
    let server = Server::bind(
        options.port,
        if options.port <= 7999 {
            7999
        } else {
            options.port
        },
    )?;
    let url = server.url(&token);
    let (source, label, live) = source(&options)?;
    // Release abort does not run Drop. Stop capture from the panic hook as well.
    let _panic_cleanup = PanicCleanup::start(source.child_handle());
    // Historical playback starts at its first packet so pipeline flushes and
    // inactivity checks never compare old traffic with the desktop wall clock.
    let started = if let Some(path) = &options.file {
        crate::capture::Reader::open(path)?
            .next()
            .transpose()?
            .map_or(Duration::ZERO, |raw| raw.ts)
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    };
    let mut logs = log::Options::default();
    if let Some(base) = options.log_dir {
        logs.base = base;
    }
    let mut engine = Engine::start(
        source,
        EngineOptions {
            live,
            source: label,
            started,
            max_packets: options.max_packets,
            pipeline: pipeline::Options {
                log: (!options.no_log).then_some(logs),
                record: options.record,
                proc_root: live.then(|| PathBuf::from("/proc")),
                alerts: Default::default(),
            },
        },
    )?;
    let api: Arc<dyn Api> = Arc::new(engine.api());
    let mut stdout = io::stdout().lock();
    let newline = if io::stdout().is_terminal() {
        "\r\n"
    } else {
        "\n"
    };
    write!(stdout, "{}{newline}", words::open_url(&url))?;
    if placeholder() {
        write!(stdout, "{}{newline}", words::PLACEHOLDER_NOTE)?;
    }
    stdout.flush()?;
    drop(stdout);
    if !options.no_open {
        open_browser(url);
    }
    server.serve(token, api, stop);
    engine.stop();
    Ok(())
}
fn source(options: &Options) -> Result<(Source, String, bool), Box<dyn std::error::Error>> {
    if let Some(path) = &options.file {
        return Ok((
            Source::file(path)?,
            path.to_string_lossy().into_owned(),
            false,
        ));
    }
    let interface = if let Some(name) = &options.interface {
        name.clone()
    } else {
        let interfaces = crate::live::list_interfaces()?;
        crate::live::default_interface(&interfaces)
            .ok_or(ui::NO_INTERFACE)?
            .name
            .clone()
    };
    Ok((
        Source::dumpcap(&interface, options.capture_filter.as_deref())?,
        interface,
        true,
    ))
}
fn placeholder() -> bool {
    // Detect compiled bytes, not the current filesystem: dist may be built after
    // this executable, or removed after a complete page was embedded.
    super::assets::FILES
        .iter()
        .find(|(name, _)| *name == "index.html")
        .is_none_or(|(_, bytes)| *bytes == words::UNBUILT_PAGE.as_bytes())
}
fn open_browser(url: String) {
    // A separate process group prevents a later terminal Ctrl-C from killing the
    // desktop's launcher. Reap it on a worker without delaying API service.
    let mut command = Command::new("xdg-open");
    crate::sys::unmask_child(&mut command);
    match command
        .arg(url)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            thread::spawn(move || {
                if child.wait().map_or(true, |status| !status.success()) {
                    eprintln!("{}", words::OPEN_FAILED);
                }
            });
        }
        Err(_) => eprintln!("{}", words::OPEN_FAILED),
    }
}

type PanicHook = Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync>;

struct PanicCleanup {
    previous: PanicHook,
}
impl PanicCleanup {
    fn start(child: Option<crate::live::ChildHandle>) -> Option<Self> {
        let child = child?;
        let previous: PanicHook = std::panic::take_hook().into();
        let prior = Arc::clone(&previous);
        std::panic::set_hook(Box::new(move |info| {
            crate::live::kill(&child);
            prior(info);
        }));
        Some(Self { previous })
    }
}
impl Drop for PanicCleanup {
    fn drop(&mut self) {
        // set_hook itself panics while unwinding; leave the installed cleanup in
        // that case. Successful command shutdown restores the prior hook.
        if !std::thread::panicking() {
            let previous = Arc::clone(&self.previous);
            std::panic::set_hook(Box::new(move |info| previous(info)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_hook_terminates_the_owned_capture_process_group() {
        let source = Source::command(
            "sh",
            &["-c", "cat tests/fixtures/loopback-first20.pcap; sleep 60"],
        )
        .unwrap();
        let _cleanup = PanicCleanup::start(source.child_handle());
        assert!(std::panic::catch_unwind(|| panic!("synthetic capture-owner panic")).is_err());
        let mut failed = false;
        for _ in 0..=20 {
            match source
                .receiver()
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
            {
                crate::live::Message::Packet(_) => {}
                crate::live::Message::Failed(_) => {
                    failed = true;
                    break;
                }
                crate::live::Message::Ended => break,
            }
        }
        assert!(
            failed,
            "the sleeping capture child must be killed before normal exit"
        );
    }
}
