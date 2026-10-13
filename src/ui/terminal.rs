//! Adapts the packet screen to the real terminal.
//! App handles state; supervisor.rs handles capture workers and interface changes.
//! Read run first to see restoration on success, errors, and panics.
use super::{
    App,
    supervisor::{PanicChild, Request, Response, Session},
};
use crate::{live, store::DEFAULT_MAX_PACKETS};
use ratatui::crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture},
    execute,
};
use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
/// Source selection and the maximum retained packet count for the real screen.
/// Default selects live capture's preferred interface and retains 200,000 packets.
#[derive(Clone, Debug)]
pub struct ScreenOptions {
    /// Saved capture path, or None for live capture. Do not combine with live options.
    pub file: Option<PathBuf>,
    /// Live interface name, or None to use live::default_interface.
    pub interface: Option<String>,
    /// Optional dumpcap capture filter; this limits captured traffic before decoding.
    pub capture_filter: Option<String>,
    /// Packet count cap, from 1 to 200,000; packet bytes also have a 256 MiB cap.
    pub max_packets: usize,
}
impl Default for ScreenOptions {
    fn default() -> Self {
        Self {
            file: None,
            interface: None,
            capture_filter: None,
            max_packets: DEFAULT_MAX_PACKETS,
        }
    }
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableMouseCapture);
        ratatui::restore();
    }
}
fn panic_hook(child: PanicChild) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(io::stdout(), DisableMouseCapture);
        if let Ok(child) = child.lock()
            && let Some(child) = child.as_ref()
        {
            live::kill(child);
        }
        previous(info);
    }));
}
/// Opens the real terminal and runs until q or Ctrl-C.
/// Requires terminal stdout; restoration also occurs on IO errors and panics.
/// Capture failures remain visible in App so the user can choose another interface.
pub fn run(options: ScreenOptions) -> io::Result<()> {
    let panic_child = Arc::new(Mutex::new(None));
    // ratatui installs its restoring hook before entering the alternate screen.
    // Its hook invokes ours afterward, so panic=abort still stops the capture.
    panic_hook(Arc::clone(&panic_child));
    let restore = Restore;
    let mut terminal = ratatui::try_init()?;
    execute!(io::stdout(), EnableMouseCapture)?;
    let label = options
        .file
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| options.interface.clone())
        .unwrap_or_default();
    let mut app = App::new(&label, options.file.is_none(), options.max_packets);
    let session = Session::start(options, panic_child);
    let result = main_loop(&mut app, &mut terminal, &session);
    // Restore before any child joins: cleanup must not hold the user's terminal
    // in raw mode. Session then disconnects its channels before stopping workers.
    drop(restore);
    drop(terminal);
    drop(session);
    result
}
fn main_loop(
    app: &mut App,
    terminal: &mut ratatui::DefaultTerminal,
    session: &Session,
) -> io::Result<()> {
    let mut generation = 0;
    while !app.should_quit() {
        drain(app, session, generation);
        app.on_tick();
        terminal.draw(|frame| app.draw(frame))?;
        // OS time schedules frames only; rates and packet times use capture stamps.
        if event::poll(Duration::from_millis(40))? {
            app.on_event(event::read()?);
        }
        if app.take_interfaces_request() {
            let _ = session.requests.send(Request::Interfaces);
        }
        if let Some(interface) = app.take_interface_request() {
            generation = generation.saturating_add(1);
            app.restart(&interface);
            let _ = session
                .requests
                .send(Request::Restart(generation, interface));
        }
    }
    Ok(())
}
fn drain(app: &mut App, session: &Session, generation: u64) {
    let start = Instant::now();
    // Reserve most of each 50 ms frame for input and drawing under heavy traffic.
    while start.elapsed() < Duration::from_millis(8) {
        let Some(envelope) = session.receive() else {
            break;
        };
        // Restarted captures reuse packet numbers; generation keeps old queued
        // messages from being mistaken for packets from the chosen interface.
        if envelope.generation != generation {
            continue;
        }
        match envelope.response {
            Response::Capture(message) => app.on_message(message),
            Response::Interfaces(result) => app.set_interfaces(result),
            Response::Started(label) => app.source = crate::text::sanitise(label.as_bytes()),
        }
    }
}
