//! Owns capture switching outside the screen thread.
//! live::Source owns each worker; terminal.rs owns drawing and keyboard IO.
//! Read Session::start, then Worker::step to see backpressure and shutdown.
use super::terminal::ScreenOptions;
use crate::{
    explain::ui as words,
    live::{self, ChildHandle, Message, Source},
};
use std::{
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
/// A session-owned panic handle, never a process-wide source registry.
pub(super) type PanicChild = Arc<Mutex<Option<ChildHandle>>>;
/// Commands from the terminal thread to its capture supervisor.
pub(super) enum Request {
    Interfaces,
    /// Generation number followed by the interface to start after stopping the old source.
    Restart(u64, String),
    Quit,
}
/// Worker updates; labels and failures are sanitized before display.
pub(super) enum Response {
    Capture(Message),
    Interfaces(Result<Vec<live::Interface>, String>),
    Started(String),
}
/// Tags a worker update so queued messages from an old capture can be ignored.
pub(super) struct Envelope {
    /// Monotonic capture generation, starting at zero within a session.
    pub generation: u64,
    pub response: Response,
}
/// Owns the supervisor thread and disconnects its output before joining it.
pub(super) struct Session {
    pub requests: Sender<Request>,
    receiver: Option<Receiver<Envelope>>,
    worker: Option<JoinHandle<()>>,
}
impl Session {
    /// Starts blocking source setup away from App, sharing only a cleanup handle.
    pub(super) fn start(options: ScreenOptions, panic_child: PanicChild) -> Self {
        let (requests, request_receiver) = mpsc::channel();
        // Match Source's capacity so this forwarding stage remains bounded.
        let (responses, receiver) = mpsc::sync_channel(8192);
        let worker = thread::spawn(move || {
            let mut worker = Worker {
                options,
                generation: 0,
                active: None,
                pending: None,
                responses,
                requests: request_receiver,
                panic_child,
            };
            worker.open();
            while worker.step() {}
        });
        Self {
            requests,
            receiver: Some(receiver),
            worker: Some(worker),
        }
    }
    /// Takes one queued update without blocking; None means no update is ready.
    pub(super) fn receive(&self) -> Option<Envelope> {
        self.receiver.as_ref()?.try_recv().ok()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        // Disconnect first: an interface-list response may be waiting behind a
        // full packet channel. It must wake before the supervisor can join.
        drop(self.receiver.take());
        let _ = self.requests.send(Request::Quit);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
    }
}
struct Worker {
    options: ScreenOptions,
    generation: u64,
    active: Option<Source>,
    pending: Option<Envelope>,
    responses: SyncSender<Envelope>,
    requests: Receiver<Request>,
    panic_child: PanicChild,
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Ok(mut child) = self.panic_child.lock() {
            *child = None;
        }
        drop(self.active.take());
    }
}
impl Worker {
    fn open(&mut self) {
        match source(&self.options) {
            Ok((capture, label)) => {
                if let Ok(mut child) = self.panic_child.lock() {
                    *child = capture.child_handle();
                }
                self.active = Some(capture);
                self.pending = Some(self.envelope(Response::Started(label)));
            }
            Err(error) => {
                self.pending = Some(self.envelope(Response::Capture(Message::Failed(error))))
            }
        }
    }
    fn envelope(&self, response: Response) -> Envelope {
        Envelope {
            generation: self.generation,
            response,
        }
    }
    fn step(&mut self) -> bool {
        // Check requests even while output is full; otherwise quitting or picking
        // a different interface could deadlock behind backpressure.
        match self.requests.try_recv() {
            Ok(Request::Quit) | Err(mpsc::TryRecvError::Disconnected) => return false,
            Ok(Request::Interfaces) => {
                let result = live::list_interfaces().map_err(|e| e.to_string());
                if self
                    .responses
                    .send(self.envelope(Response::Interfaces(result)))
                    .is_err()
                {
                    return false;
                }
            }
            Ok(Request::Restart(generation, interface)) => {
                drop(self.active.take());
                if let Ok(mut child) = self.panic_child.lock() {
                    *child = None;
                }
                self.generation = generation;
                self.options.interface = Some(interface);
                self.open();
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let mut backpressured = false;
        if let Some(message) = self.pending.take() {
            match self.responses.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(m)) => {
                    self.pending = Some(m);
                    backpressured = true;
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        if self.pending.is_none()
            && let Some(capture) = &self.active
            && let Ok(message) = capture.receiver().try_recv()
        {
            self.pending = Some(self.envelope(Response::Capture(message)));
        }
        // Waiting for channel capacity is OS scheduling, not a traffic timeout.
        if self.pending.is_none() || backpressured {
            thread::park_timeout(Duration::from_millis(2));
        }
        true
    }
}
fn source(options: &ScreenOptions) -> Result<(Source, String), String> {
    if let Some(path) = &options.file {
        return Source::file(path)
            .map(|s| (s, path.to_string_lossy().into_owned()))
            .map_err(|e| e.to_string());
    }
    let interface = match &options.interface {
        Some(i) => i.clone(),
        None => {
            let interfaces = live::list_interfaces().map_err(|e| e.to_string())?;
            live::default_interface(&interfaces)
                .ok_or(words::NO_INTERFACE)?
                .name
                .clone()
        }
    };
    Source::dumpcap(&interface, options.capture_filter.as_deref())
        .map(|s| (s, interface))
        .map_err(|e| e.to_string())
}
