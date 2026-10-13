//! Owns the lifecycle of one capture worker.
//! Interface discovery belongs to mod.rs; capture::Reader handles packet records.
//! Read Source::stop first for cancellation when a pipe or channel is blocked.
//! A packet record is one observed network message, not a complete conversation.
use super::{LiveError, Message, failure};
use crate::{capture::Reader, explain::ui, text};
use std::{
    io::Read,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
/// Shared child ownership lets a session's panic hook stop its own capture only.
pub(crate) type ChildHandle = Arc<Mutex<Option<Child>>>;
/// Owns a capture receiver, worker, and optional child.
/// Drop stops and joins its workers; callers should drain receiver during normal use.
pub struct Source {
    receiver: Receiver<Message>,
    cancel: Arc<AtomicBool>,
    child: Option<ChildHandle>,
    worker: Option<JoinHandle<()>>,
}
fn send(sender: &SyncSender<Message>, cancel: &AtomicBool, mut message: Message) -> bool {
    // Blocking send cannot be interrupted by stop on a full channel. A short
    // park retries capacity while allowing cancellation without dropping packets.
    loop {
        if cancel.load(Ordering::Acquire) {
            return false;
        }
        match sender.try_send(message) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(m)) => {
                message = m;
                thread::park_timeout(Duration::from_millis(5));
            }
        }
    }
}
fn read_packets(
    reader: Result<Reader, crate::capture::CaptureError>,
    sender: &SyncSender<Message>,
    cancel: &AtomicBool,
) -> Option<String> {
    let reader = match reader {
        Ok(r) => r,
        Err(e) => return Some(text::sanitise(e.to_string().as_bytes())),
    };
    for packet in reader {
        if cancel.load(Ordering::Acquire) {
            return None;
        }
        match packet {
            Ok(packet) => {
                if !send(sender, cancel, Message::Packet(packet)) {
                    return None;
                }
            }
            Err(e) => return Some(text::sanitise(e.to_string().as_bytes())),
        }
    }
    None
}
/// Stops the session-owned process group, including inherited pipe writers.
pub(crate) fn kill(child: &ChildHandle) {
    if let Ok(mut child) = child.lock()
        && let Some(child) = child.as_mut()
    {
        // Each capture child is the leader of its own process group. Kill descendants
        // too: a shell's child can otherwise keep stdout open after the shell dies.
        // /bin/kill avoids another unsafe libc call and does not depend on PATH.
        let group = format!("-{}", child.id());
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &group])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = child.kill();
    }
}
fn read_errors(stderr: std::process::ChildStderr) -> String {
    let mut stderr = stderr;
    let mut kept = Vec::new();
    let mut chunk = [0; 4096];
    while let Ok(n) = stderr.read(&mut chunk) {
        if n == 0 {
            break;
        }
        // Continue draining after the 64 KiB diagnostic cap: stopping reads
        // would block a noisy child before it can deliver more packets.
        let room = 65_536usize.saturating_sub(kept.len());
        kept.extend_from_slice(chunk.get(..n.min(room)).unwrap_or_default());
    }
    text::sanitise(&kept)
}

fn command_worker(
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
    worker_child: ChildHandle,
    sender: SyncSender<Message>,
    worker_cancel: Arc<AtomicBool>,
) {
    let errors = thread::Builder::new()
        .name("netmon-capture-errors".into())
        .spawn(move || read_errors(stderr));
    let errors = match errors {
        Ok(errors) => errors,
        Err(error) => {
            // Worker creation can fail under a process cap. The child must not
            // survive the failed startup or keep its stdout pipe open forever.
            kill(&worker_child);
            if let Ok(mut child) = worker_child.lock()
                && let Some(mut child) = child.take()
            {
                let _ = child.wait();
            }
            send(
                &sender,
                &worker_cancel,
                Message::Failed(text::sanitise(error.to_string().as_bytes())),
            );
            return;
        }
    };
    let read_error = read_packets(
        Reader::from_stream(Box::new(stdout)),
        &sender,
        &worker_cancel,
    );
    if read_error.is_some() {
        kill(&worker_child);
    }
    let status = loop {
        if worker_cancel.load(Ordering::Acquire) {
            break None;
        }
        match worker_child.lock().ok().and_then(|mut c| {
            let status = c.as_mut()?.try_wait().ok()?;
            // A reaped pid can be reused by the OS. Forget the child immediately
            // so a later Drop or panic never signals an unrelated process group.
            if status.is_some() {
                *c = None;
            }
            Some(status)
        }) {
            Some(Some(status)) => break Some(status),
            Some(None) => thread::park_timeout(Duration::from_millis(5)),
            None => break None,
        }
    };
    let stderr = errors.join().unwrap_or_default();
    if worker_cancel.load(Ordering::Acquire) {
        return;
    }
    let message = if status.is_some_and(|s| !s.success()) {
        Message::Failed(ui::capture_failed(&stderr))
    } else if let Some(error) = read_error {
        Message::Failed(error)
    } else {
        Message::Ended
    };
    send(&sender, &worker_cancel, message);
}
impl Source {
    /// Starts dumpcap for an interface, optionally applying a capture filter.
    /// The filter limits capture itself, independently of the display filter.
    pub fn dumpcap(interface: &str, capture_filter: Option<&str>) -> Result<Source, LiveError> {
        let mut args = vec!["-i", interface, "-w", "-", "-q"];
        if let Some(filter) = capture_filter {
            args.extend(["-f", filter]);
        }
        Self::command("dumpcap", &args)
    }
    /// Starts a process whose stdout is pcap or pcapng.
    /// Packets use a bounded 8,192-entry channel; stderr is drained with a 64 KiB retained cap.
    pub fn command(program: &str, args: &[&str]) -> Result<Source, LiveError> {
        let mut command = Command::new(program);
        crate::sys::unmask_child(&mut command);
        let mut child = command
            .args(args)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    failure(ui::INSTALL_DUMPCAP)
                } else {
                    failure(e)
                }
            })?;
        let stdout = child.stdout.take().ok_or_else(|| failure(ui::PIPE_ERROR))?;
        let stderr = child.stderr.take().ok_or_else(|| failure(ui::PIPE_ERROR))?;
        let child = Arc::new(Mutex::new(Some(child)));
        let worker_child = Arc::clone(&child);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        // This prescribed capacity buffers a burst without unbounded traffic growth.
        let (sender, receiver) = mpsc::sync_channel(8192);
        let worker = thread::Builder::new()
            .name("netmon-capture".into())
            .spawn(move || command_worker(stdout, stderr, worker_child, sender, worker_cancel));
        let worker = match worker {
            Ok(worker) => worker,
            Err(error) => {
                kill(&child);
                if let Ok(mut child) = child.lock()
                    && let Some(mut child) = child.take()
                {
                    let _ = child.wait();
                }
                return Err(failure(error));
            }
        };
        Ok(Self {
            receiver,
            cancel,
            child: Some(child),
            worker: Some(worker),
        })
    }
    /// Starts saved-file reading on a worker without blocking the caller.
    /// Open and parse failures arrive as Message::Failed.
    pub fn file(path: &Path) -> Result<Source, LiveError> {
        let path = path.to_owned();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (sender, receiver) = mpsc::sync_channel(8192);
        let worker = thread::Builder::new()
            .name("netmon-file".into())
            .spawn(move || {
                let error = read_packets(Reader::open(&path), &sender, &worker_cancel);
                let message = error.map_or(Message::Ended, Message::Failed);
                send(&sender, &worker_cancel, message);
            })
            .map_err(failure)?;
        Ok(Self {
            receiver,
            cancel,
            child: None,
            worker: Some(worker),
        })
    }
    /// Returns the child cleanup handle, or None for saved-file reading.
    pub(crate) fn child_handle(&self) -> Option<ChildHandle> {
        self.child.clone()
    }
    /// Borrows the ordered packet channel; use nonblocking receives on the UI thread.
    pub fn receiver(&self) -> &Receiver<Message> {
        &self.receiver
    }
    /// Cancels backpressure, kills the process group, and joins workers.
    /// Safe to call repeatedly; this blocks and must run outside App.
    pub fn stop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(child) = &self.child {
            kill(child);
        }
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
        if let Some(child) = self.child.take()
            && let Ok(mut child) = child.lock()
            && let Some(mut child) = child.take()
        {
            let _ = child.wait();
        }
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.stop();
    }
}
