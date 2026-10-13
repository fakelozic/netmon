//! Owns the engine thread and its bounded request/reply channels.
//! State transitions stay in `state`; HTTP sockets stay in `web::server`.
//! Read `Engine::start` for capture ownership and `WebApi::handle` for deadlines.
//! Capture keeps running when a browser stops reading its replies.

use super::{Options, state::State};
use crate::{
    explain::web as words,
    live::{Message, Source},
    web::{Api, ApiReply, Method},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

// Match the server's 32 workers, bounding queued requests even for direct callers.
const REQUESTS: usize = 32;
const DEADLINE: Duration = Duration::from_secs(2);
const CAPTURE_SLICE: Duration = Duration::from_millis(8);

/// One bounded API request, with an independent nonblocking reply channel.
pub(super) struct Job {
    /// HTTP method after access checks in the router.
    pub method: Method,
    /// Relative path after `/api/`.
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Monotonic request deadline, two seconds after submission.
    pub until: Instant,
    pub reply: SyncSender<ApiReply>,
}

/// Cloneable API sender. HTTP callers never borrow pipeline or capture state.
#[derive(Clone)]
pub struct WebApi {
    sender: SyncSender<Job>,
}
impl Api for WebApi {
    fn handle(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &[u8],
    ) -> ApiReply {
        if path.len() > 8192
            || body.len() > 4096
            || query.len() > 64
            || query
                .iter()
                .map(|(k, v)| k.len().saturating_add(v.len()))
                .fold(0usize, usize::saturating_add)
                > 8192
        {
            return failure(400, words::error(400));
        }
        let (reply, receive) = mpsc::sync_channel(1);
        let until = Instant::now() + DEADLINE;
        let job = Job {
            method,
            path: path.into(),
            query: query.to_vec(),
            body: body.to_vec(),
            until,
            reply,
        };
        if self.sender.try_send(job).is_err() {
            return failure(500, words::ENGINE_BUSY);
        }
        match receive.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(reply) => reply,
            Err(mpsc::RecvTimeoutError::Timeout) => failure(500, words::ENGINE_TIMEOUT),
            Err(mpsc::RecvTimeoutError::Disconnected) => failure(500, words::ENGINE_BUSY),
        }
    }
}

/// Encodes a fixed error sentence using the shared JSON writer.
pub(super) fn failure(status: u16, message: &str) -> ApiReply {
    ApiReply {
        status: if status >= 500 { 500 } else { status },
        json: crate::log::Json::object().str("error", message).finish(),
    }
}

/// Capture/pipeline worker owner. Drop cancels capture, finishes logs and joins it.
pub struct Engine {
    api: WebApi,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Engine {
    /// Moves one capture source and pipeline policy onto a dedicated thread.
    /// Returns thread-start errors; later capture/logging failures appear in `/session`.
    pub fn start(source: Source, options: Options) -> io::Result<Self> {
        Self::spawn(options, move |receive, stop, state| {
            run(Some(source), None, receive, stop, state)
        })
    }
    /// Starts the same engine with an ordered, caller-owned capture channel.
    /// Useful for deterministic playback; disconnection marks the session ended.
    /// The caller must number packets in strictly increasing order, starting at one.
    pub fn channel(input: Receiver<Message>, options: Options) -> io::Result<Self> {
        Self::spawn(options, move |receive, stop, state| {
            run(None, Some(input), receive, stop, state)
        })
    }
    fn spawn(
        options: Options,
        work: impl FnOnce(Receiver<Job>, Arc<AtomicBool>, State) + Send + 'static,
    ) -> io::Result<Self> {
        let (sender, receive) = mpsc::sync_channel(REQUESTS);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("netmon-web-engine".into())
            .spawn(move || {
                work(receive, flag, State::new(options));
            })?;
        Ok(Self {
            api: WebApi { sender },
            stop,
            worker: Some(worker),
        })
    }
    /// Returns a sender usable by all HTTP workers; it cannot mutate state directly.
    pub fn api(&self) -> WebApi {
        self.api.clone()
    }
    /// Cancels capture and joins after conversation close records and log flushing.
    /// Idempotent; outstanding calls receive 500 when their reply channel closes.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(
    mut source: Option<Source>,
    input: Option<Receiver<Message>>,
    receive: Receiver<Job>,
    stop: Arc<AtomicBool>,
    mut state: State,
) {
    let mut pending: Option<Job> = None;
    while !stop.load(Ordering::Acquire) {
        let start = Instant::now();
        while start.elapsed() < CAPTURE_SLICE && state.running() {
            let input = source.as_ref().map(Source::receiver).or(input.as_ref());
            let Some(input) = input else {
                break;
            };
            match input.try_recv() {
                Ok(message) => state.message(message),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    state.message(Message::Ended);
                    break;
                }
            }
        }
        state.tick();
        if pending.is_none() {
            pending = receive.try_recv().ok();
        }
        if let Some(job) = pending.take()
            && Instant::now() < job.until
        {
            if let Some(reply) = state.reply(&job) {
                let _ = job.reply.try_send(reply);
            } else {
                pending = Some(job);
            }
        }
        // Park only with no queued API work and no known capture backlog; OS time
        // schedules work slices, while every traffic rate/timeout uses packet time.
        if pending.is_none() {
            match receive.recv_timeout(Duration::from_millis(1)) {
                Ok(job) => pending = Some(job),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
    if let Some(source) = source.as_mut() {
        source.stop();
    }
    state.pipeline.finish();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_full_or_closed_queue_returns_a_truthful_json_error() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let (reply, _receive) = mpsc::sync_channel(1);
        sender
            .try_send(Job {
                method: Method::Get,
                path: "session".into(),
                query: Vec::new(),
                body: Vec::new(),
                until: Instant::now() + DEADLINE,
                reply,
            })
            .unwrap_or_else(|_| panic!("empty queue rejected job"));
        let api = WebApi { sender };
        let full = api.handle(Method::Get, "session", &[], b"");
        assert_eq!(full.status, 500);
        assert!(full.json.contains("busy or unavailable"));
        drop(receiver);
        let closed = api.handle(Method::Get, "session", &[], b"");
        assert_eq!(closed.status, 500);
        assert!(closed.json.contains("busy or unavailable"));
    }
}
