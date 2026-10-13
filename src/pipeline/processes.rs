//! Background procfs snapshots used by the pipeline.
//! Socket ownership scanning stays in `procs::Refresher`.
//! Read `Processes::new` for startup, then `refresh` for packet-time scheduling.
//! Local addresses identify this computer's side of a conversation.

use crate::procs::{self, ProcTable, Refresher};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// Ownership changes faster than interface addresses; the brief asks for a
// 30-second packet-time address cadence and the process module polls every 2 s.
const ADDRESS_INTERVAL: Duration = Duration::from_secs(30);
const PROCESS_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
/// Published address/gateway snapshot, bounded by the procfs reader limits.
pub(super) struct Addresses {
    pub local: Vec<IpAddr>,
    /// None means no readable eligible IPv4 default route was found.
    pub gateway: Option<IpAddr>,
}

impl Addresses {
    fn read(root: &Path) -> Self {
        Self {
            local: procs::local_addresses(root),
            gateway: procs::default_gateway(root).map(IpAddr::V4),
        }
    }
}

/// Background procfs lookup with one pending address refresh request.
pub(super) struct Processes {
    refresher: Refresher,
    addresses: Arc<Mutex<Arc<Addresses>>>,
    requests: Option<mpsc::SyncSender<()>>,
    worker: Option<JoinHandle<()>>,
    last_request: Duration,
}

impl Processes {
    /// Read initial addresses and start ownership/address workers at packet time `started`.
    pub fn new(root: PathBuf, started: Duration) -> Self {
        // Startup may read procfs. After this, the packet path only borrows
        // snapshots, because interface files can be slow or disappear mid-read.
        let initial = Arc::new(Addresses::read(&root));
        let addresses = Arc::new(Mutex::new(initial));
        let worker_addresses = Arc::clone(&addresses);
        let refresher = Refresher::start(root.clone(), PROCESS_INTERVAL);
        // One pending request coalesces bursts without growing with traffic.
        let (requests, receive) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("netmon-addresses".into())
            .spawn(move || {
                while receive.recv().is_ok() {
                    let next = Arc::new(Addresses::read(&root));
                    let previous = {
                        let mut current = worker_addresses
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        std::mem::replace(&mut *current, next)
                    };
                    // Destruction of a large old snapshot must not hold the lock.
                    drop(previous);
                }
            })
            .ok();
        Self {
            refresher,
            addresses,
            requests: Some(requests),
            worker,
            last_request: started,
        }
    }

    /// Request addresses after 30 seconds of packet time; return latest without waiting.
    pub fn refresh(&mut self, now: Duration) -> Arc<Addresses> {
        if now.saturating_sub(self.last_request) >= ADDRESS_INTERVAL {
            self.last_request = now;
            if let Some(requests) = &self.requests {
                let _ = requests.try_send(());
            }
        }
        Arc::clone(
            &self
                .addresses
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        )
    }

    /// Borrow the most recently published ownership snapshot; initially it can be empty.
    pub fn latest(&self) -> Arc<ProcTable> {
        self.refresher.latest()
    }

    /// Ask the ownership worker for an early scan without waiting for the result.
    pub fn request_now(&self) {
        self.refresher.request_now();
    }
}

impl Drop for Processes {
    fn drop(&mut self) {
        // Closing the bounded channel wakes a waiting worker without another scan.
        self.requests.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
