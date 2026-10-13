//! Publication of socket-owner snapshots from a worker thread.
//! Procfs interpretation stays in scan.rs; this file only schedules scans.
//! Read Refresher::start first to see the initial empty snapshot contract.
//! A socket can change owners or disappear between two snapshots.

use super::ProcTable;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// New connections can arrive in bursts; extra scans are capped at five per second.
const EXTRA_SCAN_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Default)]
struct RefreshControl {
    stop: bool,
    requested: bool,
}

/// Background publisher of immutable ownership snapshots. Drop wakes the worker
/// and joins it after any scan in progress finishes.
pub struct Refresher {
    latest: Arc<Mutex<Arc<ProcTable>>>,
    control: Arc<(Mutex<RefreshControl>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

impl Refresher {
    /// Start with an empty snapshot and scan `proc_root` off the caller's thread.
    /// `every` is an elapsed-time period after each scan, clamped to at least 1 ms
    /// to avoid a busy loop. Failure to start a worker leaves an empty snapshot.
    pub fn start(proc_root: PathBuf, every: Duration) -> Refresher {
        Self::start_scanner(every, move || ProcTable::scan(&proc_root))
    }

    fn start_scanner(every: Duration, scan: impl FnMut() -> ProcTable + Send + 'static) -> Self {
        let latest = Arc::new(Mutex::new(Arc::new(ProcTable::empty())));
        let control = Arc::new((Mutex::new(RefreshControl::default()), Condvar::new()));
        let worker_latest = Arc::clone(&latest);
        let worker_control = Arc::clone(&control);
        let thread = thread::Builder::new()
            .name("netmon-procs".into())
            .spawn(move || {
                refresh_loop(
                    scan,
                    every.max(Duration::from_millis(1)),
                    &worker_latest,
                    &worker_control,
                );
            })
            .ok();
        Self {
            latest,
            control,
            thread,
        }
    }

    /// Clone the latest snapshot without waiting for a scan or old-table cleanup.
    /// The short publication lock protects only an Arc clone/swap. An empty
    /// snapshot can mean the initial scan has not finished. Returned snapshots
    /// remain valid across later refreshes.
    pub fn latest(&self) -> Arc<ProcTable> {
        Arc::clone(
            &self
                .latest
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        )
    }

    /// Ask for a scan without waiting. Requests coalesce to at most one extra
    /// scan per 200 ms; a request during the cooldown remains pending.
    pub fn request_now(&self) {
        let (control, wake) = &*self.control;
        control
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .requested = true;
        wake.notify_one();
    }
}

impl Drop for Refresher {
    fn drop(&mut self) {
        let (control, wake) = &*self.control;
        control
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stop = true;
        wake.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn refresh_loop(
    mut scan: impl FnMut() -> ProcTable,
    every: Duration,
    latest: &Mutex<Arc<ProcTable>>,
    control: &(Mutex<RefreshControl>, Condvar),
) {
    let initial = Arc::new(scan());
    publish(latest, initial);
    // Procfs polling uses elapsed time independently of packet arrival. It does
    // not measure traffic rates or connection timeouts, which use packet time.
    let mut last_scan = Instant::now();
    let mut last_extra: Option<Instant> = None;
    loop {
        let (state, wake) = control;
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        if state.stop {
            return;
        }
        let decision = refresh_decision(
            every,
            last_scan.elapsed(),
            last_extra.map(|last| last.elapsed()),
            state.requested,
        );
        if let RefreshDecision::Scan { extra } = decision {
            state.requested = false;
            if extra {
                last_extra = Some(Instant::now());
            }
            drop(state);
            let table = Arc::new(scan());
            publish(latest, table);
            last_scan = Instant::now();
        } else if let RefreshDecision::Wait(wait) = decision {
            // Limit an OS wait to one day so Duration::MAX cannot overflow the
            // platform's timed-wait representation. Notifications still wake it.
            let (state, _) = wake
                .wait_timeout(state, wait.min(Duration::from_secs(86_400)))
                .unwrap_or_else(|error| error.into_inner());
            drop(state);
        }
    }
}

fn publish(latest: &Mutex<Arc<ProcTable>>, table: Arc<ProcTable>) {
    let previous = {
        let mut latest = latest.lock().unwrap_or_else(|error| error.into_inner());
        std::mem::replace(&mut *latest, table)
    };
    // A large old table is destroyed outside the snapshot lock as well.
    drop(previous);
}

#[derive(Debug, Eq, PartialEq)]
enum RefreshDecision {
    Scan { extra: bool },
    Wait(Duration),
}

// Scheduling can be tested with synthetic elapsed times, independently of how
// quickly the operating system schedules the worker thread.
fn refresh_decision(
    every: Duration,
    since_scan: Duration,
    since_extra: Option<Duration>,
    requested: bool,
) -> RefreshDecision {
    if since_scan >= every {
        return RefreshDecision::Scan { extra: false };
    }
    let cooldown = since_extra.map_or(Duration::ZERO, |elapsed| {
        EXTRA_SCAN_INTERVAL.saturating_sub(elapsed)
    });
    if requested && cooldown.is_zero() {
        return RefreshDecision::Scan { extra: true };
    }
    let periodic_wait = every.saturating_sub(since_scan);
    RefreshDecision::Wait(if requested {
        periodic_wait.min(cooldown)
    } else {
        periodic_wait
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn extra_scan_cooldown_uses_synthetic_elapsed_times() {
        let every = Duration::from_secs(2);
        let ms = Duration::from_millis;
        assert_eq!(
            refresh_decision(every, ms(0), None, true),
            RefreshDecision::Scan { extra: true }
        );
        for elapsed in [0, 1, 100, 199] {
            assert_eq!(
                refresh_decision(every, ms(elapsed), Some(ms(elapsed)), true),
                RefreshDecision::Wait(ms(200 - elapsed))
            );
        }
        assert_eq!(
            refresh_decision(every, ms(200), Some(ms(200)), true),
            RefreshDecision::Scan { extra: true }
        );
        assert_eq!(
            refresh_decision(every, ms(200), Some(ms(200)), false),
            RefreshDecision::Wait(ms(1800))
        );
        assert_eq!(
            refresh_decision(every, every, Some(ms(0)), true),
            RefreshDecision::Scan { extra: false }
        );
    }

    #[test]
    fn latest_returns_while_a_scan_is_blocked_and_drop_joins() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let refresher = Arc::new(Refresher::start_scanner(Duration::MAX, move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            ProcTable::empty()
        }));
        started_rx.recv().unwrap();
        let reader_refresher = Arc::clone(&refresher);
        let (read_tx, read_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            read_tx.send(reader_refresher.latest()).unwrap();
        });
        // This is a deadlock watchdog, not a speed assertion. The scanner is
        // deliberately blocked until after the reader has returned.
        let snapshot = read_rx.recv_timeout(Duration::from_secs(10));
        release_tx.send(()).unwrap();
        reader.join().unwrap();
        assert_eq!(snapshot.unwrap().sockets(), 0);
        let (joined_tx, joined_rx) = mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(refresher);
            joined_tx.send(()).unwrap();
        });
        joined_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        dropper.join().unwrap();
    }
}
