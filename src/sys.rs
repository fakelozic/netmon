//! Wraps the operating-system calls used by the command line.
//! Capture timestamp interpretation belongs to capture; shutdown policy belongs to main.
//! Read local_time for clock formatting and Interrupt for process interruption.
//! A packet timestamp records when a network message was captured.
use std::time::Duration;
use std::{
    io,
    marker::PhantomData,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

/// Restores ordinary interruption in a child launched by a signal-waiting parent.
/// Call before spawn; the post-fork closure uses only async-signal-safe libc calls.
pub(crate) fn unmask_child(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: after fork this changes only the child's signal mask. The set is
    // initialized, all pointers are valid, and the closure allocates no memory.
    unsafe {
        command.pre_exec(|| {
            let mut signals = std::mem::zeroed();
            libc::sigemptyset(&mut signals);
            libc::sigaddset(&mut signals, libc::SIGINT);
            libc::sigaddset(&mut signals, libc::SIGTERM);
            if libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}
/// Converts a packet's Unix timestamp to local clock time; never reads the clock.
/// Returns HH:MM:SS.mmm, or None if libc cannot represent or convert the time.
pub fn local_time(timestamp: Duration) -> Option<String> {
    let seconds = libc::time_t::try_from(timestamp.as_secs()).ok()?;
    let mut result = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: both pointers refer to valid, correctly aligned objects. localtime_r
    // writes the entire tm on success, uses no shared tm storage, and a null return
    // is checked before the initialized result is read.
    let result = unsafe {
        if libc::localtime_r(&seconds, result.as_mut_ptr()).is_null() {
            return None;
        }
        result.assume_init()
    };
    Some(format!(
        "{:02}:{:02}:{:02}.{:03}",
        result.tm_hour,
        result.tm_min,
        result.tm_sec,
        timestamp.subsec_millis()
    ))
}

/// Owns SIGINT/SIGTERM delivery for a command started on its main thread.
/// Start before any workers or children: they must inherit the blocked mask.
/// Drop joins the waiter and restores the caller's previous mask on the same thread.
/// No signal handler or global mutable state is used.
pub struct Interrupt {
    previous: libc::sigset_t,
    done: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    same_thread: PhantomData<Rc<()>>,
}

impl Interrupt {
    /// Sets `stop` on SIGINT or SIGTERM, including when stdin is redirected.
    /// Returns mask/thread errors before capture starts; polling is at most 50 ms.
    pub fn start(stop: Arc<AtomicBool>) -> io::Result<Self> {
        // SAFETY: sigemptyset initializes the set before additions. Both mask
        // pointers refer to live aligned storage; pthread_sigmask fills previous.
        let (signals, previous) = unsafe {
            let mut signals = std::mem::zeroed();
            let mut previous = std::mem::zeroed();
            libc::sigemptyset(&mut signals);
            libc::sigaddset(&mut signals, libc::SIGINT);
            libc::sigaddset(&mut signals, libc::SIGTERM);
            let result = libc::pthread_sigmask(libc::SIG_BLOCK, &signals, &mut previous);
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            (signals, previous)
        };
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let worker = thread::Builder::new()
            .name("netmon-signals".into())
            .spawn(move || {
                let timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 50_000_000,
                };
                while !flag.load(Ordering::Acquire) {
                    // SAFETY: the set and timeout stay live, signals are blocked on
                    // this inherited thread mask, and no siginfo storage is requested.
                    let signal =
                        unsafe { libc::sigtimedwait(&signals, std::ptr::null_mut(), &timeout) };
                    if signal == libc::SIGINT || signal == libc::SIGTERM {
                        stop.store(true, Ordering::Release);
                    }
                }
            });
        match worker {
            Ok(worker) => Ok(Self {
                previous,
                done,
                worker: Some(worker),
                same_thread: PhantomData,
            }),
            Err(error) => {
                // SAFETY: previous is the mask returned for this calling thread.
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                }
                Err(error)
            }
        }
    }
}

impl Drop for Interrupt {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        // SAFETY: !Send keeps this value on the thread whose mask we saved.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::os::unix::thread::JoinHandleExt;

    #[test]
    fn launched_children_do_not_inherit_blocked_termination() {
        let stop = Arc::new(AtomicBool::new(false));
        let _interrupt = Interrupt::start(Arc::clone(&stop)).unwrap();
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "kill -TERM $$; exit 99"]);
        unmask_child(&mut command);
        assert_eq!(command.status().unwrap().signal(), Some(libc::SIGTERM));
        assert!(!stop.load(Ordering::Acquire));
    }

    #[test]
    fn blocked_signals_set_stop_and_restore_the_callers_mask() {
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let stop = Arc::new(AtomicBool::new(false));
            let interrupt = Interrupt::start(Arc::clone(&stop)).unwrap();
            let previous = interrupt.previous;
            // SAFETY: the join handle owns a live waiter; directing the test signal
            // to it isolates this test from the test harness's unblocked threads.
            let result = unsafe {
                libc::pthread_kill(interrupt.worker.as_ref().unwrap().as_pthread_t(), signal)
            };
            assert_eq!(result, 0);
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !stop.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                thread::yield_now();
            }
            assert!(stop.load(Ordering::Acquire));
            drop(interrupt);
            // SAFETY: a null input only queries the calling thread's mask, and
            // current is fully initialized before sigismember reads it.
            unsafe {
                let mut current = std::mem::zeroed();
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current),
                    0
                );
                for signal in [libc::SIGINT, libc::SIGTERM] {
                    assert_eq!(
                        libc::sigismember(&current, signal),
                        libc::sigismember(&previous, signal)
                    );
                }
            }
        }
    }
}
