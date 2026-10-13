//! Fake procfs socket ownership for pipeline checks.
//! Packet creation stays in mod.rs; app assertions stay in pipeline/apps.rs.
//! Read `fake_proc` for the kernel-table shape used without a live socket.

use super::{TestDir, sequence, tcp};
use netmon::pipeline::Pipeline;
use std::{
    fs,
    os::unix::fs::symlink,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

/// Populate one process owning a connected 10.0.0.1:40000 -> 10.0.0.2:80 socket.
pub(crate) fn fake_proc(base: &TestDir, name: &str) -> std::path::PathBuf {
    let root = base.path().join("proc");
    fs::create_dir_all(root.join("net")).unwrap();
    fs::create_dir_all(root.join("42/fd")).unwrap();
    fs::write(root.join("42/comm"), format!("{name}\n")).unwrap();
    symlink("socket:[123]", root.join("42/fd/0")).unwrap();
    let src = u32::from_ne_bytes([10, 0, 0, 1]);
    let dst = u32::from_ne_bytes([10, 0, 0, 2]);
    fs::write(root.join("net/tcp"),format!("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: {src:08X}:9C40 {dst:08X}:0050 01 00000000:00000000 00:00000000 00000000 1000 0 123 1\n")).unwrap();
    fs::write(
        root.join("net/fib_trie"),
        " |-- 10.0.0.0\n /8 host LOCAL\n |-- 10.0.0.1\n /32 host LOCAL\n",
    )
    .unwrap();
    fs::write(
        root.join("net/route"),
        format!("eth0 00000000 {dst:08X} 0003\n"),
    )
    .unwrap();
    root
}

/// Wait for content, never for a measured scan speed. The timeout is only a
/// deadlock watchdog; the stop flag and join prevent a failed test leaking work.
/// Fresh SYN sequence numbers keep initial empty-snapshot misses on separate flows.
pub(crate) fn ready(mut pipeline: Pipeline) -> Pipeline {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let (send, receive) = mpsc::channel();
        let stop_ref = &stop;
        let watcher = scope.spawn(move || {
            let mut number = 1u64;
            while !stop_ref.load(Ordering::Relaxed) {
                let row = pipeline.push(&sequence(
                    tcp(number, false, [40000, 80], 2, &[]),
                    number as u32,
                    0,
                ));
                if row.app.is_some() {
                    let _ = send.send(());
                    break;
                }
                number = number.saturating_add(1);
                thread::yield_now();
            }
            pipeline
        });
        let published = receive.recv_timeout(Duration::from_secs(10));
        stop.store(true, Ordering::Relaxed);
        let pipeline = watcher.join().unwrap();
        published.expect("background ownership snapshot was not published");
        pipeline
    })
}
