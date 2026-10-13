//! Fake procfs fixtures shared by focused ownership tests.
//! Assertions live in the child modules; filesystem construction belongs here.
//! Read FakeProc::new first for the temporary-directory lifecycle.
//! A socket fd symlink exposes the inode used in its procfs socket-table row.

mod addresses;
mod lookup;
mod parsing;
mod real;
mod refresh;
mod robustness;

use netmon::procs::{ProcTable, Refresher};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

/// A per-test procfs root removed when its owner drops.
struct FakeProc {
    root: PathBuf,
}

impl FakeProc {
    /// Create a labelled root under Cargo's temporary directory; labels are unique per test.
    fn new(label: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("procs-{label}-{}", std::process::id()));
        fs::create_dir_all(root.join("net")).unwrap();
        Self { root }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn net(&self, file: &str, bytes: impl AsRef<[u8]>) {
        fs::write(self.root.join("net").join(file), bytes).unwrap();
    }

    fn sockets(&self, file: &str, rows: &[String]) {
        let mut text = String::from(
            "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
        );
        for row in rows {
            text.push_str(row);
        }
        self.net(file, text);
    }

    fn process(&self, pid: u32, comm: &[u8], inodes: &[u64]) {
        let process = self.root.join(pid.to_string());
        fs::create_dir_all(process.join("fd")).unwrap();
        fs::write(process.join("comm"), comm).unwrap();
        for (fd, inode) in inodes.iter().enumerate() {
            symlink(
                format!("socket:[{inode}]"),
                process.join("fd").join(fd.to_string()),
            )
            .unwrap();
        }
    }
}

impl Drop for FakeProc {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn raw_row(local: &str, remote: &str, inode: u64) -> String {
    format!(
        "0: {local} {remote} 01 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1 0000000000000000\n"
    )
}

fn row(local: SocketAddr, remote: SocketAddr, inode: u64) -> String {
    raw_row(&encode_endpoint(local), &encode_endpoint(remote), inode)
}

fn encode_v4(address: std::net::Ipv4Addr) -> String {
    format!("{:08X}", u32::from_ne_bytes(address.octets()))
}

fn encode_endpoint(address: SocketAddr) -> String {
    let ip = match address.ip() {
        IpAddr::V4(ip) => encode_v4(ip),
        IpAddr::V6(ip) => ip
            .octets()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| format!("{:08X}", u32::from_ne_bytes(*word)))
            .collect(),
    };
    format!("{ip}:{:04X}", address.port())
}

/// Wait for content, not for a measured scan speed. The channel timeout is only
/// a deadlock watchdog; cancellation and joining prevent a failed test leaking
/// a polling thread. Refresher cadence is tested with synthetic time separately.
fn wait_for(
    refresher: &Refresher,
    predicate: impl Fn(&ProcTable) -> bool + Send,
) -> Arc<ProcTable> {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let (send, receive) = mpsc::channel();
        let stop_ref = &stop;
        let watcher = scope.spawn(move || {
            while !stop_ref.load(Ordering::Relaxed) {
                let table = refresher.latest();
                if predicate(&table) {
                    let _ = send.send(table);
                    break;
                }
                thread::yield_now();
            }
        });
        let result = receive.recv_timeout(Duration::from_secs(10));
        stop.store(true, Ordering::Relaxed);
        watcher.join().unwrap();
        result.expect("refresher did not publish the requested content")
    })
}
