//! Checks for procfs refresh behavior.
//! Fake-tree construction stays in mod.rs.
//! Read refresher_publishes_added_sockets_keeps_old_snapshots_and_joins_on_drop first.
//! Kernel socket ownership is a changing snapshot, rather than a packet history.

use super::{FakeProc, addr, row, wait_for};
use netmon::procs::{Refresher, Transport};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

#[test]
fn refresher_publishes_added_sockets_keeps_old_snapshots_and_joins_on_drop() {
    let fake = FakeProc::new("refresher");
    fake.sockets("udp", &[row(addr("127.0.0.1:5000"), addr("0.0.0.0:0"), 1)]);
    fake.process(42, b"first\n", &[1]);
    let refresher = Refresher::start(fake.root().to_path_buf(), Duration::from_secs(60));
    let first = wait_for(&refresher, |table| table.sockets() == 1);
    fake.process(43, b"added\n", &[2]);
    fake.sockets(
        "udp",
        &[
            row(addr("127.0.0.1:5000"), addr("0.0.0.0:0"), 1),
            row(addr("127.0.0.1:5001"), addr("0.0.0.0:0"), 2),
        ],
    );
    for _ in 0..100 {
        refresher.request_now();
    }
    let second = wait_for(&refresher, |table| table.sockets() == 2);
    assert_eq!(first.sockets(), 1);
    assert_eq!(
        second
            .lookup(Transport::Udp, addr("127.0.0.1:5001"), addr("192.0.2.1:53"))
            .unwrap()
            .pid,
        43
    );
    assert!(!Arc::ptr_eq(&first, &second));
    let (send, receive) = mpsc::channel();
    let dropper = thread::spawn(move || {
        drop(refresher);
        send.send(()).unwrap();
    });
    receive.recv_timeout(Duration::from_secs(10)).unwrap();
    dropper.join().unwrap();
}
