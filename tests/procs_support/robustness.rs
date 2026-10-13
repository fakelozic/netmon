//! Checks for procfs robustness behavior.
//! Fake-tree construction stays in mod.rs.
//! Read empty_header_only_missing_net_and_missing_root_are_empty first.
//! A socket can outlive one process when another process still holds its fd.

use super::{FakeProc, addr, row};
use netmon::procs::{ProcTable, Transport, default_gateway, local_addresses};
use std::fs;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn empty_header_only_missing_net_and_missing_root_are_empty() {
    let fake = FakeProc::new("empty");
    assert_eq!(ProcTable::empty().sockets(), 0);
    for file in ["tcp", "tcp6", "udp", "udp6"] {
        fake.net(file, b"");
    }
    assert_eq!(ProcTable::scan(fake.root()).sockets(), 0);
    for file in ["tcp", "tcp6", "udp", "udp6"] {
        fake.sockets(file, &[]);
    }
    assert_eq!(ProcTable::scan(fake.root()).sockets(), 0);
    fs::remove_dir_all(fake.root().join("net")).unwrap();
    fake.process(42, b"alone\n", &[1]);
    let table = ProcTable::scan(fake.root());
    assert_eq!(table.sockets(), 0);
    assert_eq!(table.unreadable(), 0);
    let missing = fake.root().join("does-not-exist");
    assert_eq!(ProcTable::scan(&missing).sockets(), 0);
    assert!(local_addresses(&missing).is_empty());
    assert_eq!(default_gateway(&missing), None);
}

#[test]
fn a_process_vanishing_during_the_scan_is_not_an_error() {
    let fake = FakeProc::new("vanishing");
    fake.sockets("udp", &[row(addr("127.0.0.1:5000"), addr("0.0.0.0:0"), 1)]);
    for _ in 0..16 {
        fake.process(42, b"temporary\n", &[1]);
        let barrier = Arc::new(Barrier::new(2));
        let scanner_barrier = Arc::clone(&barrier);
        let root = fake.root().to_path_buf();
        let scanner = thread::spawn(move || {
            scanner_barrier.wait();
            ProcTable::scan(&root)
        });
        barrier.wait();
        fs::remove_dir_all(fake.root().join("42")).unwrap();
        let table = scanner.join().unwrap();
        assert!(table.sockets() <= 1);
        assert_eq!(table.unreadable(), 0);
        for (_, _, _, owner) in table.iter() {
            assert_eq!(owner.pid, 42);
            assert_eq!(owner.name, "temporary");
        }
    }
}

#[test]
fn unreadable_processes_are_counted_once_and_partial_owners_survive() {
    let fake = FakeProc::new("unreadable");
    fake.sockets("udp", &[row(addr("127.0.0.1:5000"), addr("0.0.0.0:0"), 1)]);
    fake.process(10, b"visible\n", &[1]);
    fake.process(20, b"denied\n", &[1]);
    let denied = fake.root().join("20/fd");
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o0)).unwrap();
    if fs::read_dir(&denied).is_err() {
        let table = ProcTable::scan(fake.root());
        assert_eq!(table.unreadable(), 1);
        assert_eq!(table.sockets(), 1);
        assert_eq!(table.iter().next().unwrap().3.pid, 10);
    } else {
        // A root test runner bypasses mode bits. A self-referential symlink is
        // a deterministic access failure even with elevated privileges.
        fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&denied).unwrap();
        symlink("fd", &denied).unwrap();
        let table = ProcTable::scan(fake.root());
        assert_eq!(table.unreadable(), 1);
        assert_eq!(table.sockets(), 1);
    }
    if denied.is_dir() {
        fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn small_files_and_the_shared_socket_line_budget_are_bounded() {
    let fake = FakeProc::new("line-bounds");
    let first = row(addr("127.0.0.1:5000"), addr("0.0.0.0:0"), 1);
    let excluded = row(addr("127.0.0.1:5001"), addr("0.0.0.0:0"), 2);
    let mut contents = first;
    for _ in 1..200_000 {
        contents.push_str("malformed\n");
    }
    contents.push_str(&excluded);
    fake.net("tcp", contents);
    fake.sockets("udp", &[excluded]);
    let mut comm = vec![b'a'; 4096];
    comm.extend_from_slice(b"\x1bhidden\n");
    fake.process(42, &comm, &[1, 2]);
    let table = ProcTable::scan(fake.root());
    assert_eq!(table.sockets(), 1);
    let owner = table.iter().next().unwrap().3;
    assert_eq!(owner.name, "a".repeat(4096));
    assert!(
        table
            .lookup(Transport::Udp, addr("127.0.0.1:5001"), addr("192.0.2.1:53"))
            .is_none()
    );
}

#[test]
fn descriptor_link_budget_is_shared_across_the_scan() {
    let fake = FakeProc::new("fd-bounds");
    let path = fake.root().join("net/tcp");
    let mut file = BufWriter::new(fs::File::create(path).unwrap());
    for inode in 1..=100_001 {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), (inode % 65_536) as u16);
        let remote = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            (inode / 65_536 + 1) as u16,
        );
        file.write_all(row(local, remote, inode).as_bytes())
            .unwrap();
    }
    file.flush().unwrap();
    fake.process(42, b"bounded-a\n", &(1..=50_000).collect::<Vec<_>>());
    fake.process(43, b"bounded-b\n", &(50_001..=100_001).collect::<Vec<_>>());
    let table = ProcTable::scan(fake.root());
    assert_eq!(table.sockets(), 100_000);
    assert_eq!(table.unreadable(), 0);
    assert!(
        table
            .iter()
            .all(|(_, _, _, owner)| [42, 43].contains(&owner.pid))
    );
}
