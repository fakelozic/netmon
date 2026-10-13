//! Checks for procfs lookup behavior.
//! Fake-tree construction stays in mod.rs.
//! Read exact_then_bound_listener_then_wildcard_and_transport_is_separate first.
//! A local port can belong to a bound listener or to a connected socket.

use super::{FakeProc, addr, row};
use netmon::procs::{ProcTable, Transport};

#[test]
fn exact_then_bound_listener_then_wildcard_and_transport_is_separate() {
    let fake = FakeProc::new("specificity");
    let local = addr("127.0.0.1:8000");
    let peer = addr("192.0.2.1:5000");
    fake.sockets(
        "tcp",
        &[
            row(addr("0.0.0.0:8000"), addr("0.0.0.0:0"), 1),
            row(local, addr("0.0.0.0:0"), 2),
            row(local, peer, 3),
            row(addr("127.0.0.1:9000"), peer, 4),
        ],
    );
    fake.sockets("udp", &[row(local, addr("0.0.0.0:0"), 5)]);
    for (pid, inode) in [(10, 1), (20, 2), (30, 3), (40, 4), (50, 5)] {
        fake.process(pid, b"owner\n", &[inode]);
    }
    let table = ProcTable::scan(fake.root());
    assert_eq!(table.lookup(Transport::Tcp, local, peer).unwrap().pid, 30);
    assert_eq!(
        table
            .lookup(Transport::Tcp, local, addr("203.0.113.1:22"))
            .unwrap()
            .pid,
        20
    );
    assert_eq!(
        table
            .lookup(Transport::Tcp, addr("192.168.1.2:8000"), peer)
            .unwrap()
            .pid,
        10
    );
    assert_eq!(table.lookup(Transport::Udp, local, peer).unwrap().pid, 50);
    assert!(
        table
            .lookup(
                Transport::Tcp,
                addr("127.0.0.1:9000"),
                addr("203.0.113.1:22")
            )
            .is_none()
    );
    assert!(
        table
            .lookup(Transport::Tcp, addr("127.0.0.1:8001"), peer)
            .is_none()
    );
    assert!(
        table
            .lookup(Transport::Udp, addr("127.0.0.1:9000"), peer)
            .is_none()
    );
    assert!(
        table
            .lookup(Transport::Tcp, local, addr("[2001:db8::1]:22"))
            .is_none()
    );
}

fn ipv6_fixture() -> FakeProc {
    let fake = FakeProc::new("v6-and-mapped");
    fake.sockets(
        "tcp6",
        &[
            row(addr("[::]:8080"), addr("[::]:0"), 1),
            row(addr("[2001:db8::1]:8081"), addr("[::]:0"), 2),
            row(
                addr("[::ffff:192.0.2.1]:5000"),
                addr("[::ffff:192.0.2.2]:443"),
                3,
            ),
        ],
    );
    fake.sockets(
        "udp6",
        &[
            row(addr("[::1]:5353"), addr("[::]:0"), 4),
            row(addr("[::ffff:127.0.0.1]:5354"), addr("[::]:0"), 5),
            row(addr("[::]:5355"), addr("[::]:0"), 6),
        ],
    );
    fake.sockets(
        "tcp",
        &[row(addr("192.0.2.1:5001"), addr("192.0.2.2:443"), 7)],
    );
    for inode in 1..=7 {
        fake.process(inode as u32 + 10, b"socket\n", &[inode]);
    }
    fake
}

#[test]
fn ipv6_listeners_udp_and_ipv4_mapped_endpoints_match() {
    let fake = ipv6_fixture();
    let table = ProcTable::scan(fake.root());
    for (transport, local, remote, pid) in [
        (
            Transport::Tcp,
            "[2001:db8::99]:8080",
            "[2001:db8::2]:3333",
            11,
        ),
        (
            Transport::Tcp,
            "[2001:db8::1]:8081",
            "[2001:db8::2]:3333",
            12,
        ),
        (Transport::Tcp, "192.0.2.1:5000", "192.0.2.2:443", 13),
        (
            Transport::Tcp,
            "[::ffff:192.0.2.1]:5000",
            "[::ffff:192.0.2.2]:443",
            13,
        ),
        (Transport::Udp, "[::1]:5353", "[2001:db8::2]:3333", 14),
        (Transport::Udp, "127.0.0.1:5354", "192.0.2.2:53", 15),
        (
            Transport::Udp,
            "[2001:db8::1]:5355",
            "[2001:db8::2]:3333",
            16,
        ),
        (
            Transport::Tcp,
            "[::ffff:192.0.2.1]:5001",
            "[::ffff:192.0.2.2]:443",
            17,
        ),
    ] {
        assert_eq!(
            table
                .lookup(transport, addr(local), addr(remote))
                .unwrap()
                .pid,
            pid
        );
    }
    assert!(
        table
            .lookup(
                Transport::Tcp,
                addr("[2001:db8::3]:8081"),
                addr("[2001:db8::2]:3333")
            )
            .is_none()
    );
}

#[test]
fn packet_lookup_reports_direction_and_prefers_the_source_on_loopback() {
    let fake = FakeProc::new("packet-direction");
    let local = addr("127.0.0.1:40000");
    let peer = addr("192.0.2.1:443");
    fake.sockets("tcp", &[row(local, peer, 1), row(peer, local, 2)]);
    fake.sockets("udp", &[row(local, addr("0.0.0.0:0"), 3)]);
    fake.process(10, b"client\n", &[1, 3]);
    let table = ProcTable::scan(fake.root());
    assert_eq!(
        table
            .lookup_packet(6, local, peer)
            .map(|(p, outgoing)| (p.pid, outgoing)),
        Some((10, true))
    );
    assert_eq!(
        table
            .lookup_packet(6, peer, local)
            .map(|(p, outgoing)| (p.pid, outgoing)),
        Some((10, false))
    );
    assert_eq!(
        table
            .lookup_packet(17, peer, local)
            .map(|(p, outgoing)| (p.pid, outgoing)),
        Some((10, false))
    );
    assert!(table.lookup_packet(1, local, peer).is_none());
    fake.process(20, b"server\n", &[2]);
    let table = ProcTable::scan(fake.root());
    assert_eq!(
        table
            .lookup_packet(6, peer, local)
            .map(|(p, outgoing)| (p.pid, outgoing)),
        Some((20, true))
    );
}

#[test]
fn shared_sockets_prefer_the_lowest_non_init_pid_and_hide_unowned_rows() {
    let fake = FakeProc::new("shared-owner");
    fake.sockets(
        "udp",
        &[
            row(addr("127.0.0.1:5000"), addr("0.0.0.0:0"), 1),
            row(addr("127.0.0.1:5001"), addr("0.0.0.0:0"), 2),
            row(addr("127.0.0.1:5002"), addr("0.0.0.0:0"), 3),
        ],
    );
    fake.process(100, b"higher\n", &[1]);
    fake.process(1, b"init\n", &[1, 2]);
    fake.process(22, b"preferred\n", &[1, 1]);
    let table = ProcTable::scan(fake.root());
    let peer = addr("192.0.2.1:53");
    assert_eq!(
        table
            .lookup(Transport::Udp, addr("127.0.0.1:5000"), peer)
            .unwrap()
            .pid,
        22
    );
    assert_eq!(
        table
            .lookup(Transport::Udp, addr("127.0.0.1:5001"), peer)
            .unwrap()
            .pid,
        1
    );
    assert!(
        table
            .lookup(Transport::Udp, addr("127.0.0.1:5002"), peer)
            .is_none()
    );
    assert_eq!(table.sockets(), 2);
    assert_eq!(table.iter().count(), 2);
}
