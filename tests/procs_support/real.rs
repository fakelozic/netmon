//! Checks for procfs real behavior.
//! Fake-tree construction stays in mod.rs.
//! Read real_proc_finds_this_process_for_a_bound_loopback_udp_socket first.
//! Binding a UDP socket creates a kernel endpoint without sending a packet.

use super::addr;
use netmon::procs::{ProcTable, Transport};
use std::fs;
use std::net::UdpSocket;

#[test]
fn real_proc_finds_this_process_for_a_bound_loopback_udp_socket() {
    if fs::File::open("/proc/net/udp").is_err() {
        eprintln!("notice: /proc/net/udp cannot be read; skipping real-proc ownership test");
        return;
    }
    // No packets are sent: this only creates the socket required by the brief.
    let socket = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "notice: sandbox denied UDP socket creation ({error}); real-proc ownership is not verified"
            );
            return;
        }
        Err(error) => panic!("could not bind the real-proc test socket: {error}"),
    };
    let local = socket.local_addr().unwrap();
    let table = ProcTable::scan(std::path::Path::new("/proc"));
    let owner = table
        .lookup(Transport::Udp, local, addr("192.0.2.1:53"))
        .unwrap();
    assert_eq!(owner.pid, std::process::id());
}
