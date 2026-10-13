//! Checks for procfs parsing behavior.
//! Fake-tree construction stays in mod.rs.
//! Read known_proc_hex_words_decode_to_known_addresses_and_ports first.
//! Procfs prints socket addresses in native-endian words.

use super::{FakeProc, addr, raw_row, row};
use netmon::procs::{ProcTable, Transport};
use std::fs;
use std::os::unix::fs::symlink;

#[test]
#[cfg(target_endian = "little")]
fn known_proc_hex_words_decode_to_known_addresses_and_ports() {
    // These literals are independent of the fixture encoder, so an identical
    // byte-order error in both encoder and decoder cannot make this test pass.
    let fake = FakeProc::new("literal-addresses");
    let cases = [
        (
            "tcp",
            Transport::Tcp,
            "0100007F:9C40",
            "0200007F:0050",
            "127.0.0.1:40000",
            "127.0.0.2:80",
        ),
        (
            "udp",
            Transport::Udp,
            "2A01A8C0:14E9",
            "04030201:0035",
            "192.168.1.42:5353",
            "1.2.3.4:53",
        ),
        (
            "tcp6",
            Transport::Tcp,
            "00000000000000000000000001000000:9C41",
            "00000000000000000000000001000000:01BB",
            "[::1]:40001",
            "[::1]:443",
        ),
        (
            "udp6",
            Transport::Udp,
            "B80D012078563412F0DEBC9A78563412:1F90",
            "00000000000000000000000001000000:0035",
            "[2001:db8:1234:5678:9abc:def0:1234:5678]:8080",
            "[::1]:53",
        ),
        (
            "tcp6",
            Transport::Tcp,
            "0000000000000000FFFF00000A01A8C0:1388",
            "0000000000000000FFFF0000010200C0:01BB",
            "192.168.1.10:5000",
            "192.0.2.1:443",
        ),
    ];
    for file in ["tcp", "tcp6", "udp", "udp6"] {
        let rows = cases
            .iter()
            .enumerate()
            .filter(|(_, case)| case.0 == file)
            .map(|(index, case)| raw_row(case.2, case.3, 100 + index as u64))
            .collect::<Vec<_>>();
        fake.sockets(file, &rows);
    }
    fake.process(42, b"known\n", &[100, 101, 102, 103, 104]);
    let table = ProcTable::scan(fake.root());
    assert_eq!(table.sockets(), cases.len());
    for (_, transport, _, _, local, remote) in cases {
        let owner = table.lookup(transport, addr(local), addr(remote)).unwrap();
        assert_eq!(owner.pid, 42);
        assert_eq!(owner.name, "known");
        assert!(
            table
                .iter()
                .any(|(t, l, r, _)| t == transport && l == addr(local) && r == addr(remote))
        );
    }
}

#[test]
fn malformed_non_utf8_and_overlong_input_leave_a_partial_sanitised_table() {
    let fake = FakeProc::new("malformed");
    let valid = row(addr("127.0.0.1:5000"), addr("192.0.2.1:53"), 1);
    let mut contents = b"\xff\xfe\n\nnot a socket\n".to_vec();
    for malformed in [
        "0: invalid 00000000:0000\n".to_string(),
        valid.replace("01 00000000", "zz 00000000"),
        valid.replace("1000 0 1", "1000 0 18446744073709551616"),
        valid.replace("1000 0 1", "1000 0 +1"),
        valid.replace("1000 0 1", "1000 0 0"),
        valid.replace(":1388", ":10000"),
    ] {
        contents.extend_from_slice(malformed.as_bytes());
    }
    contents.extend_from_slice(&vec![b'x'; 20_000]);
    contents.push(b'\n');
    contents.extend_from_slice(valid.trim_end().as_bytes()); // EOF without newline
    fake.net("tcp", contents);
    fake.process(42, b"tool\x1b\n\xff\n", &[1]);
    for (fd, target) in [
        (1, "socket:[bad]"),
        (2, "socket:[18446744073709551616]"),
        (3, "socket:[+1]"),
        (4, "socket:[1]junk"),
    ] {
        symlink(target, fake.root().join("42/fd").join(fd.to_string())).unwrap();
    }
    fs::write(fake.root().join("42/fd/5"), b"not a link").unwrap();
    fake.process(99, b"missing\n", &[1]);
    fs::remove_file(fake.root().join("99/comm")).unwrap();
    fake.process(100, b"missing\n", &[1]);
    fs::remove_dir_all(fake.root().join("100/fd")).unwrap();
    let table = ProcTable::scan(fake.root());
    assert_eq!(table.sockets(), 1);
    assert_eq!(table.unreadable(), 0);
    let owner = table
        .lookup(Transport::Tcp, addr("127.0.0.1:5000"), addr("192.0.2.1:53"))
        .unwrap();
    assert_eq!(owner.pid, 42);
    assert_eq!(owner.name, "tool\\x1B\\x0A\\xFF");
    assert!(owner.name.bytes().all(|byte| (0x20..=0x7e).contains(&byte)));
}
