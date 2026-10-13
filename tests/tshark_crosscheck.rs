//! Compares fixture fields against a local tshark invocation.
//! Synthetic packet parsing belongs to `netmon::decode`; output belongs to `netmon::render`.
//! Start with `every_fixture_field_matches_tshark`.

use netmon::capture::Reader;
use netmon::decode::{AppInfo, Detail, decode};
use netmon::{render, text};
use std::{io, path::Path, process::Command};

const FIELDS: [&str; 25] = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "ip.proto",
    "ipv6.nxt",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.window_size_value",
    "dns.id",
    "dns.qry.name",
    "dns.flags.rcode",
    "http.request.method",
    "http.response.code",
    "tls.handshake.extensions_server_name",
    "icmp.type",
    "icmpv6.type",
];

#[test]
fn every_fixture_field_matches_tshark() {
    for file in ["loopback-mixed.pcapng", "cooked-any.pcapng"] {
        let path = Path::new("tests/fixtures").join(file);
        let Some(output) = tshark(&path) else {
            return;
        };
        let rows = output.lines().collect::<Vec<_>>();
        let packets = Reader::open(&path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(packets.len(), rows.len());
        for (p, row) in packets.iter().zip(rows) {
            let actual = cells(p);
            let expected = row.split('\t').collect::<Vec<_>>();
            assert_eq!(expected.len(), actual.len());
            for ((field, actual), expected) in FIELDS.iter().zip(actual.iter()).zip(expected) {
                assert_eq!(actual, expected, "{file} packet {} {field}", p.number);
            }
        }
    }
}

fn tshark(path: &Path) -> Option<String> {
    let mut command = Command::new("tshark");
    // Disable TCP reassembly because these decoders inspect one packet at a time.
    command.arg("-r").arg(path).args([
        "-o",
        "tcp.desegment_tcp_streams:FALSE",
        "-T",
        "fields",
        "-E",
        "occurrence=f",
    ]);
    for f in FIELDS {
        command.args(["-e", f]);
    }
    let result = match command.output() {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("tshark is not on PATH; cross-check skipped");
            return None;
        }
        Err(e) => panic!("cannot run tshark: {e}"),
    };
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    Some(output)
}

fn cells(p: &netmon::capture::RawPacket) -> Vec<String> {
    let d = decode(p.link, &p.data, p.orig_len, Detail::Summary);
    let s = &d.summary;
    let mut actual = vec![String::new(); FIELDS.len()];
    actual[0] = p.number.to_string();
    actual[1] = render::epoch(p.ts);
    actual[2] = p.orig_len.to_string();
    if let Some(a) = &s.src {
        actual[if matches!(a, netmon::decode::Addr::V6(_)) {
            4
        } else {
            3
        }] = text::address(a);
    }
    if let Some(a) = &s.dst {
        actual[if matches!(a, netmon::decode::Addr::V6(_)) {
            6
        } else {
            5
        }] = text::address(a);
    }
    if let Some(n) = s.ip_proto {
        actual[if matches!(&s.src, Some(netmon::decode::Addr::V6(_))) {
            8
        } else {
            7
        }] = n.to_string();
    }
    let (src, dst) = if s.tcp.is_some() { (9, 10) } else { (11, 12) };
    if let Some(n) = s.src_port {
        actual[src] = n.to_string();
    }
    if let Some(n) = s.dst_port {
        actual[dst] = n.to_string();
    }
    if let Some(t) = &s.tcp {
        actual[13] = format!("0x{:04x}", t.flags);
        actual[14] = t.seq.to_string();
        actual[15] = t.ack.to_string();
        actual[16] = t.window.to_string();
    }
    application_cells(&mut actual, s);
    actual
}

fn application_cells(actual: &mut [String], s: &netmon::decode::Summary) {
    match &s.app {
        Some(AppInfo::DnsQuery { id, name, .. }) => {
            actual[17] = format!("0x{id:04x}");
            actual[18] = name.clone();
        }
        Some(AppInfo::DnsResponse {
            id, name, rcode, ..
        }) => {
            actual[17] = format!("0x{id:04x}");
            actual[18] = name.clone();
            actual[19] = rcode.to_string();
        }
        Some(AppInfo::HttpRequest { method, .. }) => actual[20] = method.clone(),
        Some(AppInfo::HttpResponse { status, .. }) => actual[21] = status.to_string(),
        Some(AppInfo::TlsClientHello(h)) => actual[22] = h.server_name.clone().unwrap_or_default(),
        Some(AppInfo::Icmp {
            v6, kind, embedded, ..
        }) => {
            actual[if *v6 { 24 } else { 23 }] = kind.to_string();
            if let Some(e) = embedded {
                let (src, dst) = if e.protocol == Some(6) {
                    (9, 10)
                } else {
                    (11, 12)
                };
                if let Some(p) = e.src_port {
                    actual[src] = p.to_string();
                }
                if let Some(p) = e.dst_port {
                    actual[dst] = p.to_string();
                }
            }
        }
        _ => {}
    }
}
