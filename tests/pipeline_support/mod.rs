//! Synthetic inputs and file helpers for pipeline checks.
//! Assertions stay in `tests/pipeline`; JSON syntax checks reuse `log_support`.
//! Read `tcp` for test packets and `configured` for optional logging.
//! Ports select the receiving service inside an IP host.

pub(crate) mod proc;

pub(crate) use crate::log_support::{START, TestDir, Value, number, packets, parse, string};
use netmon::capture::{LinkType, RawPacket};
use netmon::pipeline::{Options, Pipeline};
use std::{fs, path::Path, time::Duration};

/// Make a pipeline with no procfs access, optionally logging under a reserved test folder.
pub(crate) fn configured(base: Option<&TestDir>, started: Duration) -> Pipeline {
    Pipeline::new(options(base), started)
}

/// Select saved-capture policies, with packet logs enabled only when a folder is supplied.
pub(crate) fn options(base: Option<&TestDir>) -> Options {
    Options {
        log: base.map(|base| crate::log_support::options(base.path())),
        record: false,
        proc_root: None,
        alerts: netmon::alerts::Config::default(),
    }
}

/// Wrap a checked test payload in IPv4 with fixed 10.0.0.1/10.0.0.2 endpoints.
pub(crate) fn ip(number: u64, protocol: u8, reverse: bool, payload: &[u8]) -> RawPacket {
    let len = u16::try_from(payload.len() + 20).unwrap();
    let mut data = vec![0x45, 0];
    data.extend_from_slice(&len.to_be_bytes());
    data.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
    let addresses = if reverse {
        [10, 0, 0, 2, 10, 0, 0, 1]
    } else {
        [10, 0, 0, 1, 10, 0, 0, 2]
    };
    data.extend_from_slice(&addresses);
    data.extend_from_slice(payload);
    RawPacket {
        number,
        ts: Duration::from_millis(number),
        link: LinkType::RawIp,
        iface: 0,
        orig_len: u32::from(len),
        data,
    }
}

/// TCP with literal flags/data and 20-byte header; reverse swaps the supplied port pair.
pub(crate) fn tcp(
    number: u64,
    reverse: bool,
    ports: [u16; 2],
    flags: u8,
    payload: &[u8],
) -> RawPacket {
    let [src, dst] = if reverse { [ports[1], ports[0]] } else { ports };
    let mut data = src.to_be_bytes().to_vec();
    data.extend_from_slice(&dst.to_be_bytes());
    data.extend_from_slice(&100u32.to_be_bytes());
    data.extend_from_slice(&101u32.to_be_bytes());
    data.extend_from_slice(&[0x50, flags, 0x10, 0, 0, 0, 0, 0]);
    data.extend_from_slice(payload);
    ip(number, 6, reverse, &data)
}

/// Replace sequence/ACK numbers in a complete TCP test packet using checked slices.
pub(crate) fn sequence(mut raw: RawPacket, seq: u32, ack: u32) -> RawPacket {
    raw.data
        .get_mut(24..28)
        .unwrap()
        .copy_from_slice(&seq.to_be_bytes());
    raw.data
        .get_mut(28..32)
        .unwrap()
        .copy_from_slice(&ack.to_be_bytes());
    raw
}

/// Build UDP with a chosen destination port and fixed client port 50053.
pub(crate) fn udp(number: u64, destination: u16, reverse: bool, payload: &[u8]) -> RawPacket {
    let ports: [u16; 2] = if reverse {
        [destination, 50053]
    } else {
        [50053, destination]
    };
    let mut data = ports[0].to_be_bytes().to_vec();
    data.extend_from_slice(&ports[1].to_be_bytes());
    data.extend_from_slice(&u16::try_from(payload.len() + 8).unwrap().to_be_bytes());
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(payload);
    ip(number, 17, reverse, &data)
}

/// Build an A query/reply, allowing hostile literal characters in DNS labels.
/// A successful reply gives 10.0.0.2; failed replies contain no answer records.
pub(crate) fn dns(number: u64, response: bool, name: &str, rcode: u8) -> RawPacket {
    let mut data = vec![
        0,
        1,
        if response { 0x81 } else { 1 },
        if response { 0x80 | rcode } else { 0 },
        0,
        1,
        0,
        u8::from(response && rcode == 0),
        0,
        0,
        0,
        0,
    ];
    for label in name.as_bytes().split(|b| *b == b'.') {
        assert!(label.len() <= 63);
        data.push(u8::try_from(label.len()).unwrap());
        data.extend_from_slice(label);
    }
    data.extend_from_slice(&[0, 0, 1, 0, 1]);
    if response && rcode == 0 {
        data.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 2]);
    }
    udp(number, 53, response, &data)
}

/// Parse every nonempty JSON line independently of the production writer.
pub(crate) fn json_lines(dir: &Path, name: &str) -> Vec<Value> {
    fs::read_to_string(dir.join(name))
        .unwrap()
        .lines()
        .map(|line| parse(line).unwrap())
        .collect()
}

/// Validate Markdown table widths with escaped pipes excluded from delimiters.
pub(crate) fn check_tables(markdown: &str) {
    let mut expected = None;
    for line in markdown.lines() {
        if !line.starts_with('|') {
            expected = None;
            continue;
        }
        let mut slash = false;
        let mut cells = 0;
        for ch in line.chars() {
            if ch == '|' && !slash {
                cells += 1;
            }
            slash = ch == '\\' && !slash;
        }
        match expected {
            None => expected = Some(cells),
            Some(width) => assert_eq!(cells, width, "{line}"),
        }
    }
}

/// Compare only an owned golden file; blessing is opt-in for this test invocation.
pub(crate) fn golden(name: &str, actual: &str) {
    let path = Path::new("tests/golden").join(name);
    if std::env::var_os("NETMON_BLESS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        fs::write(&path, actual).unwrap();
    }
    assert_eq!(fs::read_to_string(path).unwrap(), actual);
}
