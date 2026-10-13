//! Reads saved pcap or pcapng records as a packet iterator.
//! Protocol decoding belongs to `decode`; output belongs to `render`.
//! Start with `Reader`.

use pcap_file::PcapError;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;

mod pcapng;
use std::fmt;
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::Path;
use std::time::Duration;

/// The link header format declared by the capture; unknown numeric types remain available in `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    /// Ethernet frames, including optional VLAN tags.
    Ethernet,
    /// Linux cooked capture version 1 metadata.
    LinuxSll,
    /// Linux cooked capture version 2 metadata.
    LinuxSll2,
    /// IP packet bytes without a link header.
    RawIp,
    /// Unrecognised capture link number; decoding keeps its bytes as raw data.
    Other(u32),
}
impl From<u32> for LinkType {
    fn from(n: u32) -> Self {
        match n {
            1 => Self::Ethernet,
            113 => Self::LinuxSll,
            276 => Self::LinuxSll2,
            101 => Self::RawIp,
            _ => Self::Other(n),
        }
    }
}

/// One captured packet with its original wire length and captured bytes, which may be shorter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawPacket {
    /// One-based packet index in this reader, saturating at u64::MAX.
    pub number: u64,
    /// Time since the Unix epoch; zero means no timestamp for a pcapng Simple Packet Block.
    pub ts: Duration,
    /// Format of the captured link header.
    pub link: LinkType,
    /// Zero-based interface index in the current pcapng section; classic pcap uses zero.
    pub iface: u32,
    /// Original wire length in bytes, which may exceed the captured data length.
    pub orig_len: u32,
    /// Captured packet bytes, including the declared link header.
    pub data: Vec<u8>,
}

/// A capture-format or I/O failure; the reader yields an error once and then ends.
#[derive(Debug)]
pub enum CaptureError {
    /// Missing or unrecognised capture magic bytes.
    NotACapture,
    /// Recognised format cut short in a header, block or packet.
    Truncated,
    /// An underlying reader or file-system error.
    Io(io::Error),
    /// A parser or capture-metadata failure with a diagnostic string.
    Invalid(String),
}
impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACapture => f.write_str("not a pcap or pcapng capture"),
            Self::Truncated => f.write_str("capture ends in the middle of a block or packet"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Invalid(s) => write!(f, "invalid capture: {s}"),
        }
    }
}
impl std::error::Error for CaptureError {}
impl From<PcapError> for CaptureError {
    fn from(e: PcapError) -> Self {
        match e {
            PcapError::IncompleteBuffer => Self::Truncated,
            PcapError::IoError(e) if e.kind() == io::ErrorKind::UnexpectedEof => Self::Truncated,
            PcapError::IoError(e) => Self::Io(e),
            e => Self::Invalid(e.to_string()),
        }
    }
}

type Input = Box<dyn Read + Send>;
enum Format {
    Pcap(PcapReader<Input>),
    Ng(PcapNgReader<Input>, usize),
    /// Recognised format cut short in a header, block or packet.
    Truncated,
}
/// A streaming pcap/pcapng iterator; packet numbers start at one and errors end iteration.
pub struct Reader {
    format: Format,
    number: u64,
    done: bool,
}
impl Reader {
    /// Opens a saved capture; recognised but incomplete headers yield a truncation error on iteration.
    pub fn open(path: &Path) -> Result<Self, CaptureError> {
        Self::from_stream(Box::new(File::open(path).map_err(CaptureError::Io)?))
    }
    /// Reads a boxed stream from its current position, detects its format and numbers packet records from one.
    pub fn from_stream(mut r: Input) -> Result<Self, CaptureError> {
        let mut magic = [0; 4];
        r.read_exact(&mut magic).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CaptureError::NotACapture
            } else {
                CaptureError::Io(e)
            }
        })?;
        let ng = magic == [0x0a, 0x0d, 0x0d, 0x0a];
        if !ng
            && !matches!(
                magic,
                [0xd4, 0xc3, 0xb2, 0xa1]
                    | [0xa1, 0xb2, 0xc3, 0xd4]
                    | [0x4d, 0x3c, 0xb2, 0xa1]
                    | [0xa1, 0xb2, 0x3c, 0x4d]
            )
        {
            return Err(CaptureError::NotACapture);
        }
        let input: Input = Box::new(Cursor::new(magic).chain(r));
        let initial = if ng {
            PcapNgReader::new(input)
                .map(|reader| Format::Ng(reader, 0))
                .map_err(CaptureError::from)
        } else {
            PcapReader::new(input)
                .map(Format::Pcap)
                .map_err(CaptureError::from)
        };
        // A recognised magic followed by an incomplete header is still a truncated
        // capture. Deliver that condition through the iterator, even with no packets.
        let format = match initial {
            Ok(format) => format,
            Err(CaptureError::Truncated) => Format::Truncated,
            Err(error) => return Err(error),
        };
        Ok(Self {
            format,
            number: 0,
            done: false,
        })
    }
}

// pcap-file 2.0 treats pcapng tick words as nanoseconds even when the interface
// declares another resolution. Recover the raw tick count and scale it here.
// The high resolution bit selects a power of two; otherwise it selects a power of ten.
fn timestamp(ticks: u128, resolution: u8) -> Duration {
    let units = if resolution & 0x80 == 0 {
        10u128.checked_pow(u32::from(resolution))
    } else {
        1u128.checked_shl(u32::from(resolution & 0x7f))
    };
    // At resolutions finer than u128 can express, a u64 tick count is below one nanosecond.
    let Some(units) = units else {
        return Duration::ZERO;
    };
    let seconds = ticks / units;
    let nanos = (ticks % units).saturating_mul(1_000_000_000) / units;
    Duration::new(seconds.min(u128::from(u64::MAX)) as u64, nanos as u32)
}

impl Iterator for Reader {
    type Item = Result<RawPacket, CaptureError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let result = match &mut self.format {
            Format::Truncated => Some(Err(CaptureError::Truncated)),
            Format::Pcap(r) => {
                let link = u32::from(r.header().datalink).into();
                r.next_packet().map(|p| {
                    p.map(|p| RawPacket {
                        number: 0,
                        ts: p.timestamp,
                        link,
                        iface: 0,
                        orig_len: p.orig_len,
                        data: p.data.into_owned(),
                    })
                    .map_err(CaptureError::from)
                })
            }
            Format::Ng(r, metadata) => pcapng::next_ng(r, metadata),
        };
        match result {
            Some(Ok(mut p)) => {
                self.number = self.number.saturating_add(1);
                p.number = self.number;
                Some(Ok(p))
            }
            Some(Err(e)) => {
                self.done = true;
                Some(Err(e))
            }
            None => {
                self.done = true;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn block(kind: u32, mut body: Vec<u8>) -> Vec<u8> {
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let len = (body.len() + 12) as u32;
        let mut b = kind.to_le_bytes().to_vec();
        b.extend_from_slice(&len.to_le_bytes());
        b.extend(body);
        b.extend_from_slice(&len.to_le_bytes());
        b
    }
    fn section() -> Vec<u8> {
        let mut b = 0x1a2b3c4du32.to_le_bytes().to_vec();
        b.extend_from_slice(&[1, 0, 0, 0]);
        b.extend_from_slice(&u64::MAX.to_le_bytes());
        block(0x0a0d0d0a, b)
    }
    fn interface(link: u16, resolution: Option<u8>) -> Vec<u8> {
        let mut b = link.to_le_bytes().to_vec();
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&65535u32.to_le_bytes());
        if let Some(r) = resolution {
            b.extend_from_slice(&[9, 0, 1, 0, r, 0, 0, 0, 0, 0, 0, 0]);
        }
        block(1, b)
    }
    fn packet(iface: u32, ticks: u64) -> Vec<u8> {
        let mut b = iface.to_le_bytes().to_vec();
        for n in [(ticks >> 32) as u32, ticks as u32, 4, 4] {
            b.extend_from_slice(&n.to_le_bytes());
        }
        b.extend_from_slice(&[1, 2, 3, 4]);
        block(6, b)
    }
    fn capture(resolution: Option<u8>, ticks: u64) -> Vec<u8> {
        let mut b = section();
        b.extend(interface(1, resolution));
        b.extend(packet(0, ticks));
        b.extend(packet(0, ticks));
        b
    }
    #[test]
    fn declared_resolution_and_default() {
        for (r, ticks) in [
            (None, 1_500_000),
            (Some(6), 1_500_000),
            (Some(9), 1_500_000_000),
            (Some(0x80 | 10), 1536),
        ] {
            let mut reader = Reader::from_stream(Box::new(Cursor::new(capture(r, ticks)))).unwrap();
            assert_eq!(
                reader.next().unwrap().unwrap().ts,
                Duration::from_millis(1500)
            );
        }
    }
    #[test]
    fn truncated_initial_header_and_legacy_packet_block() {
        let mut r =
            Reader::from_stream(Box::new(Cursor::new(vec![0x0a, 0x0d, 0x0d, 0x0a]))).unwrap();
        assert!(matches!(r.next(), Some(Err(CaptureError::Truncated))));
        assert!(r.next().is_none());
        let mut b = section();
        b.extend(interface(1, Some(9)));
        let mut body = vec![0, 0, 0, 0];
        for word in [1u32, 5, 3, 3] {
            body.extend_from_slice(&word.to_le_bytes());
        }
        body.extend_from_slice(&[1, 2, 3]);
        b.extend(block(2, body));
        let p = Reader::from_stream(Box::new(Cursor::new(b)))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(p.ts, Duration::from_nanos((1u64 << 32) | 5));
        assert_eq!(p.data, vec![1, 2, 3]);
    }
    struct OneByte {
        inner: Cursor<Vec<u8>>,
    }
    impl Read for OneByte {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = buf.len().min(1);
            self.inner.read(buf.get_mut(..len).unwrap_or_default())
        }
    }
    #[test]
    fn byte_at_a_time_and_truncated_once() {
        let bytes = capture(Some(9), 1234);
        let mut r = Reader::from_stream(Box::new(OneByte {
            inner: Cursor::new(bytes.clone()),
        }))
        .unwrap();
        assert_eq!(r.by_ref().collect::<Result<Vec<_>, _>>().unwrap().len(), 2);
        let mut bytes = bytes;
        bytes.truncate(bytes.len() - 3);
        let mut r = Reader::from_stream(Box::new(OneByte {
            inner: Cursor::new(bytes),
        }))
        .unwrap();
        assert!(r.next().unwrap().is_ok());
        assert!(matches!(r.next(), Some(Err(CaptureError::Truncated))));
        assert!(r.next().is_none());
        assert!(matches!(
            Reader::from_stream(Box::new(Cursor::new(vec![1, 2, 3, 4]))),
            Err(CaptureError::NotACapture)
        ));
    }
    #[test]
    fn interfaces_simple_packets_and_new_sections() {
        let mut bytes = section();
        bytes.extend(interface(1, None));
        bytes.extend(interface(276, Some(9)));
        bytes.extend(packet(1, 1_000_000_001));
        let mut simple = 3u32.to_le_bytes().to_vec();
        simple.extend_from_slice(&[1, 2, 3]);
        bytes.extend(block(3, simple));
        bytes.extend(section());
        bytes.extend(interface(113, None));
        bytes.extend(packet(0, 1_000_000));
        let p = Reader::from_stream(Box::new(Cursor::new(bytes)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(p[0].link, LinkType::LinuxSll2);
        assert_eq!(p[0].iface, 1);
        assert_eq!(p[0].ts, Duration::new(1, 1));
        assert_eq!(p[1].ts, Duration::ZERO);
        assert_eq!(p[1].data, vec![1, 2, 3]);
        assert_eq!(p[2].link, LinkType::LinuxSll);
        assert_eq!(p[2].number, 3);
    }
    #[test]
    fn classic_pcap_all_magic_numbers() {
        for little in [true, false] {
            for nanos in [true, false] {
                let word = |n: u32| {
                    if little {
                        n.to_le_bytes()
                    } else {
                        n.to_be_bytes()
                    }
                };
                let half = |n: u16| {
                    if little {
                        n.to_le_bytes()
                    } else {
                        n.to_be_bytes()
                    }
                };
                let mut b = word(if nanos { 0xa1b23c4d } else { 0xa1b2c3d4 }).to_vec();
                b.extend_from_slice(&half(2));
                b.extend_from_slice(&half(4));
                for n in [
                    0,
                    0,
                    65535,
                    101,
                    1,
                    if nanos { 500_000_000 } else { 500_000 },
                    3,
                    3,
                ] {
                    b.extend_from_slice(&word(n));
                }
                b.extend_from_slice(&[1, 2, 3]);
                let p = Reader::from_stream(Box::new(Cursor::new(b)))
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap();
                assert_eq!(p.ts, Duration::from_millis(1500));
                assert_eq!(p.link, LinkType::RawIp);
                assert_eq!(p.data, vec![1, 2, 3]);
            }
        }
    }
}
