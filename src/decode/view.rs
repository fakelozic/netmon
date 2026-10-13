//! Provides checked reads within one captured byte window.
//! Result construction belongs to `context`; protocol rules belong to decoders.
//! Start with `View`.

// RFC 1122, section 1.1.3: each protocol header describes the next layer.
// +-------------+-----------+-----------+------------------+
// | Link header | IP header | TCP / UDP | Application data |
// +-------------+-----------+-----------+------------------+
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

/// A checked byte window: reads return `None` on missing bytes or offset overflow.
/// Local offsets become absolute, captured-byte ranges; tail and limit always clamp.
/// Construct the initial view from the captured packet with base zero.
#[derive(Clone, Copy)]
pub(crate) struct View<'a> {
    /// Captured bytes in this window; constructing subviews must keep them inside the original packet.
    pub bytes: &'a [u8],
    /// Absolute byte offset of this window in the original packet; subviews use saturating arithmetic.
    pub base: usize,
}
impl<'a> View<'a> {
    /// Returns all requested bytes at a local byte offset, or `None` if the end overflows or lies outside this view.
    pub fn get(self, off: usize, len: usize) -> Option<&'a [u8]> {
        self.bytes.get(off..off.checked_add(len)?)
    }
    /// Reads up to eight big-endian bytes at a local offset; zero bytes gives zero, larger or missing spans give `None`.
    pub fn num(self, off: usize, len: usize) -> Option<u64> {
        if len > 8 {
            return None;
        }
        Some(
            self.get(off, len)?
                .iter()
                .fold(0, |n, b| (n << 8) | u64::from(*b)),
        )
    }
    /// Reads one byte at a local offset, or `None` when absent.
    pub fn u8(self, off: usize) -> Option<u8> {
        self.num(off, 1).map(|n| n as u8)
    }
    /// Reads a big-endian 16-bit value at a local byte offset, or `None` when incomplete.
    pub fn u16(self, off: usize) -> Option<u16> {
        self.num(off, 2).map(|n| n as u16)
    }
    /// Reads a big-endian 32-bit value at a local byte offset, or `None` when incomplete.
    pub fn u32(self, off: usize) -> Option<u32> {
        self.num(off, 4).map(|n| n as u32)
    }
    /// Formats a complete big-endian value in base ten, or `?` when bytes are missing.
    pub fn display_num(self, off: usize, len: usize) -> String {
        self.num(off, len)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into())
    }
    /// Copies exactly N bytes at a local byte offset, or returns `None` for an incomplete span.
    pub fn array<const N: usize>(self, off: usize) -> Option<[u8; N]> {
        self.get(off, N)?.try_into().ok()
    }
    /// Returns the remaining bytes after a local offset, clamping an oversized offset to an empty view at its end.
    // Clamping an absent tail keeps its empty range at the captured end, not beyond it.
    pub fn tail(self, off: usize) -> Self {
        let start = off.min(self.bytes.len());
        Self {
            bytes: self.bytes.get(start..).unwrap_or_default(),
            base: self.base.saturating_add(start),
        }
    }
    /// Clamps this view to at most the requested byte length, keeping its absolute base.
    pub fn limit(self, len: usize) -> Self {
        Self {
            bytes: self
                .bytes
                .get(..len.min(self.bytes.len()))
                .unwrap_or_default(),
            base: self.base,
        }
    }
    /// Returns the captured portion of a local byte span as an absolute packet range; overflowing spans clamp at the view end.
    pub fn range(self, off: usize, len: usize) -> Range<usize> {
        let start = off.min(self.bytes.len());
        let end = off.saturating_add(len).min(self.bytes.len()).max(start);
        self.base.saturating_add(start)..self.base.saturating_add(end)
    }
    /// Reads the four bytes of an IPv4 address at a local offset, or `None` when incomplete.
    pub fn v4(self, off: usize) -> Option<Ipv4Addr> {
        self.array::<4>(off).map(Ipv4Addr::from)
    }
    /// Reads the sixteen bytes of an IPv6 address at a local offset, or `None` when incomplete.
    pub fn v6(self, off: usize) -> Option<Ipv6Addr> {
        self.array::<16>(off).map(Ipv6Addr::from)
    }
}
