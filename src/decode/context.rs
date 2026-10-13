//! Builds a packet result while dispatching each recognised payload.
//! Checked reads belong to `view`; protocol layouts belong to decoders.
//! Start with `Context`.

// RFC 1122, section 1.1.3: each protocol header describes the next layer.
// +-------------+-----------+-----------+------------------+
// | Link header | IP header | TCP / UDP | Application data |
// +-------------+-----------+-----------+------------------+
use super::{Decoded, Detail, Field, FieldKey, Layer, Proto, Summary, View, ip, link, transport};
use crate::text;

/// Builds one result; layers and fields use clamped View ranges, and summary mode never evaluates field-value closures.
pub(crate) struct Context {
    /// Result being built; protocol parsers must explicitly mark incomplete data not covered by layer lengths.
    pub decoded: Decoded,
    /// Controls field-tree allocation while leaving summary computation active.
    pub detail: Detail,
}
impl Context {
    /// Starts an empty decode; `orig_len` is the reported wire length in bytes, not the captured length.
    pub(super) fn new(orig_len: u32, detail: Detail) -> Self {
        Self {
            detail,
            decoded: Decoded {
                layers: Vec::new(),
                truncated: false,
                summary: Summary {
                    proto: Proto::Data,
                    src: None,
                    dst: None,
                    ip_proto: None,
                    src_port: None,
                    dst_port: None,
                    tcp: None,
                    wire_len: orig_len,
                    app: None,
                    ether_type: None,
                    fragment_offset: None,
                    udp_payload_len: None,
                },
            },
        }
    }
    /// Starts a layer with a clamped absolute range and marks truncation when its declared byte length exceeds the view.
    pub fn layer(&mut self, proto: Proto, v: View<'_>, len: usize, line: String) -> Layer {
        if len > v.bytes.len() {
            self.decoded.truncated = true;
        }
        // A raw tail must not hide the last recognised protocol in the packet list.
        if proto != Proto::Data {
            self.decoded.summary.proto = proto;
        }
        Layer {
            proto,
            range: v.range(0, len),
            line,
            fields: Vec::new(),
        }
    }
    /// Adds a field only in full detail; `span` is a local (offset, byte length) and `num` is its optional numeric value.
    pub fn field(
        &self,
        fields: &mut Vec<Field>,
        key: FieldKey,
        v: View<'_>,
        span: (usize, usize),
        value: impl FnOnce() -> String,
        num: Option<u64>,
    ) {
        if self.detail == Detail::Full {
            fields.push(Field {
                key,
                value: value(),
                num,
                range: v.range(span.0, span.1),
                children: Vec::new(),
            });
        }
    }
    /// Adds a numeric field only when its value is present; offsets and lengths are local bytes.
    pub fn n(
        &self,
        fields: &mut Vec<Field>,
        key: FieldKey,
        v: View<'_>,
        off: usize,
        len: usize,
        n: Option<u64>,
    ) {
        if let Some(n) = n {
            self.field(fields, key, v, (off, len), || n.to_string(), Some(n));
        }
    }
    /// Adds captured bytes as hexadecimal in full detail; missing tail bytes clamp the field range.
    pub fn raw(&self, fields: &mut Vec<Field>, key: FieldKey, v: View<'_>, off: usize, len: usize) {
        let bytes = v.tail(off).limit(len).bytes;
        self.field(fields, key, v, (off, len), || text::hex(bytes), None);
    }
    /// Adds a raw-data layer for a nonempty view without replacing the most specific recognised summary protocol.
    pub fn data(&mut self, v: View<'_>) {
        if v.bytes.is_empty() {
            return;
        }
        let mut l = self.layer(
            Proto::Data,
            v,
            v.bytes.len(),
            format!("{} bytes", v.bytes.len()),
        );
        self.n(
            &mut l.fields,
            FieldKey::DataSize,
            v,
            0,
            v.bytes.len(),
            Some(v.bytes.len() as u64),
        );
        self.decoded.layers.push(l);
    }
    /// Dispatches by EtherType; unknown payload formats become a raw-data layer.
    pub fn network(&mut self, ether_type: u16, v: View<'_>) {
        self.decoded.summary.ether_type = Some(ether_type);
        match ether_type {
            0x0800 => ip::ipv4(self, v),
            0x86dd => ip::ipv6(self, v),
            0x0806 => link::arp(self, v),
            _ => self.data(v),
        }
    }
    /// Dispatches by IP protocol number; `wire_len` is the declared payload byte count from the IP header.
    pub fn transport(&mut self, protocol: u8, v: View<'_>, wire_len: u32) {
        self.decoded.summary.ip_proto = Some(protocol);
        match protocol {
            6 => transport::tcp(self, v, wire_len),
            17 => transport::udp(self, v),
            1 => ip::icmp(self, v, false),
            58 => ip::icmp(self, v, true),
            _ => self.data(v),
        }
    }
}
