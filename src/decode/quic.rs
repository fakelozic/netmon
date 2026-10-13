//! Recognises visible QUIC headers without decrypting their payload.
//! UDP framing belongs to `transport`; wording belongs to `crate::explain`.
//! Start with `quic`.

// RFC 9000 QUIC long/short headers; RFC 9369 QUIC version 2.
// +--------+--------------------+----------+----------------------------+
// |1 F TT..| Version 32         | DCID len | Destination id ...         |
// +--------+--------------------+----------+----------------------------+
// | SCID len | Source id ... | Type-specific fields, encrypted data ... |
// +-------------------------------------------------------------------+
// Short: |0 1 ...| Destination id ... | Protected packet number/data ...|
use super::{AppInfo, Context, FieldKey as K, Proto, View};
/// Recognises visible QUIC headers; short-header detection also requires port 443 and does not decrypt contents.
pub(super) fn quic(c: &mut Context, v: View<'_>, port443: bool) -> bool {
    // QUIC runs inside UDP and hides application data; only visible header facts are decoded (RFC 9000, section 17).
    let first = v.u8(0).unwrap_or(0);
    let long = first & 0x80 != 0;
    let version = v.u32(1);
    if long {
        if !matches!(version, Some(0 | 1 | 0x6b3343cf)) {
            return false;
        }
    } else if !port443 || first & 0x40 == 0 {
        return false;
    }
    let packet_type = if long {
        // QUIC v2 rotates the long-header packet type assignments (RFC 9369, section 3.2).
        if version == Some(0x6b3343cf) {
            ((first >> 4) & 3).wrapping_add(3) & 3
        } else {
            (first >> 4) & 3
        }
    } else {
        4
    };
    let mut l = c.layer(
        Proto::Quic,
        v,
        if long { 7 } else { 1 },
        if long {
            format!(
                "long=true version={:08x} type={packet_type}",
                version.unwrap_or(0)
            )
        } else {
            "short header".into()
        },
    );
    c.n(&mut l.fields, K::QuicForm, v, 0, 1, Some(u64::from(long)));
    let mut off = 1usize;
    if long {
        c.n(
            &mut l.fields,
            K::QuicType,
            v,
            0,
            1,
            Some(u64::from(packet_type)),
        );
        if let Some(n) = version {
            c.field(
                &mut l.fields,
                K::QuicVersion,
                v,
                (1, 4),
                || format!("0x{n:08x}"),
                Some(u64::from(n)),
            );
        }
        off = connection_ids(c, &mut l.fields, v);
    }
    l.range = v.range(0, off);
    c.decoded.summary.app = Some(AppInfo::Quic {
        long,
        version: if long { version } else { None },
        packet_type,
        bytes: v.bytes.len() as u32,
    });
    c.decoded.layers.push(l);
    c.data(v.tail(off));
    true
}
fn connection_ids(c: &mut Context, fields: &mut Vec<super::Field>, v: View<'_>) -> usize {
    let mut off = 5usize;
    for (length_key, id_key) in [(K::QuicDstLen, K::QuicDstId), (K::QuicSrcLen, K::QuicSrcId)] {
        let Some(len) = v.u8(off) else {
            c.decoded.truncated = true;
            break;
        };
        let len = usize::from(len);
        c.n(fields, length_key, v, off, 1, Some(len as u64));
        off = off.saturating_add(1);
        c.raw(fields, id_key, v, off, len);
        off = off.saturating_add(len);
        if off > v.bytes.len() {
            c.decoded.truncated = true;
            break;
        }
    }
    off
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_and_detection_limits() {
        let b = [0xc0, 0, 0, 0, 1, 2, 1, 2, 1, 3, 0, 0];
        let mut c = Context::new(12, super::super::Detail::Full);
        assert!(quic(&mut c, View { bytes: &b, base: 0 }, false));
        assert!(!c.decoded.truncated);
        assert!(matches!(
            c.decoded.summary.app,
            Some(AppInfo::Quic {
                packet_type: 0,
                version: Some(1),
                ..
            })
        ));
        let b = [0xc0, 0, 0, 0, 9, 0, 0];
        assert!(!quic(&mut c, View { bytes: &b, base: 0 }, true));
        assert!(!quic(
            &mut c,
            View {
                bytes: &[0x40],
                base: 0
            },
            false
        ));
        assert!(quic(
            &mut c,
            View {
                bytes: &[0x40],
                base: 0
            },
            true
        ));
    }
}
