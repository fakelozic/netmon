//! Reads DNS labels and bounded compression-pointer chains.
//! Message sections belong to `super`; record values belong to `super::rdata`.
//! Start with `name`.

// RFC 1035, sections 3.1 and 4.1.4: a name can reuse earlier labels by pointer.
// +------------------+----------------------+
// | Length 8 | Label bytes ... | 0          |
// +------------------+----------------------+
// | 11 | Pointer offset 14                 |
// +----------------------------------------+
use crate::decode::{Context, Field, FieldKey as K, View};
use crate::text;

/// A sanitised DNS name plus the local cursor after its encoded representation; incomplete names have `complete == false`.
pub(super) struct Name {
    /// Sanitised dotted labels; an empty string can be an incomplete name, while a complete root is a dot.
    pub(super) text: String,
    /// Local byte offset after the name encoding before following compression pointers.
    pub(super) end: usize,
    /// True only when decompression reaches a terminating zero within its hard limits.
    pub(super) complete: bool,
}
/// Decompresses a DNS name at a local byte offset; pointers refer to the whole message view and loops are bounded.
pub(super) fn name(v: View<'_>, start: usize) -> Name {
    let mut pos = start;
    let mut end = start;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut bytes = 0usize;
    // Pointers can cycle without consuming label bytes; a 128-step cap makes that malformed input terminate.
    for _ in 0..128 {
        let Some(len) = v.u8(pos) else {
            break;
        };
        if len == 0 {
            if !jumped {
                end = pos.saturating_add(1);
            }
            return Name {
                text: if labels.is_empty() {
                    ".".into()
                } else {
                    labels.join(".")
                },
                end,
                complete: true,
            };
        }
        if len & 0xc0 == 0xc0 {
            let Some(pointer) = v.u16(pos) else {
                break;
            };
            // After a pointer, the caller resumes after its two encoded bytes, not after the pointed-to labels (RFC 1035, section 4.1.4).
            if !jumped {
                end = pos.saturating_add(2);
                jumped = true;
            }
            pos = usize::from(pointer & 0x3fff);
            continue;
        }
        if len > 63 {
            break;
        }
        pos = pos.saturating_add(1);
        let Some(label) = v.get(pos, usize::from(len)) else {
            break;
        };
        bytes = bytes.saturating_add(label.len()).saturating_add(1);
        // DNS names are limited to 255 encoded octets; labels are at most 63 (RFC 1035, section 2.3.4).
        if bytes > 255 {
            break;
        }
        labels.push(text::sanitise(label));
        pos = pos.saturating_add(usize::from(len));
        if !jumped {
            end = pos;
        }
    }
    Name {
        text: labels.join("."),
        end: end.min(v.bytes.len()),
        complete: false,
    }
}

/// Reads a DNS name at a local offset and adds its captured encoding range, marking incomplete decompression truncated.
pub(super) fn name_field(
    c: &mut Context,
    fields: &mut Vec<Field>,
    key: K,
    v: View<'_>,
    off: usize,
) -> Name {
    let n = name(v, off);
    if !n.complete {
        c.decoded.truncated = true;
    }
    c.field(
        fields,
        key,
        v,
        (off, n.end.saturating_sub(off)),
        || n.text.clone(),
        None,
    );
    n
}
