//! Reads DHCP address-configuration messages.
//! Transport framing belongs to `transport`; wording belongs to `crate::explain`.
//! Start with `dhcp`.

// RFC 2131 DHCPv4, RFC 2132 DHCP options (BOOTP layout from RFC 951).
// +--------+--------+--------+--------+--------------------------------+
// | op 8   | htype 8| hlen 8 | hops 8 | Transaction id 32              |
// +-----------------+-----------------+--------------------------------+
// | Seconds 16      | Flags 16        | Client IP 32                   |
// | Your IP 32      | Server IP 32    | Relay IP 32                    |
// +------------------------------------------------------------------+
// | Client hardware address 16B | Server name 64B | Boot filename 128B |
// +------------------------------------------------------------------+
// | Magic cookie 4B | Options: code 8, length 8, value ...             |
use super::{AppInfo, Context, Detail, FieldKey as K, Proto, View};
use crate::text;

/// Reads DHCPv4 configuration facts and at most 256 options, masking absent addresses as `None`.
pub(super) fn dhcp(c: &mut Context, v: View<'_>) {
    let mut l = c.layer(
        Proto::Dhcp,
        v,
        v.bytes.len().max(240),
        format!(
            "xid={}",
            v.u32(4)
                .map(|n| format!("0x{n:08x}"))
                .unwrap_or_else(|| "?".into())
        ),
    );
    fixed_numbers(c, &mut l.fields, v);
    for (key, off) in [
        (K::DhcpClientIp, 12),
        (K::DhcpYourIp, 16),
        (K::DhcpServerIp, 20),
        (K::DhcpRelayIp, 24),
    ] {
        if let Some(a) = v.v4(off) {
            c.field(&mut l.fields, key, v, (off, 4), || a.to_string(), None);
        }
    }
    if v.u8(2) == Some(6) {
        if let Some(mac) = v.array::<6>(28) {
            c.field(
                &mut l.fields,
                K::DhcpMac,
                v,
                (28, 6),
                || text::mac(&mac),
                None,
            );
        }
    } else {
        c.raw(
            &mut l.fields,
            K::DhcpMac,
            v,
            28,
            usize::from(v.u8(2).unwrap_or(0)).min(16),
        );
    }
    let parsed = options(c, v);
    if c.detail == Detail::Full {
        c.raw(
            &mut l.fields,
            K::DhcpOptions,
            v,
            240,
            v.bytes.len().saturating_sub(240),
        );
        if let Some(f) = l.fields.last_mut() {
            f.children = parsed.fields;
        }
    }
    c.decoded.summary.app = Some(AppInfo::Dhcp {
        message_type: parsed.message_type,
        offered: v.v4(16).filter(|a| !a.is_unspecified()),
        requested: parsed.requested,
        hostname: parsed.hostname,
    });
    c.decoded.layers.push(l);
}

#[derive(Default)]
struct Options {
    message_type: u8,
    requested: Option<std::net::Ipv4Addr>,
    hostname: Option<String>,
    fields: Vec<super::Field>,
}

fn options(c: &mut Context, v: View<'_>) -> Options {
    let mut parsed = Options::default();
    // The BOOTP cookie identifies DHCP options after the fixed header (RFC 2132, section 2).
    if v.get(236, 4) == Some(&[99, 130, 83, 99]) {
        let mut off = 240usize;
        // A 256-option work cap bounds even a payload made entirely of one-byte padding.
        for _ in 0..256 {
            let Some(code) = v.u8(off) else {
                break;
            };
            off = off.saturating_add(1);
            if code == 255 {
                break;
            }
            if code == 0 {
                continue;
            }
            let Some(len) = v.u8(off) else {
                c.decoded.truncated = true;
                break;
            };
            off = off.saturating_add(1);
            let len = usize::from(len);
            let data = v.tail(off).limit(len);
            if data.bytes.len() < len {
                c.decoded.truncated = true;
            }
            option(c, &mut parsed, data, code, len);
            off = off.saturating_add(len);
            if off > v.bytes.len() {
                break;
            }
        }
    }
    parsed
}

fn option(c: &mut Context, parsed: &mut Options, data: View<'_>, code: u8, len: usize) {
    match code {
        1 | 50 | 54 => {
            address_option(c, parsed, data, code, len);
        }
        3 | 6 => {
            address_list(c, &mut parsed.fields, data, code, len);
        }
        12 => {
            let s = text::sanitise(data.bytes);
            parsed.hostname = Some(s.clone());
            c.field(
                &mut parsed.fields,
                K::DhcpHostname,
                data,
                (0, len),
                || s,
                None,
            );
        }
        51 => c.n(
            &mut parsed.fields,
            K::DhcpLease,
            data,
            0,
            len,
            data.num(0, 4),
        ),
        53 => {
            parsed.message_type = data.u8(0).unwrap_or(0);
            c.n(
                &mut parsed.fields,
                K::DhcpMessage,
                data,
                0,
                len,
                data.num(0, 1),
            );
        }
        55 => c.field(
            &mut parsed.fields,
            K::DhcpParameters,
            data,
            (0, len),
            || {
                data.bytes
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            None,
        ),
        61 => c.field(
            &mut parsed.fields,
            K::DhcpClientId,
            data,
            (0, len),
            || {
                format!(
                    "type={} {}",
                    data.u8(0).unwrap_or(0),
                    text::hex(data.tail(1).bytes)
                )
            },
            None,
        ),
        _ => c.field(
            &mut parsed.fields,
            K::DhcpUnknown,
            data,
            (0, len),
            || format!("code={code} {}", text::hex(data.bytes)),
            Some(u64::from(code)),
        ),
    }
}

fn address_option(c: &mut Context, parsed: &mut Options, data: View<'_>, code: u8, len: usize) {
    if let Some(a) = data.v4(0) {
        if code == 50 {
            parsed.requested = Some(a);
        }
        c.field(
            &mut parsed.fields,
            match code {
                1 => K::DhcpSubnet,
                50 => K::DhcpRequested,
                _ => K::DhcpServer,
            },
            data,
            (0, len),
            || a.to_string(),
            None,
        );
    } else {
        c.raw(&mut parsed.fields, K::DhcpUnknown, data, 0, len);
    }
}

fn address_list(c: &Context, fields: &mut Vec<super::Field>, data: View<'_>, code: u8, len: usize) {
    let ips = data
        .bytes
        .as_chunks::<4>()
        .0
        .iter()
        .copied()
        .map(|a| std::net::Ipv4Addr::from(a).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    c.field(
        fields,
        if code == 3 {
            K::DhcpRouters
        } else {
            K::DhcpDns
        },
        data,
        (0, len),
        || ips,
        None,
    );
}

fn fixed_numbers(c: &Context, fields: &mut Vec<super::Field>, v: View<'_>) {
    for (key, off, n) in [
        (K::DhcpOp, 0, 1),
        (K::DhcpHardware, 1, 1),
        (K::DhcpHardwareLen, 2, 1),
        (K::DhcpHops, 3, 1),
        (K::DhcpId, 4, 4),
        (K::DhcpSeconds, 8, 2),
        (K::DhcpFlags, 10, 2),
    ] {
        if let Some(value) = v.num(off, n) {
            c.field(
                fields,
                key,
                v,
                (off, n),
                || match key {
                    K::DhcpId => format!("0x{value:08x}"),
                    K::DhcpFlags => format!(
                        "0x{value:04x} [{}]",
                        if value & 0x8000 != 0 { "BROADCAST" } else { "" }
                    ),
                    _ => value.to_string(),
                },
                Some(value),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discover_and_offer() {
        for message_type in [1, 2] {
            let mut b = vec![0; 240];
            b[0] = if message_type == 1 { 1 } else { 2 };
            b[1] = 1;
            b[2] = 6;
            b[16..20].copy_from_slice(&[192, 168, 1, 20]);
            b[236..240].copy_from_slice(&[99, 130, 83, 99]);
            b.extend_from_slice(&[
                53,
                1,
                message_type,
                12,
                3,
                b'p',
                b'c',
                b'1',
                50,
                4,
                192,
                168,
                1,
                20,
                255,
            ]);
            let mut c = Context::new(b.len() as u32, Detail::Full);
            dhcp(&mut c, View { bytes: &b, base: 0 });
            assert!(!c.decoded.truncated);
            assert!(
                matches!(c.decoded.summary.app,Some(AppInfo::Dhcp {message_type:m,hostname:Some(s),requested:Some(_),..}) if m==message_type && s=="pc1")
            );
        }
    }
}
