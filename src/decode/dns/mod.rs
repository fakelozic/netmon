//! Decodes DNS message sections into question and answer facts.
//! Name decompression belongs to `name`; record values belong to `rdata`.
//! Start with `dns`.

// RFC 1035 DNS, RFC 3596 AAAA, RFC 2782 SRV, RFC 6891 OPT, RFC 6762 mDNS.
// +------------------------+------------------------+
// | ID 16                  | QR Opcode AA TC RD ... |
// +------------------------+------------------------+
// | Question count 16      | Answer count 16        |
// | Authority count 16     | Additional count 16    |
// +------------------------+------------------------+
// | Question: name ... | type 16 | class 16         |
// | Record: name ... | type 16 | class 16 | TTL 32   |
// |         data length 16 | data ...               |
// +-------------------------------------------------+
mod name;
mod rdata;
use super::{AppInfo, Context, Detail, DnsAnswer, FieldKey as K, Proto, View};
use name::name_field;
use rdata::record_data;

/// Reads DNS or multicast DNS, selected by `mdns`; record counts and name-pointer walks have hard limits.
pub(in crate::decode) fn dns(c: &mut Context, v: View<'_>, mdns: bool) {
    let flags = v.u16(2).unwrap_or(0);
    let mut l = c.layer(
        if mdns { Proto::Mdns } else { Proto::Dns },
        v,
        v.bytes.len().max(12),
        format!("id=0x{:04x} flags=0x{flags:04x}", v.u16(0).unwrap_or(0)),
    );
    header_flags(c, &mut l.fields, v, flags);
    let counts = [
        v.u16(4).unwrap_or(0),
        v.u16(6).unwrap_or(0),
        v.u16(8).unwrap_or(0),
        v.u16(10).unwrap_or(0),
    ];
    for (i, key) in [
        K::DnsQuestions,
        K::DnsAnswers,
        K::DnsAuthorities,
        K::DnsAdditionals,
    ]
    .into_iter()
    .enumerate()
    {
        let off = 4usize.saturating_add(i.saturating_mul(2));
        c.n(&mut l.fields, key, v, off, 2, v.num(off, 2));
    }
    let (off, query_name, qtype) = questions(c, &mut l.fields, v, mdns, counts[0]);
    let answers = records(c, &mut l.fields, v, mdns, counts, off);
    if counts.iter().any(|n| *n > 256) {
        c.decoded.truncated = true;
    }
    c.decoded.summary.app = v.u16(2).map(|_| {
        if flags & 0x8000 == 0 {
            AppInfo::DnsQuery {
                id: v.u16(0).unwrap_or(0),
                name: query_name,
                qtype,
            }
        } else {
            AppInfo::DnsResponse {
                id: v.u16(0).unwrap_or(0),
                name: query_name,
                qtype,
                rcode: (flags & 15) as u8,
                answers,
            }
        }
    });
    c.decoded.layers.push(l);
}

fn questions(
    c: &mut Context,
    fields: &mut Vec<crate::decode::Field>,
    v: View<'_>,
    mdns: bool,
    count: u16,
) -> (usize, String, u16) {
    let mut off = 12usize;
    let mut query_name = String::new();
    let mut qtype = 0;
    // A 256-question cap bounds names and fields independently of the untrusted count.
    for i in 0..count.min(256) {
        let start = off;
        let mut children = Vec::new();
        let n = name_field(c, &mut children, K::DnsName, v, off);
        if !n.complete {
            break;
        }
        off = n.end;
        let ty = v.u16(off).unwrap_or(0);
        let class = v.u16(off.saturating_add(2));
        c.n(&mut children, K::DnsType, v, off, 2, v.num(off, 2));
        c.n(
            &mut children,
            K::DnsClass,
            v,
            off.saturating_add(2),
            2,
            class.map(|n| u64::from(if mdns { n & 0x7fff } else { n })),
        );
        if mdns {
            c.n(
                &mut children,
                K::DnsUnicast,
                v,
                off.saturating_add(2),
                2,
                class.map(|n| u64::from(n >> 15)),
            );
        }
        if i == 0 {
            query_name = n.text.clone();
            qtype = ty;
        }
        off = off.saturating_add(4);
        c.field(
            fields,
            K::DnsQuestion,
            v,
            (start, off.saturating_sub(start)),
            || n.text,
            None,
        );
        if c.detail == Detail::Full
            && let Some(f) = fields.last_mut()
        {
            f.children = children;
        }
        if off > v.bytes.len() {
            c.decoded.truncated = true;
            break;
        }
    }
    (off, query_name, qtype)
}

fn records(
    c: &mut Context,
    fields: &mut Vec<crate::decode::Field>,
    v: View<'_>,
    mdns: bool,
    counts: [u16; 4],
    mut off: usize,
) -> Vec<DnsAnswer> {
    let mut answers = Vec::new();
    for (section, count) in counts.into_iter().enumerate().skip(1) {
        // Each record section has its own 256-record cap, bounding summary answers and field trees.
        for _ in 0..count.min(256) {
            if off >= v.bytes.len() {
                c.decoded.truncated = true;
                break;
            }
            let start = off;
            let mut children = Vec::new();
            let n = name_field(c, &mut children, K::DnsName, v, off);
            if !n.complete {
                break;
            }
            off = n.end;
            let (ty, class, ttl) = record_fields(c, &mut children, v, mdns, off);
            let Some(len) = v.u16(off.saturating_add(8)) else {
                c.decoded.truncated = true;
                break;
            };
            let data_start = off.saturating_add(10);
            let data_end = data_start.saturating_add(usize::from(len));
            if data_end > v.bytes.len() {
                c.decoded.truncated = true;
            }
            let value = record_data(
                c,
                &mut children,
                v,
                data_start,
                usize::from(len),
                (ty, class.unwrap_or(0), ttl),
            );
            if section == 1 {
                answers.push(DnsAnswer {
                    name: n.text.clone(),
                    rr_type: ty,
                    value: value.clone(),
                    ttl,
                });
            }
            c.field(
                fields,
                K::DnsRecord,
                v,
                (start, data_end.saturating_sub(start)),
                || format!("{} type={ty} {value}", n.text),
                Some(section as u64),
            );
            if c.detail == Detail::Full
                && let Some(f) = fields.last_mut()
            {
                f.children = children;
            }
            off = data_end;
            if off > v.bytes.len() {
                break;
            }
        }
    }
    answers
}

fn record_fields(
    c: &Context,
    children: &mut Vec<crate::decode::Field>,
    v: View<'_>,
    mdns: bool,
    off: usize,
) -> (u16, Option<u16>, u32) {
    let ty = v.u16(off).unwrap_or(0);
    let class = v.u16(off.saturating_add(2));
    let ttl = v.u32(off.saturating_add(4)).unwrap_or(0);
    c.n(children, K::DnsType, v, off, 2, v.num(off, 2));
    if ty != 41 {
        c.n(
            children,
            K::DnsClass,
            v,
            off.saturating_add(2),
            2,
            class.map(|n| u64::from(if mdns { n & 0x7fff } else { n })),
        );
        c.n(
            children,
            K::DnsTtl,
            v,
            off.saturating_add(4),
            4,
            v.num(off.saturating_add(4), 4),
        );
    }
    if mdns && ty != 41 {
        c.n(
            children,
            K::DnsCacheFlush,
            v,
            off.saturating_add(2),
            2,
            class.map(|n| u64::from(n >> 15)),
        );
    }
    (ty, class, ttl)
}

fn header_flags(c: &Context, fields: &mut Vec<super::Field>, v: View<'_>, flags: u16) {
    if let Some(n) = v.u16(0) {
        c.field(
            fields,
            K::DnsId,
            v,
            (0, 2),
            || format!("0x{n:04x}"),
            Some(u64::from(n)),
        );
    }
    // Opcode and response code occupy multiple bits; only named control bits go in this list (RFC 1035, section 4.1.1).
    if let Some(n) = v.u16(2) {
        let names = [
            (0x8000, "QR"),
            (0x0400, "AA"),
            (0x0200, "TC"),
            (0x0100, "RD"),
            (0x0080, "RA"),
            (0x0020, "AD"),
            (0x0010, "CD"),
        ]
        .into_iter()
        .filter_map(|(bit, name)| (n & bit != 0).then_some(name))
        .collect::<Vec<_>>()
        .join(", ");
        c.field(
            fields,
            K::DnsFlags,
            v,
            (2, 2),
            || format!("0x{n:04x} [{names}]"),
            Some(u64::from(n)),
        );
    }
    if c.detail == Detail::Full
        && let Some(f) = fields.last_mut()
        && f.key == K::DnsFlags
    {
        for (key, shift, mask) in [
            (K::DnsResponse, 15, 1),
            (K::DnsOpcode, 11, 15),
            (K::DnsAuthoritative, 10, 1),
            (K::DnsTruncated, 9, 1),
            (K::DnsRecursionDesired, 8, 1),
            (K::DnsRecursionAvailable, 7, 1),
            (K::DnsRcode, 0, 15),
        ] {
            c.n(
                &mut f.children,
                key,
                v,
                2,
                2,
                Some(u64::from((flags >> shift) & mask)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::name::name;
    use super::*;
    #[test]
    fn pointer_loop_terminates() {
        let v = View {
            bytes: &[0xc0, 0],
            base: 0,
        };
        assert!(!name(v, 0).complete);
        let mut b = vec![0; 12];
        b[5] = 1;
        b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        let mut c = Context::new(b.len() as u32, Detail::Full);
        dns(&mut c, View { bytes: &b, base: 0 }, false);
        assert!(c.decoded.truncated);
    }
    #[test]
    fn cname_chain_mdns_and_sanitising() {
        let mut b = vec![0, 1, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        b.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        for (owner, ty, data) in [
            (12u16, 5u16, vec![1, b'b', 0]),
            (31, 5, vec![1, b'c', 0]),
            (46, 1, vec![1, 2, 3, 4]),
        ] {
            b.extend_from_slice(&(0xc000 | owner).to_be_bytes());
            b.extend_from_slice(&ty.to_be_bytes());
            b.extend_from_slice(&[0x80, 1, 0, 0, 0, 60]);
            b.extend_from_slice(&(data.len() as u16).to_be_bytes());
            b.extend_from_slice(&data);
        }
        // Explicit owner names avoid depending on offsets in this test's record layout.
        b[34] = 0xc0;
        b[35] = 31;
        b[49] = 0xc0;
        b[50] = 46;
        let mut c = Context::new(b.len() as u32, Detail::Full);
        dns(&mut c, View { bytes: &b, base: 0 }, true);
        assert!(
            matches!(&c.decoded.summary.app,Some(AppInfo::DnsResponse {answers,..}) if answers.len()==3 && answers[2].value=="1.2.3.4")
        );
        assert!(
            c.decoded.layers[0]
                .fields
                .iter()
                .any(|f| f.children.iter().any(|f| f.key == K::DnsCacheFlush))
        );
        b[13] = 0x1b;
        let mut c = Context::new(b.len() as u32, Detail::Full);
        dns(&mut c, View { bytes: &b, base: 0 }, false);
        assert!(
            matches!(c.decoded.summary.app,Some(AppInfo::DnsResponse {name,..}) if name=="\\x1B")
        );
    }
    #[test]
    fn record_data_formats() {
        let named = vec![4, b'm', b'a', b'i', b'l', 0];
        let mut mx = vec![0, 10];
        mx.extend_from_slice(&named);
        let mut srv = vec![0, 1, 0, 2, 1, 187];
        srv.extend_from_slice(&named);
        let mut soa = named.clone();
        soa.extend_from_slice(&named);
        for n in [1u32, 2, 3, 4, 5] {
            soa.extend_from_slice(&n.to_be_bytes());
        }
        for (ty, bytes, expected) in [
            (2, named.clone(), "mail"),
            (12, named, "mail"),
            (15, mx, "10 mail"),
            (16, vec![2, b'h', b'i', 1, 0x1b], "hi; \\x1B"),
            (33, srv, "1 2 443 mail"),
            (6, soa, "mail mail 1 2 3 4 5"),
            (28, std::net::Ipv6Addr::LOCALHOST.octets().to_vec(), "::1"),
            (41, vec![0, 12, 0, 1, 7], "udp=1232 version=0 flags=0x0000"),
        ] {
            let mut c = Context::new(bytes.len() as u32, Detail::Full);
            let mut fields = Vec::new();
            let value = record_data(
                &mut c,
                &mut fields,
                View {
                    bytes: &bytes,
                    base: 0,
                },
                0,
                bytes.len(),
                (ty, 1232, 0),
            );
            assert_eq!(value, expected);
            assert!(!c.decoded.truncated, "type {ty}");
        }
    }
}
