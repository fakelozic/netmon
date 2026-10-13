//! Tests TLS hello completeness and record selection with synthetic bytes.
//! Parsing belongs to the parent TLS modules; no capture or network is used.
//! Start with `server_name_requires_every_declared_byte`.

// RFC 8446, section 4.1.2: the synthetic hello offers encryption settings.
// +--------+-----------+----------------------+
// | Type 8 | Length 24 | Client Hello ...     |
// +--------+-----------+----------------------+
use super::*;
use crate::decode::AppInfo;
use crate::decode::tls::tls;
/// Builds a deterministic complete Client Hello with a server name, application protocol and supported versions.
pub(crate) fn client_hello() -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    let mut ext = vec![0, 0, 0, 16, 0, 14, 0, 0, 11];
    ext.extend_from_slice(b"netmon.test");
    ext.extend_from_slice(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2', 0, 43, 0, 5, 4, 3, 4, 3, 3]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut h = vec![1, 0, 0, body.len() as u8];
    h.extend_from_slice(&body);
    h
}
#[test]
fn complete_and_partial_hello() {
    let b = client_hello();
    let h = parse_client_hello(&b);
    assert!(h.complete);
    assert_eq!(h.server_name.as_deref(), Some("netmon.test"));
    assert_eq!(h.alpn, vec!["h2"]);
    assert_eq!(h.versions, vec![0x304, 0x303]);
    let h = parse_client_hello(&b[..b.len() / 2]);
    assert!(!h.complete);
}
#[test]
fn server_name_requires_every_declared_byte() {
    let bytes = client_hello();
    let name = b"netmon.test";
    let start = bytes
        .windows(name.len())
        .position(|part| part == name)
        .unwrap();
    // Every prefix ending inside the name must withhold the identity.
    for end in start..start + name.len() {
        let hello = parse_client_hello(&bytes[..end]);
        assert_eq!(hello.server_name, None, "cut at name byte {}", end - start);
        assert!(!hello.complete, "cut at name byte {}", end - start);
    }
    // A complete name remains useful even if later extensions are absent.
    let hello = parse_client_hello(&bytes[..start + name.len()]);
    assert_eq!(hello.server_name.as_deref(), Some("netmon.test"));
    assert!(!hello.complete);
}
#[test]
fn several_records_prefer_hello_and_sum_encrypted_bytes() {
    let h = client_hello();
    let mut b = vec![23, 3, 3, 0, 3, 1, 2, 3, 22, 3, 3];
    b.extend_from_slice(&(h.len() as u16).to_be_bytes());
    b.extend_from_slice(&h);
    let mut c = Context::new(b.len() as u32, Detail::Full);
    assert!(tls(&mut c, View { bytes: &b, base: 0 }));
    assert!(matches!(
        c.decoded.summary.app,
        Some(AppInfo::TlsClientHello(_))
    ));
    assert_eq!(c.decoded.layers.len(), 2);
    let b = [23, 3, 3, 0, 2, 1, 2, 23, 3, 3, 0, 3, 3, 4, 5];
    let mut c = Context::new(15, Detail::Summary);
    tls(&mut c, View { bytes: &b, base: 0 });
    assert!(matches!(
        c.decoded.summary.app,
        Some(AppInfo::TlsRecords {
            encrypted_bytes: 5,
            ..
        })
    ));
}
