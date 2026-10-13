//! Holds TLS field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use crate::decode::FieldKey as K;
use crate::decode::{Decoded, Field};
use crate::explain::tls_version;

/// Closed set of TLS fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Record,
    ContentType,
    RecordVersion,
    RecordLen,
    Handshake,
    HandshakeType,
    HandshakeLen,
    HelloVersion,
    Random,
    Session,
    CipherCount,
    Ciphers,
    Cipher,
    Compression,
    Extensions,
    Extension,
    ServerName,
    Alpn,
    Versions,
    KeyShare,
    SupportedVersion,
    Encrypted,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 8446, section 5.
        Kind::Record => (
            "Record",
            "Wraps encryption setup messages or protected data in a block with a type and length, called a TLS record.",
            "",
        ),
        // RFC 8446, section 5.1.
        Kind::ContentType => (
            "Content type",
            "Tells the receiver how to read this TLS block, such as encryption setup, an error, or protected data.",
            "",
        ),
        // RFC 8446, section 5.1.
        Kind::RecordVersion => (
            "Record version",
            "Keeps older software able to recognise the TLS record format. This value alone does not tell you the negotiated TLS version.",
            "",
        ),
        // RFC 8446, section 5.1.
        Kind::RecordLen => (
            "Record length",
            "Tells the receiver how many bytes follow the five-byte TLS record header.",
            "",
        ),
        // RFC 8446, section 4.
        Kind::Handshake => (
            "Handshake message",
            "Helps the two computers agree on encryption settings and keys before sending protected data.",
            "",
        ),
        // RFC 8446, section 4.
        Kind::HandshakeType => (
            "Handshake type",
            "Tells the receiver which step of the encryption setup this message carries.",
            "",
        ),
        // RFC 8446, section 4.
        Kind::HandshakeLen => (
            "Handshake length",
            "Tells the receiver how many bytes belong to this encryption setup message, excluding its four-byte header.",
            "",
        ),
        // RFC 8446, section 4.1.2–4.1.3.
        Kind::HelloVersion => (
            "Hello version",
            "Keeps older software able to recognise the hello message. An extra setting can offer or select a newer TLS version.",
            "",
        ),
        // RFC 5246, section 7.4.1.2; RFC 8446, section 4.1.2.
        Kind::Random => (
            "Random",
            "Adds fresh random bytes to the encryption setup, helping keep separate connections from using the same keys.",
            "",
        ),
        // RFC 8446, section 4.1.2.
        Kind::Session => (
            "Session identifier",
            "Helps identify an earlier connection for reuse in older TLS versions. TLS 1.3 uses it for compatibility with older software.",
            "",
        ),
        // RFC 8446, section 4.1.2.
        Kind::CipherCount => (
            "Cipher suite count",
            "Tells the server how many encryption choices the client offers.",
            "",
        ),
        // RFC 8446, section 4.1.2.
        Kind::Ciphers => (
            "Cipher suites",
            "Lists the encryption choices the client offers so the server can pick one they both support.",
            "",
        ),
        // RFC 8446, section 4.1.3.
        Kind::Cipher => (
            "Cipher suite",
            "Names the encryption choice the server picked for this connection, called a cipher suite.",
            "",
        ),
        // RFC 8446, section 4.1.2–4.1.3.
        Kind::Compression => (
            "Compression",
            "Offers or selects a way to shrink data before encryption. TLS 1.3 requires no compression.",
            "",
        ),
        // RFC 8446, section 4.2.
        Kind::Extensions => (
            "Extensions",
            "Carries extra encryption settings, such as the requested site name and supported TLS versions.",
            "",
        ),
        // RFC 8446, section 4.2.
        Kind::Extension => (
            "Extension",
            "Identifies one extra encryption setting and how many bytes it occupies.",
            "",
        ),
        // RFC 6066, section 3.
        Kind::ServerName => (
            "Server name",
            "Tells the server which site the client wants, so sites sharing an IP address can be distinguished.",
            "The requested site name is visible to anyone who can capture this packet.",
        ),
        // RFC 7301, section 3.
        Kind::Alpn => (
            "Application protocol",
            "Offers or selects the rules for the data sent after encryption setup, such as HTTP/2 for web traffic.",
            "",
        ),
        // RFC 8446, section 4.2.1.
        Kind::Versions => (
            "Offered version",
            "Offers a TLS version the client supports so the server can choose one they both understand.",
            "",
        ),
        // RFC 8446, section 4.2.8.
        Kind::KeyShare => (
            "Key share group",
            "Names the method used to create a shared encryption secret without sending the secret itself.",
            "",
        ),
        // RFC 8446, section 4.2.1.
        Kind::SupportedVersion => (
            "Selected version",
            "Tells the client which TLS version the server selected.",
            "",
        ),
        // RFC 8446, section 5.2.
        Kind::Encrypted => (
            "Encrypted data",
            "Carries protected bytes whose contents require the connection's keys to read. They can include data or later encryption setup messages.",
            "Their contents cannot be read without the connection's keys.",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, field: &Field, packet: &Decoded) -> String {
    let n = field.num.unwrap_or(0);
    match key {
        Kind::RecordVersion | Kind::HelloVersion | Kind::Versions | Kind::SupportedVersion => {
            if matches!(field.key, K::TlsRecordVersion | K::TlsHelloVersion) {
                format!(
                    "The field encodes {}. An offered-version or selected-version extension may show a newer version.",
                    tls_version(n as u16)
                )
            } else if field.key == K::TlsVersions {
                format!(
                    "The client offers {}. The server still needs to choose a version.",
                    tls_version(n as u16)
                )
            } else {
                format!(
                    "The server selected {} for this connection.",
                    tls_version(n as u16)
                )
            }
        }
        Kind::ServerName => format!(
            "The client asks for {}. This selects a site but does not prove the server's identity.",
            field.value
        ),
        Kind::Alpn => {
            let name = match field.value.as_str() {
                "h2" => "HTTP/2 web traffic",
                "http/1.1" => "HTTP/1.1 web traffic",
                "h3" => "HTTP/3 web traffic",
                _ => return String::new(),
            };
            // Client ALPN is an offer, not the selected application protocol (RFC 7301, section 3.1).
            if matches!(
                packet.summary.app,
                Some(crate::decode::AppInfo::TlsClientHello(_))
            ) {
                format!("The client offers {name}. The server still needs to select a protocol.")
            } else {
                format!("This names {name} for use after encryption setup.")
            }
        }
        Kind::Record
        | Kind::ContentType
        | Kind::RecordLen
        | Kind::Handshake
        | Kind::HandshakeType
        | Kind::HandshakeLen
        | Kind::Random
        | Kind::Session
        | Kind::CipherCount
        | Kind::Ciphers
        | Kind::Cipher
        | Kind::Compression
        | Kind::Extensions
        | Kind::Extension
        | Kind::KeyShare
        | Kind::Encrypted => String::new(),
    }
}
