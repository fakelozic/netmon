//! Parses a standalone TLS Client Hello for callers joining packet data.
//! Record decoding belongs to `records`; hello layouts belong to `hello`.
//! Start with `parse_client_hello`.

// RFC 5246, section 7.4.1.2; RFC 8446, section 4.1.2: a Client Hello offers encryption settings.
// +--------+-----------+------------------+
// | Type 8 | Length 24 | Hello body ...   |
// +--------+-----------+------------------+
mod extensions;
mod hello;
mod records;
#[cfg(test)]
/// Deterministic TLS packet builders shared by decoder tests.
pub(crate) mod tests;
use super::{ClientHello, Context, Detail, View};
use hello::hello;
pub(in crate::decode) use records::tls;

/// Accepts a handshake message beginning with type 1 and its three-byte length.
/// It also accepts an incomplete message; `complete` refers to that entire message.
/// A server name is retained only when all its declared bytes are captured.
pub fn parse_client_hello(data: &[u8]) -> ClientHello {
    let v = View {
        bytes: data,
        base: 0,
    };
    if v.u8(0) != Some(1) {
        return ClientHello::default();
    }
    let Some(len) = v.num(1, 3) else {
        return ClientHello::default();
    };
    let mut c = Context::new(data.len() as u32, Detail::Summary);
    let mut fields = Vec::new();
    let (mut hello, _, _) = hello(&mut c, &mut fields, v.tail(4).limit(len as usize), false);
    hello.complete = !c.decoded.truncated && len as usize <= data.len().saturating_sub(4);
    hello
}
