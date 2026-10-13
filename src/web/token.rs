//! Creates the local web session's random access token.
//! HTTP header checks belong to `routing`; this module compares candidate secrets.
//! Read `Token::generate` first. The token is never derived from clocks or counters.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};

/// A 128-bit session secret, displayed as exactly 32 lowercase hexadecimal digits.
/// Cloning keeps the same secret; generating again reads fresh operating-system bytes.
#[derive(Clone)]
pub struct Token([u8; 32]);

impl Token {
    /// Reads all 16 bytes from `/dev/urandom`, failing without a weaker fallback.
    pub fn generate() -> io::Result<Token> {
        let mut bytes = [0; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("{}: {error}", crate::explain::web::TOKEN_ERROR),
                )
            })?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = [0; 32];
        for (pair, byte) in encoded.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
            *pair = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]];
        }
        Ok(Self(encoded))
    }

    /// Compares a lowercase hex candidate with a fixed 32-byte comparison loop.
    /// Missing and extra bytes fail; the loop never stops at the first difference.
    pub fn matches(&self, candidate: &str) -> bool {
        let candidate = candidate.as_bytes();
        let mut difference = candidate.len() ^ 32;
        for (index, expected) in self.0.iter().enumerate() {
            let supplied = candidate.get(index).copied().unwrap_or(0);
            // Pre-encoding avoids secret-dependent table lookups in comparison.
            // Combine every difference before deciding, so a shared prefix is not exposed.
            difference |= usize::from(expected ^ supplied);
        }
        difference == 0
    }
}

impl fmt::Display for Token {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(out, "{}", char::from(*byte))?;
        }
        Ok(())
    }
}
