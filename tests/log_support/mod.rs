//! Shared test inputs for the logging integration checks.
//! Production encoding belongs to `netmon::log`; assertions live in `tests/log/`.
//! Read `TestDir` for file isolation, then `parse` for syntax validation.

use netmon::capture::{RawPacket, Reader};
use netmon::log::Options;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Fixed Unix timestamp for 2026-10-12 14:02:11.812 UTC, independent of wall time.
pub(crate) const START: Duration = Duration::new(1_791_813_731, 812_000_000);

/// Enables packet logs under a test folder while retaining the production defaults.
pub(crate) fn options(base: &Path) -> Options {
    Options {
        base: base.to_path_buf(),
        log_packets: true,
        ..Options::default()
    }
}

/// Resolves a checked-in synthetic capture name without creating or changing it.
pub(crate) fn fixture(name: &str) -> PathBuf {
    Path::new("tests/fixtures").join(name)
}

/// Reads all packets from a known fixture; malformed fixtures fail the test.
pub(crate) fn packets(name: &str) -> Vec<RawPacket> {
    Reader::open(&fixture(name))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// Builds an expected parsed string, preserving empty and non-ASCII values.
pub(crate) fn string(value: &str) -> Value {
    Value::String(value.into())
}
/// Builds an expected decimal token without losing large integer precision.
pub(crate) fn number(value: impl ToString) -> Value {
    Value::Number(value.to_string())
}

/// Owns a unique test folder under Cargo's temporary directory; drop removes it.
pub(crate) struct TestDir(PathBuf);

impl TestDir {
    /// Reserves a fresh folder without a wall clock, randomness, or global counter.
    /// An unexpected filesystem failure panics so it cannot silently skip assertions.
    pub(crate) fn new() -> Self {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base).unwrap();
        let mut suffix = 1u64;
        loop {
            let path = base.join(format!("log-tests-{}-{suffix}", std::process::id()));
            // Exclusive creation lets parallel tests reserve different folders;
            // reusing an existing folder could make one test consume another's output.
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    suffix = suffix.checked_add(1).expect("test folder suffix exhausted");
                }
                Err(error) => panic!("cannot create test folder: {error}"),
            }
        }
    }

    /// Borrows the reserved folder path for the lifetime of this owner.
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Parsed JSON values used to inspect writer output independently of its encoder.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Value {
    /// Keyed fields, with duplicate input keys retaining their last value.
    Object(BTreeMap<String, Value>),
    /// Values in their input order, including an empty list.
    Array(Vec<Value>),
    /// Decoded Unicode text after JSON escapes have been interpreted.
    String(String),
    /// Original number token, avoiding floating-point rounding in assertions.
    Number(String),
    /// A JSON Boolean literal.
    Bool(bool),
    /// A JSON null literal, distinct from a missing field.
    Null,
}

impl Value {
    /// Returns an object's named field; missing keys and non-objects give `None`.
    pub(crate) fn field(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(fields) => fields.get(key),
            _ => None,
        }
    }
}

/// Independent RFC 8259 syntax reader: rejects bad escapes, numbers, separators,
/// control characters and unpaired UTF-16 surrogates. Input must already be UTF-8.
/// Trailing non-whitespace input or nesting deeper than 64 gives an error.
pub(crate) fn parse(text: &str) -> Result<Value, &'static str> {
    let mut reader = JsonReader { text, pos: 0 };
    let value = reader.value(0)?;
    reader.whitespace();
    if reader.pos != text.len() {
        return Err("trailing input");
    }
    Ok(value)
}

struct JsonReader<'a> {
    text: &'a str,
    pos: usize,
}

impl JsonReader<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn need(&mut self, byte: u8) -> Result<(), &'static str> {
        if self.take(byte) {
            Ok(())
        } else {
            Err("missing delimiter")
        }
    }

    fn literal(&mut self, text: &str) -> Result<(), &'static str> {
        if self
            .text
            .get(self.pos..)
            .is_some_and(|tail| tail.starts_with(text))
        {
            self.pos += text.len();
            Ok(())
        } else {
            Err("invalid literal")
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, &'static str> {
        // Bound recursive stack use even if a test supplies adversarial nesting.
        if depth > 64 {
            return Err("nesting limit");
        }
        self.whitespace();
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                self.whitespace();
                let mut fields = BTreeMap::new();
                if self.take(b'}') {
                    return Ok(Value::Object(fields));
                }
                loop {
                    self.whitespace();
                    let key = self.string()?;
                    self.whitespace();
                    self.need(b':')?;
                    fields.insert(key, self.value(depth + 1)?);
                    self.whitespace();
                    if self.take(b'}') {
                        return Ok(Value::Object(fields));
                    }
                    self.need(b',')?;
                }
            }
            Some(b'[') => {
                self.pos += 1;
                self.whitespace();
                let mut values = Vec::new();
                if self.take(b']') {
                    return Ok(Value::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.whitespace();
                    if self.take(b']') {
                        return Ok(Value::Array(values));
                    }
                    self.need(b',')?;
                }
            }
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.number().map(Value::Number),
            _ => Err("invalid value"),
        }
    }

    fn string(&mut self) -> Result<String, &'static str> {
        self.need(b'"')?;
        let mut out = String::new();
        loop {
            let ch = self
                .text
                .get(self.pos..)
                .and_then(|tail| tail.chars().next())
                .ok_or("unfinished string")?;
            self.pos += ch.len_utf8();
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let escape = self.peek().ok_or("unfinished escape")?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex_quad()?;
                            // A supplementary Unicode character uses a high/low
                            // UTF-16 surrogate pair in JSON escapes (RFC 8259, 7).
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                self.need(b'\\')?;
                                self.need(b'u')?;
                                let second = self.hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err("invalid surrogate pair");
                                }
                                0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
                            } else {
                                first
                            };
                            out.push(char::from_u32(scalar).ok_or("invalid Unicode scalar")?);
                        }
                        _ => return Err("invalid escape"),
                    }
                }
                '\u{0000}'..='\u{001f}' => return Err("unescaped control"),
                _ => out.push(ch),
            }
        }
    }

    fn hex_quad(&mut self) -> Result<u32, &'static str> {
        let mut value = 0;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(byte @ b'0'..=b'9') => byte - b'0',
                Some(byte @ b'a'..=b'f') => byte - b'a' + 10,
                Some(byte @ b'A'..=b'F') => byte - b'A' + 10,
                _ => return Err("invalid hex escape"),
            };
            self.pos += 1;
            value = value * 16 + u32::from(digit);
        }
        Ok(value)
    }

    fn digits(&mut self) -> Result<(), &'static str> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == start {
            Err("missing digits")
        } else {
            Ok(())
        }
    }

    fn number(&mut self) -> Result<String, &'static str> {
        let start = self.pos;
        self.take(b'-');
        // RFC 8259, 6 allows a single zero but forbids leading zeros in numbers;
        // leaving extra digits unread makes the enclosing parser reject them.
        if !self.take(b'0') {
            self.digits()?;
        }
        if self.take(b'.') {
            self.digits()?;
        }
        if self.take(b'e') || self.take(b'E') {
            if !self.take(b'+') {
                self.take(b'-');
            }
            self.digits()?;
        }
        Ok(self
            .text
            .get(start..self.pos)
            .ok_or("invalid number range")?
            .into())
    }
}
