//! Encode single-line JSON objects for callers that supply finished log values.
//! Text sanitising belongs to `crate::text`; callers remove secrets.
//! Disk writes belong to `session`. Read `Json::object` first.

use std::fmt::Write as _;

/// An RFC 8259 object builder with scalar fields and nested encoded values.
/// Escaping preserves UTF-8, unlike terminal sanitising. Callers must remove
/// secrets themselves and avoid duplicate keys when consumers require unique names.
pub struct Json {
    text: String,
    first: bool,
}

/// A complete JSON value produced by this encoder; raw JSON cannot be injected.
pub struct JsonValue(String);

impl JsonValue {
    /// Encodes absence as the JSON null literal.
    pub fn null() -> Self {
        Self("null".into())
    }
    /// Encodes one UTF-8 string with the shared RFC 8259 escaping rules.
    pub fn string(value: &str) -> Self {
        let mut text = String::new();
        json_string(&mut text, value);
        Self(text)
    }
    /// Encodes exact unsigned decimal digits.
    pub fn number(value: u64) -> Self {
        Self(value.to_string())
    }
    /// Encodes a finite fractional number; nonfinite values become null.
    pub fn float(value: f64) -> Self {
        if value.is_finite() {
            Self(value.to_string())
        } else {
            Self::null()
        }
    }
    /// Encodes values in iterator order, including an empty array.
    pub fn array(values: impl IntoIterator<Item = Self>) -> Self {
        let mut text = String::from("[");
        for (i, value) in values.into_iter().enumerate() {
            if i != 0 {
                text.push(',');
            }
            text.push_str(&value.0);
        }
        text.push(']');
        Self(text)
    }
}

impl Json {
    /// Nests an object already produced by this writer within the crate.
    /// Outside input must never be supplied here.
    pub(crate) fn encoded_object(text: String) -> JsonValue {
        JsonValue(text)
    }
    /// Appends a nested value, including null, an object, or an array.
    pub fn value(mut self, key: &str, value: JsonValue) -> Self {
        self.key(key);
        self.text.push_str(&value.0);
        self
    }

    /// Closes this object for nesting inside another object or array.
    pub fn into_value(self) -> JsonValue {
        JsonValue(self.finish())
    }
    /// Starts an empty object; `finish` closes it, even when no fields are added.
    pub fn object() -> Json {
        Self {
            text: "{".into(),
            first: true,
        }
    }

    fn key(&mut self, key: &str) {
        if !self.first {
            self.text.push(',');
        }
        self.first = false;
        json_string(&mut self.text, key);
        self.text.push(':');
    }

    /// Appends an escaped string field, preserving an empty string as `""`.
    pub fn str(mut self, key: &str, value: &str) -> Json {
        self.key(key);
        json_string(&mut self.text, value);
        self
    }

    /// Appends an unsigned integer as exact decimal digits, including zero.
    pub fn num(mut self, key: &str, value: u64) -> Json {
        self.key(key);
        let _ = write!(self.text, "{value}");
        self
    }

    /// Appends a signed integer as exact decimal digits, including `i64::MIN`.
    pub fn int(mut self, key: &str, value: i64) -> Json {
        self.key(key);
        let _ = write!(self.text, "{value}");
        self
    }

    /// Appends a Boolean literal without quotes.
    pub fn bool(mut self, key: &str, value: bool) -> Json {
        self.key(key);
        self.text.push_str(if value { "true" } else { "false" });
        self
    }

    /// Appends a string when present; `None` omits the key rather than writing null.
    pub fn opt_str(self, key: &str, value: Option<&str>) -> Json {
        match value {
            Some(value) => self.str(key, value),
            None => self,
        }
    }

    /// Appends an unsigned integer when present; `None` omits the key.
    pub fn opt_num(self, key: &str, value: Option<u64>) -> Json {
        match value {
            Some(value) => self.num(key, value),
            None => self,
        }
    }

    /// Returns one complete object with no raw line breaks or trailing newline.
    pub fn finish(mut self) -> String {
        self.text.push('}');
        self.text
    }
}

fn json_string(out: &mut String, value: &str) {
    // Quotes, backslashes, and U+0000 through U+001F need escapes (RFC 8259, 7).
    // Escaping keys too prevents a supplied key from changing the object structure.
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // Encode HTML delimiters so logs contain no raw tags; JSON readers recover their values.
            '<' => out.push_str("\\u003C"),
            '>' => out.push_str("\\u003E"),
            '&' => out.push_str("\\u0026"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => {
                let _ = write!(out, "\\u00{:02X}", u32::from(ch));
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
}
