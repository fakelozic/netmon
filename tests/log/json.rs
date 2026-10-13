//! Check JSON escaping against an independent syntax reader.
//! Session output checks live in `session.rs`; calendar checks live in `clock.rs`.
//! Start with `json_escapes_every_control_and_preserves_unicode`.

use crate::log_support::{Value, number, parse, string};
use netmon::log::Json;

#[test]
fn json_escapes_every_control_and_preserves_unicode() {
    // Exercise every forbidden raw control, so a missing escape cannot hide
    // behind the more familiar newline and tab cases (RFC 8259, 7).
    let controls: String = (0u8..32).map(char::from).collect();
    for value in ["", "\"\\", "café Ελληνικά 日本語 🦀", &controls] {
        let line = Json::object().str("key", value).str(value, "").finish();
        assert!(!line.bytes().any(|b| b < 0x20));
        let parsed = parse(&line).unwrap();
        assert_eq!(parsed.field("key"), Some(&string(value)));
        assert_eq!(parsed.field(value), Some(&string("")));
    }
    assert_eq!(
        Json::object().str("\n\"\\", "\n\r\t\0").finish(),
        "{\"\\n\\\"\\\\\":\"\\n\\r\\t\\u0000\"}"
    );
    assert_eq!(Json::object().finish(), "{}");
    assert_eq!(parse("{}").unwrap(), Value::Object(Default::default()));
}

#[test]
fn json_options_bools_and_number_extremes() {
    let line = Json::object()
        .num("zero", 0)
        .num("max", u64::MAX)
        .int("min", i64::MIN)
        .int("imax", i64::MAX)
        .int("negative", -1)
        .bool("yes", true)
        .bool("no", false)
        .opt_str("missing", None)
        .opt_num("also_missing", None)
        .opt_str("empty", Some(""))
        .opt_num("some", Some(42))
        .finish();
    let parsed = parse(&line).unwrap();
    // Compare decimal tokens, since a floating-point reader could round u64::MAX.
    for (key, value) in [
        ("zero", "0"),
        ("max", "18446744073709551615"),
        ("min", "-9223372036854775808"),
        ("imax", "9223372036854775807"),
        ("negative", "-1"),
        ("some", "42"),
    ] {
        assert_eq!(parsed.field(key), Some(&number(value)));
    }
    assert_eq!(parsed.field("yes"), Some(&Value::Bool(true)));
    assert_eq!(parsed.field("no"), Some(&Value::Bool(false)));
    assert_eq!(parsed.field("empty"), Some(&string("")));
    assert_eq!(parsed.field("missing"), None);
    assert_eq!(parsed.field("also_missing"), None);
}

#[test]
fn independent_json_reader_rejects_invalid_rfc8259_syntax() {
    // Negative cases check the oracle itself: a permissive reader could falsely
    // certify invalid writer output. Positive cases prevent rejection of everything.
    for invalid in [
        "",
        "{",
        "{\"a\":1,}",
        "[1,]",
        "{a:1}",
        "{\"a\" 1}",
        "01",
        "-01",
        "1.",
        "1e",
        "+1",
        "NaN",
        "Infinity",
        "true false",
        "\"\\x20\"",
        "\"\\u12G4\"",
        "\"\\uD800\"",
        "\"\\uDC00\"",
        "\"\\uD800\\u0041\"",
        "\"raw\nline\"",
        "\"\0\"",
        "\u{000b}null",
    ] {
        assert!(parse(invalid).is_err(), "accepted {invalid:?}");
    }
    for valid in [
        "[]",
        " [null,true,false,{},\"a\\/b\",-0,1.2e-3] \n",
        "\"\\uD83E\\uDD80\"",
        "1E+20",
    ] {
        assert!(parse(valid).is_ok(), "rejected {valid:?}");
    }
}
