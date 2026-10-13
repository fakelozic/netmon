//! Formats small protocol values and masks sensitive HTTP header values.
//! Protocol name tables belong to `tables`; packet sentences belong to `sentence`.
//! Start with `http_header_value`.

use crate::text::number;

/// Status used when an incomplete header cannot be checksum-verified.
pub const CHECKSUM_INCOMPLETE: &str = "not verified: header is incomplete";
/// Names the result of a completed checksum verification.
pub fn checksum_status(correct: bool) -> &'static str {
    if correct { "correct" } else { "incorrect" }
}
/// Formats an encrypted payload byte count; it reveals only size, never protected contents.
pub fn encrypted(n: usize) -> String {
    format!("encrypted, {}", byte_count(n))
}
/// Formats a byte count with thousands separators and singular or plural units.
pub fn byte_count(n: usize) -> String {
    count(n as u64, "byte")
}
/// Formats a count with thousands separators and the singular or plural unit supplied by the caller.
pub(super) fn count(n: u64, unit: &str) -> String {
    format!("{} {unit}{}", number(n), if n == 1 { "" } else { "s" })
}
/// Replacement for HTTP credential or cookie values.
pub const HIDDEN_HEADER: &str = "[hidden]";
/// Treats standard credentials/cookies and explicitly private extension names as secret.
/// Names mentioning passwords, secrets, tokens, cookies or API keys are hidden
/// conservatively; an unfamiliar private field must not bypass the standard list.
pub fn http_sensitive_header(name: &str) -> bool {
    [
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "Set-Cookie",
    ]
    .iter()
    .any(|s| name.eq_ignore_ascii_case(s))
        || ["password", "secret", "token", "cookie", "api-key", "apikey"]
            .iter()
            .any(|marker| name.to_ascii_lowercase().contains(marker))
}
/// Masks HTTP credentials and cookies; other values must already be sanitised by the caller.
pub fn http_header_value(name: &str, value: &str) -> String {
    if name.eq_ignore_ascii_case("Authorization")
        || name.eq_ignore_ascii_case("Proxy-Authorization")
    {
        let scheme = value.split_whitespace().next().unwrap_or("");
        // A scheme is a token, not the credentials. Without a separating space hide all of it.
        if value.contains(' ')
            && ["Basic", "Bearer", "Digest", "Negotiate"]
                .iter()
                .any(|known| scheme.eq_ignore_ascii_case(known))
        {
            format!("{scheme} [hidden]")
        } else {
            "[hidden]".into()
        }
    } else if http_sensitive_header(name) {
        "[hidden]".into()
    } else {
        value.into()
    }
}
/// Lists set TCP control bits in wire order; no set bits gives an empty string.
pub fn tcp_flags(flags: u16) -> String {
    [
        (0x100, "NS"),
        (128, "CWR"),
        (64, "ECE"),
        (32, "URG"),
        (16, "ACK"),
        (8, "PSH"),
        (4, "RST"),
        (2, "SYN"),
        (1, "FIN"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| if flags & bit != 0 { Some(name) } else { None })
    .collect::<Vec<_>>()
    .join(", ")
}
