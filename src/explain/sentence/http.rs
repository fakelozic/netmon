//! Explains HTTP packet facts in one sentence.
//! Field definitions belong to `crate::explain::fields`; dispatch belongs to `super`.
//! Start with `request`.

/// Formats the decoded request facts without reading packet bytes.
pub(super) fn request(method: &str, target: &str, host: &Option<String>) -> String {
    format!(
        "Requests {method} {target}{}",
        host.as_ref()
            .map(|h| format!(" from {h}"))
            .unwrap_or_default()
    )
}

/// Formats the decoded response facts without reading packet bytes.
pub(super) fn response(status: &u16, reason: &str) -> String {
    format!("Replies {status} {reason}")
}
