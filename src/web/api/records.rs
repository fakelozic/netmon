//! Encodes the web contract from retained network evidence.
//! JSON escaping stays in `log::Json`; filtering stays in `packets`.
//! Read `row`, then `State::packet`, for compact and detailed packet replies.
//! Flow directions describe the starter, while packet directions describe this computer.

use super::state::State;
use crate::sys;
use crate::{
    alerts::{AlertKind, Severity},
    explain::{self, web as words},
    log::{Json, JsonValue as V, Recording},
};
use std::time::Duration;

/// A complete JSON object or an HTTP status and fixed explanatory sentence.
pub(super) type ResultJson = Result<String, (u16, &'static str)>;
/// Encodes an optional string as a value; None is explicit null.
pub(super) fn opt(value: Option<&str>) -> V {
    value.map_or_else(V::null, V::string)
}
/// Encodes an optional exact unsigned number; None is explicit null.
pub(super) fn opt_num(value: Option<u64>) -> V {
    value.map_or_else(V::null, V::number)
}
/// Seconds since the first packet, saturating backwards timestamps to zero.
pub(super) fn elapsed(time: Duration, first: Option<Duration>) -> f64 {
    time.saturating_sub(first.unwrap_or(time)).as_secs_f64()
}
/// Stable lowercase recording states from the web contract.
pub(super) fn recording(r: Recording) -> &'static str {
    match r {
        Recording::Off => "off",
        Recording::On => "on",
        Recording::Full => "full",
        Recording::Failed => "failed",
    }
}
/// Encodes the newest bounded alert history with lifetime-stable IDs.
pub(super) fn alerts(s: &State) -> String {
    let alerts: Vec<_> = s.pipeline.recent_alerts().collect();
    let start = s.pipeline.alert_count().saturating_sub(alerts.len() as u64);
    Json::object()
        .num("total", s.pipeline.alert_count())
        .value(
            "alerts",
            V::array(alerts.into_iter().enumerate().map(|(i, a)| {
                let kind = match a.kind {
                    AlertKind::PortScan => "port_scan",
                    AlertKind::CleartextCredentials => "cleartext_credentials",
                    AlertKind::ArpChange => "arp_change",
                    AlertKind::SuspiciousDns => "suspicious_dns",
                    AlertKind::UnexpectedInbound => "unexpected_inbound",
                };
                let severity = match a.severity {
                    Severity::Notice => "notice",
                    Severity::Warning => "warning",
                    Severity::Serious => "serious",
                };
                Json::object()
                    .num("id", start.saturating_add(i as u64).saturating_add(1))
                    .str("kind", kind)
                    .str("severity", severity)
                    .value("time", V::float(elapsed(a.ts, s.first)))
                    .value("clock", opt(sys::local_time(a.ts).as_deref()))
                    .str("title", &a.title)
                    .str("seen", &a.seen)
                    .str("why", a.why)
                    .str("next", a.next)
                    .num("packet", a.packet)
                    .num("first_packet", a.first_packet)
                    .value(
                        "subject",
                        opt(a.subject.map(|ip| ip.to_string()).as_deref()),
                    )
                    .into_value()
            })),
        )
        .finish()
}
/// Encodes glossary entries sorted by their exact term names.
pub(super) fn glossary() -> String {
    let mut terms: Vec<_> = explain::GLOSSARY.iter().collect();
    terms.sort_by_key(|(term, _)| *term);
    Json::object()
        .value(
            "terms",
            V::array(terms.into_iter().map(|(term, text)| {
                Json::object()
                    .str("term", term)
                    .str("text", text)
                    .into_value()
            })),
        )
        .finish()
}
/// Rejects unknown or repeated query keys before interpreting any values.
pub(super) fn keys(
    query: &[(String, String)],
    allowed: &[&str],
) -> Result<(), (u16, &'static str)> {
    for (i, (key, _)) in query.iter().enumerate() {
        if !allowed.contains(&key.as_str())
            || query.iter().take(i).any(|(previous, _)| previous == key)
        {
            return Err((400, words::error(400)));
        }
    }
    Ok(())
}
/// Parses an optional nonnegative decimal query number; malformed values give 400.
pub(super) fn number(
    query: &[(String, String)],
    key: &str,
) -> Result<Option<u64>, (u16, &'static str)> {
    query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| decimal(v))
        .transpose()
}
fn decimal(value: &str) -> Result<u64, (u16, &'static str)> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err((400, words::error(400)));
    }
    value.parse().map_err(|_| (400, words::error(400)))
}
/// Parses a positive capture or conversation ID after the exact endpoint prefix.
pub(super) fn id(path: &str, prefix: &str) -> Result<u64, (u16, &'static str)> {
    let id = decimal(path.strip_prefix(prefix).unwrap_or_default())?;
    if id == 0 {
        Err((400, words::error(400)))
    } else {
        Ok(id)
    }
}
