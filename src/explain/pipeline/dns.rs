//! Formats compact DNS reply evidence for session reports.
//! DNS decoding belongs to `decode`; timing and state stay in `pipeline`.
//! Read `dns_row` for address answers reached through a CNAME alias.

use super::{label, report_duration};
use crate::{
    decode::{AppInfo, Summary},
    flow::Note,
    log::markdown,
    names::Names,
};

/// Compact DNS reply facts; no raw payload or credentials are retained.
pub(crate) struct DnsRow {
    pub name: String,
    pub answer: String,
    pub asked: String,
    /// Matched elapsed time in human units, or `not seen` when its query was absent.
    pub time: String,
    pub result: String,
}

/// Build DNS reply facts; non-replies return None, unmatched timing says `not seen`.
pub(crate) fn dns_row(
    summary: &Summary,
    notes: &[Note],
    names: &Names,
    app: Option<&str>,
) -> Option<DnsRow> {
    let AppInfo::DnsResponse {
        name,
        answers,
        rcode,
        ..
    } = summary.app.as_ref()?
    else {
        return None;
    };
    let addresses: Vec<_> = answers
        .iter()
        .filter(|a| matches!(a.rr_type, 1 | 28))
        .collect();
    let answer = addresses
        .first()
        .copied()
        .or_else(|| answers.first())
        .map(|a| {
            let more = if addresses.is_empty() {
                answers.len()
            } else {
                addresses.len()
            }
            .saturating_sub(1);
            if more > 0 {
                format!("{} (and {more} more)", a.value)
            } else {
                a.value.clone()
            }
        })
        .unwrap_or_else(|| "no answer records".into());
    let answer = if let Some(alias) = answers
        .iter()
        .find(|a| a.rr_type == 5)
        .filter(|_| !addresses.is_empty())
    {
        format!("{answer} (via {})", alias.value)
    } else {
        answer
    };
    let time = notes
        .iter()
        .find_map(|n| {
            if let Note::DnsAnswerTime(t) = n {
                Some(report_duration(*t))
            } else {
                None
            }
        })
        .unwrap_or_else(|| "not seen".into());
    let result = match rcode {
        0 => "answered",
        1 => "format error (FORMERR)",
        2 => "server failed (SERVFAIL)",
        3 => "name does not exist (NXDOMAIN)",
        4 => "not implemented (NOTIMP)",
        5 => "refused (REFUSED)",
        _ => "lookup failed",
    };
    Some(DnsRow {
        name: name.clone(),
        answer,
        asked: app
            .map(str::to_owned)
            .unwrap_or_else(|| label(summary.dst.as_ref(), summary.dst_port, names)),
        time,
        result: result.into(),
    })
}

/// Describe who asked, the first answer, other-answer count and observed timing/result.
pub(crate) fn dns_event(row: &DnsRow) -> String {
    format!(
        "{} asked for {}: {} ({}, {})",
        row.asked, row.name, row.answer, row.time, row.result
    )
}

/// Escape DNS facts into five table cells.
pub(crate) fn dns_markdown(row: &DnsRow) -> String {
    format!(
        "| {} | {} | {} | {} | {} |\n",
        markdown::escape(&row.name),
        markdown::escape(&row.answer),
        markdown::escape(&row.asked),
        markdown::explanation(&row.time),
        markdown::escape(&row.result)
    )
}
