//! Human-readable wording for the packet pipeline.
//! State retention belongs to `pipeline`; Markdown safety belongs to `log::markdown`.
//! Read `heading` for a conversation event and `story_markdown` for exports.
//! A conversation joins packets exchanged between two IP endpoints.

use crate::alerts::{Alert, AlertKind, Severity};
use crate::decode::{Addr, Proto};
use crate::explain::{self, flows};
use crate::flow::{Endpoint, Flow};
use crate::log::{Json, markdown};
use crate::names::Names;
use crate::text;
use std::{fmt::Display, time::Duration};

/// Argument help for the headless capture example.
pub const HEADLESS_USAGE: &str =
    "Usage: headless <CAPTURE|-> [--log-dir DIR] [--record] [--log-packets] [--proc] [--quiet]";
/// Title of the session report.
pub(crate) const SUMMARY_TITLE: &str = "# netmon session summary\n\n";
/// Heading for observed alerts.
pub(crate) const ALERTS_TITLE: &str = "## Alerts\n\n";
/// Heading and fixed columns for the largest conversations.
pub(crate) const CONVERSATIONS_TITLE: &str = "## Conversations\n\n| Number | App | Remote host | Protocol | Duration | Up (payload bytes) | Down (payload bytes) | How it ended |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n";
/// Heading and fixed columns for recent DNS replies.
pub(crate) const DNS_TITLE: &str = "## DNS lookups\n\n| Name | Answer | Asked by | Time taken | Result |\n| --- | --- | --- | --- | --- |\n";
/// Heading for packet references with observed problems.
pub(crate) const PROBLEMS_TITLE: &str = "## Problems\n\n";
/// Heading for the session file inventory.
pub(crate) const FILES_TITLE: &str = "## Files in this folder\n\n";
/// Empty-section wording.
pub(crate) const NONE: &str = "None.\n\n";
/// Capture-end reason distinct from a protocol close or inactivity timeout.
pub(crate) const CAPTURE_ENDED: &str = "still open when the capture ended";

/// Format elapsed packet time using the same units as packet explanations.
pub(crate) fn report_duration(value: Duration) -> String {
    flows::duration(value)
}

/// Report fact labels in the required order.
pub(crate) const SUMMARY_FACT_LABELS: [&str; 8] = [
    "Started",
    "Ended",
    "Duration",
    "Packets",
    "Bytes",
    "Conversations",
    "DNS lookups",
    "Alerts",
];
/// End-time value while capture is running.
pub(crate) const IN_PROGRESS: &str = "capture in progress";
/// Label for the first retained logging error.
pub(crate) const LOGGING_LABEL: &str = "Logging";

/// Format time since the Unix epoch as UTC ISO 8601 with milliseconds.
pub(crate) fn timestamp(ts: Duration) -> String {
    let c = crate::log::utc_clock(ts);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second, c.millis
    )
}

/// Explain session creation failure after sanitising its error text.
pub(crate) fn session_problem(error: &dyn Display) -> String {
    format!(
        "Cannot create the log session: {}.",
        text::sanitise(error.to_string().as_bytes())
    )
}

/// Machine-readable transport name for tracked IP protocol numbers.
pub(crate) fn transport(protocol: u8) -> &'static str {
    match protocol {
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "icmp",
    }
}

/// Format a passive address label with a port; absent addresses become `?`.
pub(crate) fn label(addr: Option<&Addr>, port: Option<u16>, names: &Names) -> String {
    let ip = match addr {
        Some(Addr::V4(ip)) => Some((*ip).into()),
        Some(Addr::V6(ip)) => Some((*ip).into()),
        _ => None,
    };
    if let Some(ip) = ip {
        endpoint(Endpoint { addr: ip, port }, &names.label(&ip))
    } else if let Some(addr) = addr {
        text::address(addr)
    } else {
        "?".into()
    }
}

fn endpoint(e: Endpoint, name: &str) -> String {
    match e.port {
        Some(port) if e.addr.is_ipv6() && name == e.addr.to_string() => format!("[{name}]:{port}"),
        Some(port) => format!("{name}:{port}"),
        None => name.to_owned(),
    }
}

/// Return array index 0 or 1 for the known local side; ties use the starter.
pub(crate) fn local_side(flow: &Flow, names: &Names) -> usize {
    // When both/neither are local, the first sender is the only known orientation.
    usize::from(!names.is_local(&flow.endpoints[0].addr) && names.is_local(&flow.endpoints[1].addr))
}

/// Format the remote endpoint using the conversation name, DNS alias, or address.
pub(crate) fn remote_host(flow: &Flow, names: &Names) -> String {
    let remote = flow.endpoints[1 - local_side(flow, names)];
    let host = flow
        .server_name
        .as_deref()
        .or_else(|| names.name_of(&remote.addr));
    endpoint(remote, host.unwrap_or(&remote.addr.to_string()))
}

/// Use the remembered process name, or `unknown app` when no owner was observed.
pub(crate) fn app_name(app: Option<&str>) -> &str {
    app.unwrap_or("unknown app")
}

/// Describe the transport and highest observed application, including negotiated TLS.
pub(crate) fn protocol(flow: &Flow) -> String {
    let transport = transport(flow.ip_proto)
        .to_ascii_uppercase()
        .replace("ICMPV6", "ICMPv6");
    if let Some(version) = flow.tls_version {
        format!("{transport} + {}", explain::tls_version(version))
    } else if !flow
        .proto
        .name()
        .eq_ignore_ascii_case(self::transport(flow.ip_proto))
    {
        format!("{transport} + {}", flow.proto.name())
    } else {
        transport
    }
}

/// Describe a conversation opening from its app, remote endpoint and transport.
pub(crate) fn heading(flow: &Flow, app: Option<&str>, names: &Names) -> String {
    format!(
        "{} -> {} ({})",
        app_name(app),
        remote_host(flow, names),
        transport(flow.ip_proto)
            .to_ascii_uppercase()
            .replace("ICMPV6", "ICMPv6")
    )
}

/// Give the observed end state; capture end overrides the tracker inactivity state.
pub(crate) fn end(flow: &Flow, capture_ended: bool) -> String {
    if capture_ended && flow.ip_proto != 6 && matches!(flow.state, crate::flow::FlowState::Idle) {
        "finished".into()
    } else if capture_ended {
        CAPTURE_ENDED.into()
    } else {
        flows::flow_status(flow).replace(" · ", "; ")
    }
}

/// Describe captured duration and directional payload bytes at conversation end.
pub(crate) fn close(flow: &Flow, app: Option<&str>, names: &Names, capture_ended: bool) -> String {
    let local = local_side(flow, names);
    format!(
        "{}, {}, {} bytes up, {} bytes down, {}",
        heading(flow, app, names),
        report_duration(flow.last.saturating_sub(flow.first)),
        text::number(flow.payload_bytes[local]),
        text::number(flow.payload_bytes[1 - local]),
        end(flow, capture_ended)
    )
}

/// Encode finished conversation facts; absent app, host and TLS values are omitted.
pub(crate) fn flow_json(
    flow: &Flow,
    app: Option<&str>,
    pid: Option<u32>,
    names: &Names,
    capture_ended: bool,
) -> String {
    let local = local_side(flow, names);
    let remote = flow.endpoints[1 - local];
    let version = flow
        .tls_version
        .map(explain::tls_version)
        .map(|v| v.strip_prefix("TLS ").unwrap_or(&v).to_owned());
    let local_endpoint = flow.endpoints[local];
    let local_address = endpoint(local_endpoint, &local_endpoint.addr.to_string());
    let status = if capture_ended {
        end(flow, true)
    } else {
        flows::flow_status(flow)
    };
    Json::object()
        .str("start", &timestamp(flow.first))
        .num("dur_ms", millis(flow.last.saturating_sub(flow.first)))
        .opt_str("app", app)
        .opt_num("pid", pid.map(u64::from))
        .str("proto", transport(flow.ip_proto))
        .str("local", &local_address)
        .str("remote", &endpoint(remote, &remote.addr.to_string()))
        .opt_str(
            "host",
            flow.server_name
                .as_deref()
                .or_else(|| names.name_of(&remote.addr)),
        )
        .opt_str("tls", version.as_deref())
        .opt_str(
            "app_proto",
            (!matches!(
                flow.proto,
                Proto::Tcp | Proto::Udp | Proto::Icmp | Proto::Icmpv6
            ))
            .then_some(flow.proto.name()),
        )
        .num("up_bytes", flow.payload_bytes[local])
        .num("down_bytes", flow.payload_bytes[1 - local])
        .num("packets", flow.packets[0].saturating_add(flow.packets[1]))
        .num("retransmits", flow.retransmissions)
        .str("end", &status)
        .finish()
}

fn millis(value: Duration) -> u64 {
    value.as_millis().min(u128::from(u64::MAX)) as u64
}

/// Fixed severity name used by readable logs and JSON.
pub(crate) fn severity(value: Severity) -> &'static str {
    match value {
        Severity::Notice => "Notice",
        Severity::Warning => "Warning",
        Severity::Serious => "Serious",
    }
}

fn alert_kind(value: AlertKind) -> &'static str {
    match value {
        AlertKind::PortScan => "PortScan",
        AlertKind::CleartextCredentials => "CleartextCredentials",
        AlertKind::ArpChange => "ArpChange",
        AlertKind::SuspiciousDns => "SuspiciousDns",
        AlertKind::UnexpectedInbound => "UnexpectedInbound",
    }
}

/// Describe an alert using only severity and its secret-free title.
pub(crate) fn alert_event(alert: &Alert) -> String {
    format!("{}: {}", severity(alert.severity), alert.title)
}

/// Encode alert facts, references and optional subject address.
pub(crate) fn alert_json(alert: &Alert) -> String {
    Json::object()
        .str("time", &timestamp(alert.ts))
        .str("kind", alert_kind(alert.kind))
        .str("severity", severity(alert.severity))
        .str("title", &alert.title)
        .str("seen", &alert.seen)
        .num("packet", alert.packet)
        .num("first_packet", alert.first_packet)
        .opt_str("subject", alert.subject.map(|ip| ip.to_string()).as_deref())
        .finish()
}

pub(crate) use dns::{DnsRow, dns_event, dns_markdown, dns_row};
mod dns;

/// Write one escaped report value; the label must be fixed wording.
pub(crate) fn fact(label: &str, value: &str) -> String {
    format!("- {label}: {}\n", markdown::explanation(value))
}

/// Format an alert heading, severity, packet references and evidence explanations.
pub(crate) fn alert_markdown(alert: &Alert) -> String {
    format!(
        "### {}\n\n{}{}{}\n{}{}{}\n",
        markdown::escape(&alert.title),
        fact("Severity", severity(alert.severity)),
        fact("First packet", &alert.first_packet.to_string()),
        fact("Triggering packet", &alert.packet.to_string()),
        fact("Seen", &alert.seen),
        fact("Why", alert.why),
        fact("Next", alert.next)
    )
}

/// Give a packet reference and escaped explanation, using readable ASCII punctuation.
pub(crate) fn problem_markdown(packet: u64, text: &str) -> String {
    format!(
        "- Packet {}: {}\n",
        markdown::escape(&packet.to_string()),
        markdown::explanation(&text.replace(" — ", " - "))
    )
}

/// Report the number of omitted finished conversations available in the JSON log.
pub(crate) fn more_conversations(count: u64) -> String {
    if count == 0 {
        return "\n".into();
    }
    format!(
        "\n{} more finished conversations are in flows.jsonl.\n\n",
        markdown::escape(&count.to_string())
    )
}
/// Report bounded-history coverage without implying it contains the whole session.
pub(crate) fn recent_only(kept: usize, total: u64) -> String {
    format!(
        "Showing the latest {} of {}.\n\n",
        markdown::escape(&kept.to_string()),
        markdown::escape(&total.to_string())
    )
}

/// Explain a present file and what opens it; the filename is escaped.
pub(crate) fn file_description(name: &str) -> String {
    let description = match name {
        "summary.md" => "Session report; open in a Markdown editor or viewer.",
        "events.md" => "Event timeline; open in a Markdown editor or viewer.",
        "flows.jsonl" => "Finished conversations; read with a JSON lines tool.",
        "alerts.jsonl" => "Alert observations; read with a JSON lines tool.",
        "packets.jsonl" => "Packet summaries; read with a JSON lines tool.",
        name if name.ends_with(".pcapng") => {
            "Raw packets, including private payload bytes; open in Wireshark or tshark."
        }
        name if name.ends_with(".md") => "Exported report; open in a Markdown editor or viewer.",
        _ => "Other session file; inspect with the tool for its format.",
    };
    format!("- {}: {description}\n", markdown::escape(name))
}

/// Build an inert Markdown story with a title, facts and a fenced text ladder.
/// `app` may be absent; all names and generated facts are escaped by shared helpers.
pub fn story_markdown(flow: &Flow, names: &Names, app: Option<&str>) -> String {
    let mut output = format!(
        "# Conversation {}\n\n",
        markdown::escape(&flow.id.0.to_string())
    );
    output.push_str(&fact("App", app_name(app)));
    output.push_str(&fact("Remote", &remote_host(flow, names)));
    output.push_str(&fact(
        "Protocol",
        &transport(flow.ip_proto)
            .to_ascii_uppercase()
            .replace("ICMPV6", "ICMPv6"),
    ));
    output.push_str(&fact(
        "State",
        &flows::flow_status(flow).replace(" · ", "; "),
    ));
    output.push('\n');
    let mut ladder = String::new();
    for step in &flow.story {
        ladder.push_str(&format!(
            "{}  {}  {}  [packets {}-{}]\n",
            report_duration(step.time.saturating_sub(flow.first)),
            if step.direction == crate::flow::Direction::Forward {
                "starter -> peer"
            } else {
                "peer -> starter"
            },
            flows::step_text(step, flow),
            step.first_packet,
            step.last_packet
        ));
    }
    output.push_str(&markdown::fenced_block(&ladder));
    output
}

/// Format one headless row with packet time relative to capture start.
/// `times` contains [packet timestamp, first packet timestamp]; labels contain
/// [source, destination]. Text must be sanitised and secret-free; None means no owner.
pub fn headless_row(
    number: u64,
    times: [Duration; 2],
    labels: [&str; 2],
    app: Option<&str>,
    sentence: &str,
) -> String {
    format!(
        "{number:5} {:10.6}  {} -> {}  {}  {sentence}",
        times[0].saturating_sub(times[1]).as_secs_f64(),
        labels[0],
        labels[1],
        app.unwrap_or("unknown app")
    )
}

/// Describe final totals; the folder is sanitised for terminal display when present.
pub fn headless_summary(
    packets: u64,
    conversations: u64,
    alerts: u64,
    folder: Option<&str>,
) -> String {
    format!(
        "{} packets, {} conversations, {} alerts{}",
        text::number(packets),
        text::number(conversations),
        text::number(alerts),
        folder
            .map(|p| format!("\nSession: {}", text::sanitise(p.as_bytes())))
            .unwrap_or_default()
    )
}

/// Format a headless failure without allowing filenames/errors to inject controls.
pub fn headless_problem(error: &dyn Display) -> String {
    format!(
        "Headless capture fails: {}",
        text::sanitise(error.to_string().as_bytes())
    )
}
