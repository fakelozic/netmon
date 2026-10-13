//! Contextual packet sentences for retained conversation evidence.
//! TCP decisions stay in `flow::tcp`; standalone wording stays in `explain`.
//! Read `sentence` for note priority, then `story` for the plain-text ladder.
use crate::decode::{AppInfo, Decoded};
use crate::flow::{Direction, Endpoint, Flow, FlowState, Note, Observation, Step, StepKind};
use crate::names::Names;
use crate::{explain, text};
use std::fmt::Write;
use std::time::Duration;

/// Label for caller-provided local interface addresses.
pub(crate) const THIS_COMPUTER: &str = "this computer";
/// Label for the caller-provided default gateway.
pub(crate) const ROUTER: &str = "router";
/// Usage text for the saved-capture flows example.
pub const EXAMPLE_USAGE: &str = "usage: cargo run --offline --example flows -- <FILE> [--stories]";

/// Format a nonnegative elapsed duration in ns, µs, ms, or seconds.
/// Sub-microsecond values remain visible; milliseconds and seconds round to one decimal.
pub fn duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        decimal(d.as_secs_f64(), "s")
    } else if d.as_millis() > 0 {
        decimal(d.as_secs_f64() * 1_000.0, "ms")
    } else if d.as_micros() > 0 {
        format!("{} µs", d.as_micros())
    } else {
        format!("{} ns", d.as_nanos())
    }
}
fn decimal(n: f64, unit: &str) -> String {
    let n = format!("{n:.1}");
    format!("{} {unit}", n.strip_suffix(".0").unwrap_or(&n))
}

/// Explain a packet using its observation and retained conversation facts.
/// With no usable notes, retain the standalone sentence and its truncation marker.
/// A sequence repeat or gap describes evidence, not proof of the cause of loss.
pub fn sentence(d: &Decoded, obs: &Observation, flow: Option<&Flow>, _names: &Names) -> String {
    let mut base = explain::sentence(d);
    // The decoder can return a prefix of a cut-short SNI (RFC 6066, 3).
    // Only the tracker's checked complete name may be presented as the server name.
    if matches!(&d.summary.app, Some(AppInfo::TlsClientHello(h)) if !h.complete) {
        base = "Starts encryption (TLS Client Hello) — waiting for the rest of the hello".into();
    }
    // Close/reset evidence outranks application timing, which outranks plain ACKs.
    let mut result = tcp_sentence(d, obs, flow)
        .or_else(|| application_sentence(d, obs, flow, &base))
        .or_else(|| ack_sentence(d, obs))
        .unwrap_or(base);
    if d.truncated && !result.ends_with(" [cut short]") {
        result.push_str(" [cut short]");
    }
    result
}

fn tcp_sentence(d: &Decoded, obs: &Observation, flow: Option<&Flow>) -> Option<String> {
    let bytes = d
        .summary
        .tcp
        .as_ref()
        .map(|t| u64::from(t.payload_len))
        .unwrap_or(0);
    let mut result = None;
    if obs.notes.contains(&Note::Refused) {
        let port = flow
            .and_then(|f| f.endpoints[1].port)
            .or(d.summary.src_port);
        result = Some(format!(
            "Refuses the connection (RST) — probably nothing is listening on port {}",
            port.map(|p| p.to_string()).unwrap_or_else(|| "?".into())
        ));
    } else if obs.notes.contains(&Note::Reset) {
        result = Some("Aborts the connection (RST)".into());
    } else if obs.notes.contains(&Note::ClosedPolitely) {
        result = Some("Confirms the close (ACK) — the connection has ended".into());
    } else if obs.notes.contains(&Note::Retransmission) {
        result = Some(retransmission(d, bytes));
    } else if obs.notes.contains(&Note::KeepAlive) {
        result = Some("Checks the connection is still alive (keep-alive)".into());
    } else if obs.notes.contains(&Note::ZeroWindow) {
        result = Some("Says it cannot take more data right now (zero window)".into());
    } else if let Some(count) = obs.notes.iter().find_map(|n| {
        if let Note::DuplicateAck(count) = n {
            Some(*count)
        } else {
            None
        }
    }) {
        result = Some(format!(
            "Repeats its last confirmation (duplicate ACK {count}) — it is still waiting for missing data"
        ));
    } else if obs.notes.contains(&Note::Gap) {
        result = Some(format!(
            "Sends {} bytes of data — an earlier packet may be missing from the capture",
            text::number(bytes)
        ));
    } else if obs.notes.contains(&Note::HandshakeStep(3)) {
        result = Some("Confirms (ACK) — handshake 3 of 3, the connection is open".into());
    } else if obs.notes.contains(&Note::HandshakeStep(2))
        && let Some(time) = obs.notes.iter().find_map(|n| {
            if let Note::HandshakeTime(time) = n {
                Some(*time)
            } else {
                None
            }
        })
    {
        result = Some(format!(
            "Accepts the connection (SYN+ACK) — handshake 2 of 3, {} after the request",
            duration(time)
        ));
    }
    result
}

fn application_sentence(
    d: &Decoded,
    obs: &Observation,
    flow: Option<&Flow>,
    base: &str,
) -> Option<String> {
    let mut result = None;
    if let Some(time) = obs.notes.iter().find_map(|n| match n {
        Note::DnsAnswerTime(t) | Note::PingTime(t) | Note::HttpResponseTime(t) => Some(*t),
        _ => None,
    }) {
        result = Some(match &d.summary.app {
            Some(AppInfo::Icmp { sequence, .. }) => format!(
                "Ping reply (seq {}, {})",
                sequence
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into()),
                duration(time)
            ),
            _ => format!(
                "{} ({})",
                base.strip_suffix(" [cut short]").unwrap_or(base),
                duration(time)
            ),
        });
    } else if let Some(name) = obs.notes.iter().find_map(|n| {
        if let Note::ServerName(name) = n {
            Some(name)
        } else {
            None
        }
    }) && flow.is_some_and(|f| f.proto == crate::decode::Proto::Tls)
    {
        result = Some(format!("Starts encryption (TLS Client Hello) for {name}"));
    }
    result
}

fn ack_sentence(d: &Decoded, obs: &Observation) -> Option<String> {
    let mut result = None;
    if d.summary
        .tcp
        .as_ref()
        .is_some_and(|t| t.payload_len == 0 && t.flags & (1 | 2 | 4) == 0)
        && let Some(bytes) = obs.notes.iter().find_map(|n| {
            if let Note::AckedBytes(bytes) = n {
                Some(*bytes)
            } else {
                None
            }
        })
    {
        result = Some(format!(
            "Confirms receipt of {} bytes (ACK)",
            text::number(bytes)
        ));
    }
    result
}

fn retransmission(d: &Decoded, bytes: u64) -> String {
    if bytes > 0 {
        format!(
            "Sends {} bytes again (retransmission) — the first copy was probably lost",
            text::number(bytes)
        )
    } else if d.summary.tcp.as_ref().is_some_and(|t| t.flags & 18 == 18) {
        "Repeats the acceptance (SYN+ACK retransmission) — no confirmation was seen".into()
    } else if d.summary.tcp.as_ref().is_some_and(|t| t.flags & 2 != 0) {
        "Repeats the connection request (SYN retransmission) — no confirmation was seen".into()
    } else {
        "Repeats the request to close (FIN retransmission) — no confirmation was seen".into()
    }
}

fn endpoint(endpoint: Endpoint, names: &Names, override_name: Option<&str>) -> String {
    let base = names.label(&endpoint.addr);
    let label = override_name
        .filter(|_| !names.is_local(&endpoint.addr) && base != ROUTER)
        .map(str::to_owned)
        .unwrap_or(base);
    if let Some(port) = endpoint.port {
        if endpoint.addr.is_ipv6() && label == endpoint.addr.to_string() {
            format!("[{label}]:{port}")
        } else {
            format!("{label}:{port}")
        }
    } else {
        label
    }
}

/// Format endpoint labels, protocol, captured elapsed time, and directional payload bytes.
/// A conversation-specific server name takes priority over a learned address alias.
pub fn flow_title(flow: &Flow, names: &Names) -> String {
    let transport = match flow.ip_proto {
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "ICMP",
    };
    let application = if let Some(version) = flow.tls_version {
        format!(" + {}", explain::tls_version(version))
    } else if flow.proto
        != match flow.ip_proto {
            6 => crate::decode::Proto::Tcp,
            17 => crate::decode::Proto::Udp,
            58 => crate::decode::Proto::Icmpv6,
            _ => crate::decode::Proto::Icmp,
        }
    {
        format!(" + {}", flow.proto.name())
    } else {
        String::new()
    };
    format!(
        "{} ⇄ {}   {transport}{application} · {} · {} bytes up / {} bytes down",
        endpoint(flow.endpoints[0], names, None),
        endpoint(flow.endpoints[1], names, flow.server_name.as_deref()),
        duration(flow.last.saturating_sub(flow.first)),
        text::number(flow.payload_bytes[0]),
        text::number(flow.payload_bytes[1])
    )
}

/// Describe retained state and observed problems; an unseen opening is labelled midstream.
pub fn flow_status(flow: &Flow) -> String {
    let status = match flow.state {
        FlowState::Opening => "waiting for the connection to open",
        FlowState::Open => "still open",
        FlowState::Closing => "closing politely",
        FlowState::Closed => "closed normally",
        FlowState::Reset => match flow.reset_by {
            Some(Direction::Reverse) if flow.start_seen => "reset by the server",
            Some(Direction::Reverse) => "reset by the peer",
            Some(Direction::Forward) => "reset by the starter",
            None => "reset",
        },
        FlowState::Refused => "refused",
        FlowState::Active => "active",
        FlowState::Idle => "ended after no packets were seen before the timeout",
    };
    let mut result = status.to_owned();
    if !flow.start_seen && flow.ip_proto == 6 {
        result.push_str(" · capture starts mid-connection");
    }
    if flow.retransmissions > 0 {
        let _ = write!(
            result,
            " · {} retransmission{}",
            text::number(flow.retransmissions),
            if flow.retransmissions == 1 { "" } else { "s" }
        );
    }
    if flow.duplicate_acks > 0 {
        let _ = write!(
            result,
            " · {} repeated confirmations",
            text::number(flow.duplicate_acks)
        );
    }
    result
}

/// Describe one ladder step; grouped byte counts include transport payload and repeat bytes.
pub fn step_text(step: &Step, flow: &Flow) -> String {
    match step.kind {
        StepKind::Syn => "\"Can we talk?\" (SYN)".into(),
        StepKind::SynAck => "\"Yes. Can you hear me?\" (SYN+ACK)".into(),
        StepKind::HandshakeAck => "\"Yes.\" The connection is open.".into(),
        StepKind::TlsClientHello => format!(
            "Starts encryption (TLS Client Hello){}",
            flow.server_name
                .as_ref()
                .map(|n| format!(" for {n}"))
                .unwrap_or_default()
        ),
        StepKind::TlsServerHello => format!(
            "Agrees on encryption settings (TLS Server Hello{})",
            flow.tls_version
                .map(|v| format!(", {}", explain::tls_version(v)))
                .unwrap_or_default()
        ),
        StepKind::TlsHandshake => "Continues setting up encryption (TLS handshake)".into(),
        StepKind::HttpRequest
        | StepKind::HttpResponse
        | StepKind::DnsQuery
        | StepKind::DnsResponse
        | StepKind::PingRequest
        | StepKind::PingReply
        | StepKind::IcmpError => step
            .text
            .clone()
            .unwrap_or_else(|| "Packet details were not captured".into()),
        StepKind::Data => format!(
            "{} packet{}, {} bytes of {}data{}",
            text::number(step.packets),
            if step.packets == 1 { "" } else { "s" },
            text::number(step.payload_bytes),
            if step.encrypted { "encrypted " } else { "" },
            if step.encrypted {
                " — the contents cannot be read"
            } else {
                ""
            }
        ),
        StepKind::Retransmission => format!(
            "Repeats {} bytes or a connection control message (retransmission)",
            text::number(step.payload_bytes)
        ),
        StepKind::Fin => "Finished sending, closing politely (FIN)".into(),
        StepKind::CloseAck => "Confirms the close (ACK) — the connection has ended".into(),
        StepKind::Reset => "Aborts the connection (RST)".into(),
        StepKind::Refused => "Refuses the connection (RST)".into(),
        StepKind::KeepAlive => "Checks the connection is still alive (keep-alive)".into(),
        StepKind::DuplicateAck => "Repeats its last confirmation (duplicate ACK)".into(),
        StepKind::Gap => {
            "Sends data beyond a gap — an earlier packet may be missing from the capture".into()
        }
        StepKind::ZeroWindow => "Says it cannot take more data right now (zero window)".into(),
    }
}

/// Format a ladder without its title/status. Step times are relative to the first packet.
/// Arrow direction follows the data sender; packet ranges can span unrelated interleaved packets.
pub fn story(flow: &Flow, names: &Names) -> String {
    let mut result = format!(
        "    {}                         {}\n",
        endpoint(flow.endpoints[0], names, None),
        endpoint(flow.endpoints[1], names, flow.server_name.as_deref())
    );
    for (index, step) in flow.story.iter().enumerate() {
        let arrow = match step.direction {
            Direction::Forward => "│ ───────────────────────▶ │",
            Direction::Reverse => "│ ◀─────────────────────── │",
        };
        let time = duration(step.time.saturating_sub(flow.first));
        let _ = writeln!(
            result,
            "  {time:>9}  {arrow}  {}. {}  [packets {}–{}]",
            index + 1,
            step_text(step, flow),
            step.first_packet,
            step.last_packet
        );
        if let Some(t) = step.duration
            && matches!(step.kind, StepKind::SynAck)
        {
            let _ = writeln!(result, "               {} after the request", duration(t));
        }
    }
    if flow.story_omitted > 0 {
        let _ = writeln!(
            result,
            "  Story limit reached. {} later packets are folded into the data totals.",
            text::number(flow.story_omitted)
        );
    }
    result
}
