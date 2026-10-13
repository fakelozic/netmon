//! Projects retained conversations and their ordered story steps.
//! Packet rows stay in `packet`; wording stays in `explain::flows`.
//! Read `State::flows` for sorting and `flow_record` for an individual story.
//! Story direction is relative to the starter, not necessarily this computer.

use super::{
    records::{self, ResultJson, elapsed, opt, opt_num},
    state::State,
};
use crate::{
    decode::Proto,
    explain::{self, web as words},
    flow::{Direction, Flow, FlowState, StepKind},
    log::{Json, JsonValue as V},
    names::Names,
};
use records::{keys, number};

impl State {
    /// Sorts retained conversations with deterministic ID ties and a bounded output limit.
    pub fn flows(&self, query: &[(String, String)]) -> ResultJson {
        keys(query, &["sort", "limit"])?;
        let sort = query
            .iter()
            .find(|(k, _)| k == "sort")
            .map_or("recent", |(_, v)| v.as_str());
        if !["recent", "bytes", "problems"].contains(&sort) {
            return Err((400, words::error(400)));
        }
        let limit = number(query, "limit")?.unwrap_or(200);
        if limit == 0 || limit > 1000 {
            return Err((400, words::error(400)));
        }
        let mut flows: Vec<&Flow> = self.paused.as_ref().map_or_else(
            || self.pipeline.tracker().flows().collect(),
            |p| p.flows.iter().collect(),
        );
        flows.sort_by(|a, b| {
            let order = match sort {
                "bytes" => sum(b.payload_bytes).cmp(&sum(a.payload_bytes)),
                "problems" => problems(b).cmp(&problems(a)),
                _ => b.last.cmp(&a.last),
            };
            order.then_with(|| a.id.cmp(&b.id))
        });
        Ok(Json::object()
            .num("total", flows.len() as u64)
            .value(
                "flows",
                V::array(
                    flows
                        .into_iter()
                        .take(limit as usize)
                        .map(|f| self.flow_record(f, false).into_value()),
                ),
            )
            .finish())
    }
    /// Encodes one retained conversation plus story; absent IDs return 404.
    pub fn flow(&self, id: u64) -> ResultJson {
        let id = crate::flow::FlowId(u32::try_from(id).map_err(|_| (400, words::error(400)))?);
        let flow = self
            .paused
            .as_ref()
            .map_or_else(
                || self.pipeline.tracker().flow(id),
                |p| p.flows.iter().find(|f| f.id == id),
            )
            .ok_or((404, words::FLOW_GONE))?;
        Ok(self.flow_record(flow, true).finish())
    }
    fn flow_base(&self, f: &Flow) -> Json {
        let names = self.pipeline.tracker().names();
        let side = self
            .paused
            .as_ref()
            .and_then(|p| p.local_sides.get(&f.id))
            .copied()
            .unwrap_or_else(|| explain::pipeline::local_side(f, names));
        let remote = self
            .paused
            .as_ref()
            .and_then(|p| p.remote_names.get(&f.id))
            .cloned()
            .unwrap_or_else(|| remote_name(f, names));
        let app = self.app(f.id);
        let title = words::flow_title(
            app.map(|a| a.name.as_str()),
            &endpoint(f.endpoints[1 - side], remote.as_deref()),
        );
        let app_proto = if let Some(v) = f.tls_version {
            Some(explain::tls_version(v))
        } else {
            (!matches!(
                f.proto,
                Proto::Tcp | Proto::Udp | Proto::Icmp | Proto::Icmpv6
            ))
            .then(|| f.proto.name().to_owned())
        };
        let ended = matches!(
            f.state,
            FlowState::Closed | FlowState::Reset | FlowState::Refused | FlowState::Idle
        );
        Json::object()
            .num("id", u64::from(f.id.0))
            .str("title", &title)
            .value("app", opt(app.map(|a| a.name.as_str())))
            .value("pid", opt_num(app.map(|a| u64::from(a.pid))))
            .str("local", &endpoint(f.endpoints[side], None))
            .str("remote", &endpoint(f.endpoints[1 - side], None))
            .value("remote_name", opt(remote.as_deref()))
            .str("proto", transport(f.ip_proto))
            .value("app_proto", opt(app_proto.as_deref()))
            .str("state", flow_state(f.state))
            .str("status", &explain::flows::flow_status(f))
            .value("started", V::float(elapsed(f.first, self.first)))
            .value(
                "duration_ms",
                if ended {
                    V::float(f.last.saturating_sub(f.first).as_secs_f64() * 1000.0)
                } else {
                    V::null()
                },
            )
            .num("up_bytes", f.payload_bytes[side])
            .num("down_bytes", f.payload_bytes[1 - side])
            .num("packets", sum(f.packets))
            .num("problems", problems(f))
            .num("first_packet", f.first_packet)
            .num("last_packet", f.last_packet)
    }
    fn flow_record(&self, f: &Flow, story: bool) -> Json {
        let mut json = self.flow_base(f);
        if story {
            json = json.value(
                "story",
                V::array(f.story.iter().enumerate().map(|(n, s)| {
                    Json::object()
                        .num("n", n as u64 + 1)
                        .str(
                            "dir",
                            if s.direction == Direction::Forward {
                                "out"
                            } else {
                                "in"
                            },
                        )
                        .str("kind", step_kind(s.kind))
                        .str("text", &explain::flows::step_text(s, f))
                        .num("first_packet", s.first_packet)
                        .num("last_packet", s.last_packet)
                        .value(
                            "at_ms",
                            V::float(s.time.saturating_sub(f.first).as_secs_f64() * 1000.0),
                        )
                        .value(
                            "took_ms",
                            s.duration
                                .map_or_else(V::null, |d| V::float(d.as_secs_f64() * 1000.0)),
                        )
                        .num("packets", s.packets)
                        .num("bytes", s.payload_bytes)
                        .bool("problem", step_problem(s.kind))
                        .into_value()
                })),
            );
        }
        json
    }
}
fn endpoint(e: crate::flow::Endpoint, name: Option<&str>) -> String {
    let addr = name
        .map(str::to_owned)
        .unwrap_or_else(|| e.addr.to_string());
    match e.port {
        Some(p) if name.is_none() && e.addr.is_ipv6() => format!("[{addr}]:{p}"),
        Some(p) => format!("{addr}:{p}"),
        None => addr,
    }
}
/// Returns conversation SNI/Host, then a learned peer alias; None means unknown.
pub(super) fn remote_name(f: &Flow, names: &Names) -> Option<String> {
    f.server_name.clone().or_else(|| {
        names
            .name_of(&f.endpoints[1 - explain::pipeline::local_side(f, names)].addr)
            .map(str::to_owned)
    })
}
fn sum(a: [u64; 2]) -> u64 {
    a[0].saturating_add(a[1])
}
fn problems(f: &Flow) -> u64 {
    f.retransmissions
        .saturating_add(f.resets)
        .saturating_add(f.duplicate_acks)
}
fn transport(p: u8) -> &'static str {
    match p {
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "ICMP",
    }
}
fn flow_state(s: FlowState) -> &'static str {
    match s {
        FlowState::Opening => "opening",
        FlowState::Open => "open",
        FlowState::Closing => "closing",
        FlowState::Closed => "closed",
        FlowState::Reset => "reset",
        FlowState::Refused => "refused",
        FlowState::Active => "active",
        FlowState::Idle => "idle",
    }
}
fn step_kind(s: StepKind) -> &'static str {
    match s {
        StepKind::Syn => "syn",
        StepKind::SynAck => "syn_ack",
        StepKind::HandshakeAck => "handshake_ack",
        StepKind::TlsClientHello => "tls_client_hello",
        StepKind::TlsServerHello => "tls_server_hello",
        StepKind::TlsHandshake => "tls_handshake",
        StepKind::HttpRequest => "http_request",
        StepKind::HttpResponse => "http_response",
        StepKind::DnsQuery => "dns_query",
        StepKind::DnsResponse => "dns_response",
        StepKind::PingRequest => "ping_request",
        StepKind::PingReply => "ping_reply",
        StepKind::Data
        | StepKind::KeepAlive
        | StepKind::CloseAck
        | StepKind::DuplicateAck
        | StepKind::Gap
        | StepKind::ZeroWindow => "data",
        StepKind::Retransmission => "retransmission",
        StepKind::Fin => "fin",
        StepKind::Reset => "reset",
        StepKind::Refused => "refused",
        StepKind::IcmpError => "icmp_error",
    }
}
fn step_problem(s: StepKind) -> bool {
    matches!(
        s,
        StepKind::Retransmission
            | StepKind::Reset
            | StepKind::Refused
            | StepKind::IcmpError
            | StepKind::DuplicateAck
            | StepKind::Gap
            | StepKind::ZeroWindow
    )
}
