//! Bounded conversation lookup using packet timestamps.
//! TCP decisions stay in `tcp`; application timings stay in `application`.
//! Read `Tracker::observe` for the path of one captured packet.
use super::application::learn_dns;
use super::packet::*;
use super::*;
use crate::capture::RawPacket;
use crate::decode::{AppInfo, Decoded};
use crate::names::Names;
use std::collections::{BTreeMap, BTreeSet, HashMap};

type TimeEntry = (Duration, u64, FlowId);
/// Single-owner conversation table with at most 50,000 retained flows.
/// Use one decoded observation per packet in capture order; all times come from packets.
pub struct Tracker {
    table: HashMap<FlowId, Tracked>,
    keys: HashMap<Key, FlowId>,
    order: BTreeMap<u64, FlowId>,
    ended: BTreeSet<(u64, FlowId)>,
    activity: BTreeSet<TimeEntry>,
    deadlines: BTreeSet<TimeEntry>,
    next_id: u32,
    next_order: u64,
    now: Duration,
    names: Names,
}
impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}
impl Tracker {
    /// Create empty flow and name tables. No network or wall-clock reads occur.
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            keys: HashMap::new(),
            order: BTreeMap::new(),
            ended: BTreeSet::new(),
            activity: BTreeSet::new(),
            deadlines: BTreeSet::new(),
            next_id: 0,
            next_order: 0,
            now: Duration::ZERO,
            names: Names::new(),
        }
    }

    /// Look up retained facts; None means the identifier was never observed or was evicted.
    pub fn flow(&self, id: FlowId) -> Option<&Flow> {
        self.table.get(&id).map(|t| &t.flow)
    }

    /// Iterate retained conversations in creation order, oldest first, including ended ones.
    pub fn flows(&self) -> impl Iterator<Item = &Flow> {
        self.order.values().filter_map(|id| self.flow(*id))
    }

    /// Borrow the passive address table; its lookups update only LRU metadata.
    pub fn names(&self) -> &Names {
        &self.names
    }

    /// Borrow address labels for caller-provided local addresses, gateway, or name hints.
    pub fn names_mut(&mut self) -> &mut Names {
        &mut self.names
    }

    /// End flows idle for 60 seconds (UDP/echo) or 300 seconds (TCP).
    /// `now` is packet time since the Unix epoch; backwards values do not rewind time.
    /// Return only ids newly ended by timeout. Ended records remain until eviction.
    pub fn tick(&mut self, now: Duration) -> Vec<FlowId> {
        // Capture timestamps can go backwards; inactivity cannot become negative.
        self.now = self.now.max(now);
        let mut ended = Vec::new();
        while let Some(&(deadline, order, id)) = self.deadlines.first() {
            if deadline > self.now {
                break;
            }
            self.deadlines.pop_first();
            if let Some(t) = self.table.get_mut(&id)
                && !t.done
            {
                t.done = true;
                t.flow.state = FlowState::Idle;
                t.release();
                self.ended.insert((order, id));
                ended.push(id);
            }
        }
        ended
    }

    fn remove(&mut self, id: FlowId) {
        if let Some(t) = self.table.remove(&id) {
            if self.keys.get(&t.key) == Some(&id) {
                self.keys.remove(&t.key);
            }
            self.order.remove(&t.order);
            self.ended.remove(&(t.order, id));
            self.activity.remove(&(t.flow.last, t.order, id));
            self.deadlines.remove(&(deadline(&t.flow), t.order, id));
        }
    }

    fn add(
        &mut self,
        key: Key,
        source: Endpoint,
        destination: Endpoint,
        raw: &RawPacket,
        d: &Decoded,
    ) -> FlowId {
        if self.table.len() >= MAX_FLOWS {
            // Ended records yield first so active conversations keep their evidence.
            let victim = self
                .ended
                .first()
                .map(|(_, id)| *id)
                .or_else(|| self.activity.first().map(|(_, _, id)| *id));
            if let Some(id) = victim {
                self.remove(id);
            }
        }
        // At most MAX_FLOWS ids are occupied, so a free id exists within this bound.
        for _ in 0..=MAX_FLOWS {
            self.next_id = self.next_id.wrapping_add(1);
            // Zero is reserved for an absent ID by callers and the web contract.
            if self.next_id != 0 && !self.table.contains_key(&FlowId(self.next_id)) {
                break;
            }
        }
        let id = FlowId(self.next_id);
        self.next_order = self.next_order.saturating_add(1);
        let start_seen = complete_tcp(raw, d).is_some_and(|t| t.flags & (SYN | ACK) == SYN);
        let mut flow = initial_flow(id, key.protocol, [source, destination], raw.ts, start_seen);
        flow.first_packet = raw.number;
        flow.last_packet = raw.number;
        self.order.insert(self.next_order, id);
        self.keys.insert(key, id);
        self.table.insert(
            id,
            Tracked {
                flow,
                key,
                order: self.next_order,
                sides: [Side::default(), Side::default()],
                syn_time: None,
                syn_ack_seen: false,
                done: false,
                echo_starter_request: echo_request(d),
                queries: VecDeque::new(),
                pings: VecDeque::new(),
                http_request: None,
                hello: (key.protocol == 6).then(Vec::new),
                hello_next: None,
            },
        );
        id
    }

    /// Observe one raw packet and its matching decoded summary exactly once, in order.
    /// Incomplete headers do not create TCP sequence evidence. Unsupported protocols
    /// return no flow; a full table evicts ended flows first, then the least active.
    /// This also runs `tick(raw.ts)`; timeout ids are available through an explicit tick before observe.
    pub fn observe(&mut self, raw: &RawPacket, d: &Decoded) -> Observation {
        self.tick(raw.ts);
        let mut obs = Observation::default();
        let Some(source_ip) = ip(d.summary.src.as_ref()) else {
            return obs;
        };
        let Some(destination_ip) = ip(d.summary.dst.as_ref()) else {
            return obs;
        };

        let icmp_error = matches!(
            &d.summary.app,
            Some(AppInfo::Icmp {
                embedded: Some(_),
                ..
            })
        );
        let found = self.locate(raw, d, source_ip, destination_ip, &mut obs);
        let Some((id, direction)) = found else {
            learn_dns(&mut self.names, d, None);
            return obs;
        };
        obs.flow = Some(id);
        obs.direction = Some(direction);
        let Some(t) = self.table.get_mut(&id) else {
            return obs;
        };
        self.activity.remove(&(t.flow.last, t.order, id));
        self.deadlines.remove(&(deadline(&t.flow), t.order, id));
        let was_done = t.done;
        t.flow.last = t.flow.last.max(raw.ts);
        t.flow.last_packet = raw.number;
        let side = direction.index();
        t.flow.packets[side] = t.flow.packets[side].saturating_add(1);
        let bytes = if icmp_error { 0 } else { payload_bytes(raw, d) };
        t.flow.payload_bytes[side] = t.flow.payload_bytes[side].saturating_add(bytes);
        if !icmp_error {
            if let Some(tcp) = complete_tcp(raw, d) {
                t.tcp(tcp, direction, raw.ts, &mut obs.notes);
                t.client_hello(raw, d, tcp, direction, &mut obs.notes);
            }
            t.application(d, direction, raw.ts, &mut self.names, &mut obs.notes);
        }
        obs.ended = !was_done && t.done;
        t.add_step(raw, d, direction, bytes, &obs, &self.names);
        if t.done {
            t.release();
            self.ended.insert((t.order, id));
        } else {
            self.deadlines.insert((deadline(&t.flow), t.order, id));
        }
        self.activity.insert((t.flow.last, t.order, id));
        obs
    }
    fn locate(
        &mut self,
        raw: &RawPacket,
        d: &Decoded,
        source_ip: IpAddr,
        destination_ip: IpAddr,
        obs: &mut Observation,
    ) -> Option<(FlowId, Direction)> {
        let mut found = None;
        if let Some(AppInfo::Icmp {
            embedded: Some(quoted),
            ..
        }) = &d.summary.app
        {
            found = self.quoted_flow(quoted, destination_ip);
        } else if let Some((key, source, destination)) = conversation(d, source_ip, destination_ip)
        {
            let existing = self.keys.get(&key).copied();
            let syn = complete_tcp(raw, d).filter(|tcp| tcp.flags & (SYN | ACK) == SYN);
            let replace = existing
                .and_then(|id| self.table.get(&id))
                .is_some_and(|t| {
                    (t.done
                        && (key.protocol != 6 || syn.is_some() || t.flow.state == FlowState::Idle))
                        || syn.is_some_and(|s| {
                            t.flow.start_seen && t.sides[0].syn.is_some_and(|n| n as u32 != s.seq)
                        })
                });
            let id = if existing.is_none() || replace {
                obs.new_flow = true;
                self.add(key, source, destination, raw, d)
            } else {
                existing?
            };
            if let Some(t) = self.table.get_mut(&id) {
                let mut direction = if t.flow.endpoints[0] == source {
                    Direction::Forward
                } else {
                    Direction::Reverse
                };
                if key.echo_id.is_some() && source == destination {
                    direction = if echo_request(d) == t.echo_starter_request {
                        Direction::Forward
                    } else {
                        Direction::Reverse
                    };
                }
                if syn.is_some() && direction == Direction::Reverse && !t.flow.start_seen {
                    t.reverse();
                    direction = Direction::Forward;
                }
                found = Some((id, direction));
            }
        }
        found
    }

    fn quoted_flow(
        &self,
        quoted: &crate::decode::EmbeddedPacket,
        destination_ip: IpAddr,
    ) -> Option<(FlowId, Direction)> {
        let mut found = None;
        // The quoted decoder does not expose its destination address. Refuse an
        // ambiguous match rather than attaching an error to an arbitrary peer.
        for t in self.table.values() {
            // A reused tuple has a new current id; old retained stories must not
            // make the current quoted packet's match look ambiguous.
            if self.keys.get(&t.key) != Some(&t.flow.id) {
                continue;
            }
            if quoted.protocol != Some(t.flow.ip_proto) || !matches!(t.flow.ip_proto, 6 | 17) {
                continue;
            }
            for direction in [Direction::Forward, Direction::Reverse] {
                let a = t.flow.endpoints[direction.index()];
                let b = t.flow.endpoints[direction.opposite().index()];
                if a.addr == destination_ip
                    && a.port == quoted.src_port
                    && b.port == quoted.dst_port
                {
                    if found.is_some() {
                        return None;
                    }
                    found = Some((t.flow.id, direction.opposite()));
                }
            }
        }
        found
    }
}

fn deadline(flow: &Flow) -> Duration {
    // These are inactivity limits from the brief, not TCP socket lifecycle timers.
    flow.last
        .checked_add(Duration::from_secs(if flow.ip_proto == 6 {
            300
        } else {
            60
        }))
        .unwrap_or(Duration::MAX)
}

fn initial_flow(
    id: FlowId,
    protocol: u8,
    endpoints: [Endpoint; 2],
    time: Duration,
    start_seen: bool,
) -> Flow {
    Flow {
        id,
        first_packet: 0,
        last_packet: 0,
        endpoints,
        ip_proto: protocol,
        state: if protocol == 6 {
            if start_seen {
                FlowState::Opening
            } else {
                FlowState::Open
            }
        } else {
            FlowState::Active
        },
        first: time,
        last: time,
        packets: [0; 2],
        payload_bytes: [0; 2],
        acked_bytes: [0; 2],
        retransmissions: 0,
        duplicate_acks: 0,
        resets: 0,
        handshake_time: None,
        server_name: None,
        tls_version: None,
        proto: transport_proto(protocol),
        start_seen,
        story: Vec::new(),
        reset_by: None,
        story_omitted: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_ids_skip_zero() {
        let raw = crate::capture::Reader::open(std::path::Path::new(
            "tests/fixtures/loopback-first20.pcap",
        ))
        .unwrap()
        .nth(16)
        .unwrap()
        .unwrap();
        let decoded = crate::decode::decode(
            raw.link,
            &raw.data,
            raw.orig_len,
            crate::decode::Detail::Summary,
        );
        let mut tracker = Tracker::new();
        tracker.next_id = u32::MAX;
        assert_eq!(tracker.observe(&raw, &decoded).flow, Some(FlowId(1)));
    }
}
