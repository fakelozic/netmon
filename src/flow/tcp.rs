//! TCP sequence evidence in a wrapping 32-bit number space.
//! Table ownership stays in `table`; story grouping stays in `story`.
//! Read `Tracked::tcp` for the order of sequence, handshake, ACK, and close decisions.
use super::*;
use crate::decode::TcpInfo;

// TCP counts bytes modulo 2^32; comparisons are valid within half that space
// (RFC 9293, 3.4). The signed distance also works when a sequence wraps past zero.
fn lift(seq: u32, reference: i64) -> i64 {
    reference.saturating_add(i64::from(seq.wrapping_sub(reference as u32) as i32))
}

fn insert_span(ranges: &mut Vec<Span>, mut span: Span) {
    if span.start >= span.end {
        return;
    }
    ranges.retain(|old| {
        if old.end < span.start || old.start > span.end {
            true
        } else {
            span.start = span.start.min(old.start);
            span.end = span.end.max(old.end);
            false
        }
    });
    ranges.push(span);
    ranges.sort_unstable_by_key(|s| s.start);
    // Retain recent evidence when a hostile stream creates too many disjoint gaps.
    if ranges.len() > MAX_RANGES {
        ranges.remove(0);
    }
}

impl Side {
    fn record(&mut self, seq: i64, tcp: &TcpInfo) {
        // SYN and FIN each consume a sequence number, but carry no payload byte
        // (RFC 9293, 3.4). Keep their ranges apart from the acknowledged data count.
        let syn = i64::from(tcp.flags & SYN != 0);
        let fin = i64::from(tcp.flags & FIN != 0);
        let data_start = seq.saturating_add(syn);
        let data_end = data_start.saturating_add(i64::from(tcp.payload_len));
        insert_span(
            &mut self.seen,
            Span {
                start: seq,
                end: data_end.saturating_add(fin),
            },
        );
        if let Some(mut next) = self.next {
            for range in &self.seen {
                if range.start <= next && range.end > next {
                    next = range.end;
                }
            }
            self.next = Some(next);
        }
        insert_span(
            &mut self.outstanding,
            Span {
                start: self
                    .acknowledged
                    .map(|a| a.max(data_start))
                    .unwrap_or(data_start),
                end: data_end,
            },
        );
        if syn != 0 && self.syn.is_none() {
            self.syn = Some(seq);
        }
        if fin != 0 && self.fin.is_none() {
            self.fin = Some(data_end);
        }
    }

    fn confirm(&mut self, confirmed: i64) -> u64 {
        let mut bytes = 0u64;
        for span in &mut self.outstanding {
            let stop = confirmed.min(span.end).max(span.start);
            bytes = bytes.saturating_add(stop.saturating_sub(span.start) as u64);
            span.start = stop;
        }
        self.outstanding.retain(|s| s.start < s.end);
        self.acknowledged = Some(
            self.acknowledged
                .map(|old| old.max(confirmed))
                .unwrap_or(confirmed),
        );
        if self.fin.is_some_and(|n| confirmed > n) {
            self.fin_acked = true;
        }
        bytes
    }
}

impl Tracked {
    /// Update TCP evidence from a complete header; packet time is an epoch duration.
    pub(super) fn tcp(
        &mut self,
        tcp: &TcpInfo,
        direction: Direction,
        time: Duration,
        notes: &mut Vec<Note>,
    ) {
        // Record SYN before matching its ACK, and count ACKs before checking a close.
        // Reordering these decisions would miss handshake steps or the final FIN ACK.
        self.sequence(tcp, direction, notes);
        self.handshake(tcp, direction, time, notes);
        self.acknowledge(tcp, direction, notes);
        if tcp.flags & (SYN | FIN | RST) == 0 && tcp.window == 0 {
            notes.push(Note::ZeroWindow);
        }
        self.finish(tcp, direction, notes);
    }

    fn sequence(&mut self, tcp: &TcpInfo, direction: Direction, notes: &mut Vec<Note>) {
        let side = direction.index();
        let both_known = self.sides.iter().all(|s| s.next.is_some());
        let syn = tcp.flags & SYN != 0;
        let fin = tcp.flags & FIN != 0;
        let rst = tcp.flags & RST != 0;
        let seq = self.sides[side]
            .next
            .map(|n| lift(tcp.seq, n))
            .unwrap_or(i64::from(tcp.seq));
        if !rst && self.sides[side].next.is_none() {
            self.sides[side].next = Some(seq);
        }
        if syn && direction == Direction::Forward && self.hello_next.is_none() {
            self.hello_next = Some(tcp.seq.wrapping_add(1));
        }
        // A keep-alive deliberately uses the previous byte, with zero or one byte
        // of payload. Do not mistake that probe for retransmitted data (RFC 1122, 4.2.3.6).
        let keep_alive = !syn
            && !fin
            && !rst
            && tcp.payload_len <= 1
            && self.sides[side]
                .next
                .is_some_and(|n| seq == n.saturating_sub(1));
        if keep_alive {
            notes.push(Note::KeepAlive);
        }
        let len = i64::from(tcp.payload_len)
            .saturating_add(i64::from(syn))
            .saturating_add(i64::from(fin));
        if len == 0 || keep_alive || rst {
            return;
        }
        let end = seq.saturating_add(len);
        // A capture that starts midstream has no earlier sequence baseline. A SYN
        // is different: its repeat is visible even before the other side responds.
        if (both_known || syn)
            && self.sides[side]
                .seen
                .iter()
                .any(|s| seq < s.end && end > s.start)
        {
            notes.push(Note::Retransmission);
            self.flow.retransmissions = self.flow.retransmissions.saturating_add(1);
        } else if tcp.payload_len > 0 && self.sides[side].next.is_some_and(|n| seq > n) {
            notes.push(Note::Gap);
        }
        self.sides[side].record(seq, tcp);
    }

    fn handshake(
        &mut self,
        tcp: &TcpInfo,
        direction: Direction,
        time: Duration,
        notes: &mut Vec<Note>,
    ) {
        let syn = tcp.flags & SYN != 0;
        let ack = tcp.flags & ACK != 0;
        if tcp.flags & RST != 0 {
            return;
        }
        let other = direction.opposite().index();
        // The peer must acknowledge the SYN before the three-way handshake can
        // be considered complete (RFC 9293, 3.5).
        let syn_confirmed = self.sides[other].syn.is_some_and(|n| lift(tcp.ack, n) > n);
        if syn && !ack {
            if !self.flow.start_seen {
                self.flow.start_seen = true;
                self.flow.state = FlowState::Opening;
            }
            self.syn_time.get_or_insert(time);
            notes.push(Note::HandshakeStep(1));
        } else if syn && ack {
            notes.push(Note::HandshakeStep(2));
            if direction == Direction::Reverse && self.flow.start_seen && syn_confirmed {
                self.syn_ack_seen = true;
                if let Some(start) = self.syn_time {
                    let elapsed = time.saturating_sub(start);
                    self.flow.handshake_time.get_or_insert(elapsed);
                    notes.push(Note::HandshakeTime(elapsed));
                }
            }
        } else if ack
            && self.flow.state == FlowState::Opening
            && direction == Direction::Forward
            && self.syn_ack_seen
            && syn_confirmed
        {
            self.flow.state = FlowState::Open;
            notes.push(Note::HandshakeStep(3));
        }
    }

    fn acknowledge(&mut self, tcp: &TcpInfo, direction: Direction, notes: &mut Vec<Note>) {
        if tcp.flags & ACK == 0 || tcp.flags & RST != 0 {
            return;
        }
        let side = direction.index();
        let other = direction.opposite().index();
        let receiver = &mut self.sides[other];
        let Some(next) = receiver.next else { return };
        let bytes = receiver.confirm(lift(tcp.ack, next));
        if bytes > 0 {
            self.flow.acked_bytes[other] = self.flow.acked_bytes[other].saturating_add(bytes);
            notes.push(Note::AckedBytes(bytes));
        }
        // An unchanged ACK/window is a duplicate only while data is outstanding;
        // exclude SYN, FIN and keep-alives from that test (RFC 5681, 2).
        let outstanding = !receiver.outstanding.is_empty();
        let sender = &mut self.sides[side];
        let control = tcp.flags & (SYN | FIN) != 0;
        if tcp.payload_len == 0
            && !control
            && !notes.contains(&Note::KeepAlive)
            && outstanding
            && sender.last_ack == Some((tcp.ack, tcp.window))
        {
            sender.duplicate_count = sender.duplicate_count.saturating_add(1);
            notes.push(Note::DuplicateAck(sender.duplicate_count));
            self.flow.duplicate_acks = self.flow.duplicate_acks.saturating_add(1);
        } else {
            sender.duplicate_count = 0;
        }
        sender.last_ack = (!control).then_some((tcp.ack, tcp.window));
    }

    fn finish(&mut self, tcp: &TcpInfo, direction: Direction, notes: &mut Vec<Note>) {
        if tcp.flags & RST != 0 {
            self.flow.resets = self.flow.resets.saturating_add(1);
            self.flow.reset_by = Some(direction);
            let other = direction.opposite().index();
            // A reset answering the opening SYN refuses that attempt. A later
            // reset aborts an established exchange (RFC 9293, 3.5.2).
            if direction == Direction::Reverse
                && self.flow.state == FlowState::Opening
                && self.flow.start_seen
                && !self.syn_ack_seen
                && tcp.flags & ACK != 0
                && self.sides[other].syn.is_some_and(|n| lift(tcp.ack, n) > n)
            {
                self.flow.state = FlowState::Refused;
                notes.push(Note::Refused);
            } else {
                self.flow.state = FlowState::Reset;
                notes.push(Note::Reset);
            }
            self.done = true;
        } else if !self.done {
            if tcp.flags & FIN != 0 {
                self.flow.state = FlowState::Closing;
            }
            // FIN closes only one sending direction. Both FINs and their ACKs
            // are needed for a complete polite close (RFC 9293, 3.6).
            if self.sides.iter().all(|s| s.fin.is_some() && s.fin_acked) {
                self.flow.state = FlowState::Closed;
                self.done = true;
                notes.push(Note::ClosedPolitely);
            }
        }
    }
}
