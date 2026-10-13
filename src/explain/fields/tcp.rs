//! Holds TCP field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use super::meanings::transport_checksum;
use super::meanings::{Flag, flag_meaning, port_meaning, window_meaning};
use crate::decode::{Decoded, Field};
use crate::text::number;

/// Closed set of TCP fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Src,
    Dst,
    Seq,
    Ack,
    Offset,
    Flags,
    Cwr,
    Ece,
    Urg,
    AckFlag,
    Psh,
    Rst,
    Syn,
    Fin,
    Window,
    Checksum,
    Urgent,
    Options,
    Mss,
    Scale,
    SackPermitted,
    Sack,
    SackLeft,
    SackRight,
    Timestamp,
    TimestampValue,
    TimestampEcho,
    Nop,
    End,
    UnknownOption,
    Payload,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 9293, section 3.1.
        Kind::Src => (
            "Source port",
            "Identifies the sending program's port. The IP address finds the computer, and the port helps find the program on it.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Dst => (
            "Destination port",
            "Helps deliver data to the right program. The IP address finds the computer, and the port helps find the program on it.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Seq => (
            "Sequence number",
            "Numbers data bytes so the receiver can put them in order and notice gaps. It gives the first data byte number, or the starting number when SYN is set.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Ack => (
            "Acknowledgment number",
            "Returns a byte number to the other computer when ACK is set. In normal data exchange, it confirms earlier bytes arrived and names the next expected byte.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Offset => (
            "Data offset",
            "Tells the receiver where the TCP header ends and the data begins, including any extra header settings.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Flags => (
            "Flags",
            "Tells the other computer whether to open or close a connection, confirm receipt, or handle data specially.",
            "",
        ),
        // RFC 3168, section 6.1.
        Kind::Cwr => (
            "CWR",
            "Reports that the sender slowed down after a busy router was reported. During connection setup it helps agree to use congestion reports.",
            "",
        ),
        // RFC 3168, section 6.1.
        Kind::Ece => (
            "ECE",
            "Reports that a router marked traffic as too busy. During connection setup it helps agree to use congestion reports.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Urg => (
            "URG",
            "Marks the urgent pointer as valid, so the receiver can find the end of data needing special attention.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::AckFlag => (
            "ACK",
            "Marks the acknowledgment number as valid, so the other computer can see which bytes arrived.",
            "",
        ),
        // RFC 9293, section 3.9.1.1.
        Kind::Psh => (
            "PSH",
            "Asks the receiver to pass the waiting data to its program without waiting for more data.",
            "",
        ),
        // RFC 9293, section 3.5.2.
        Kind::Rst => (
            "RST",
            "Stops the connection immediately or refuses an attempted connection.",
            "A reset does not by itself reveal why the connection fails.",
        ),
        // RFC 9293, section 3.4.
        Kind::Syn => (
            "SYN",
            "Starts opening a connection by sharing the byte number from which this computer will count.",
            "",
        ),
        // RFC 9293, section 3.6.
        Kind::Fin => (
            "FIN",
            "Tells the other computer that the sender has finished sending data. It can still receive data.",
            "The other direction can remain open.",
        ),
        // RFC 9293, section 3.8.6.
        Kind::Window => (
            "Window",
            "Tells the sender how much more data the receiver says it can take now. This keeps a fast sender from overwhelming a slow receiver.",
            "A zero window asks the other computer to pause sending ordinary data until space is available.",
        ),
        // RFC 9293, section 3.1.
        Kind::Checksum => (
            "Checksum",
            "Helps detect damaged TCP header or data bytes using a calculated check number, called a checksum. It also covers the IP addresses.",
            "A checksum can detect accidental damage, but it does not prove who sent the packet.",
        ),
        // RFC 9293, section 3.1.
        Kind::Urgent => (
            "Urgent pointer",
            "Locates the end of urgent data, meaning data needing special attention, when URG is set. It is an offset from this packet's sequence number.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Options => (
            "Options",
            "Carries extra TCP settings or reports, such as a data size limit or which out-of-order bytes arrived.",
            "",
        ),
        // RFC 9293, section 3.7.1.
        Kind::Mss => (
            "Maximum segment size",
            "Tells the other computer the largest amount of TCP data this computer can receive in one packet, excluding IP and TCP headers.",
            "A smaller value can be normal on a path that needs smaller packets.",
        ),
        // RFC 7323, section 2.
        Kind::Scale => (
            "Window scale",
            "Offers a multiplier for later receive windows, so TCP can advertise space larger than its fixed window field allows.",
            "Both computers must offer scaling during setup before it can be used. Opening packets always use the unscaled window.",
        ),
        // RFC 2018, section 2.
        Kind::SackPermitted => (
            "Selective acknowledgment permitted",
            "Allows the other computer to report which data arrived beyond a gap, so missing bytes can be sent again.",
            "",
        ),
        // RFC 2018, section 3.
        Kind::Sack => (
            "Selective acknowledgment blocks",
            "Reports ranges of bytes that arrived beyond a gap. This helps the sender resend missing data instead of everything after the gap.",
            "",
        ),
        // RFC 2018, section 3.
        Kind::SackLeft => (
            "Left edge",
            "Marks the first received byte in one reported range beyond a gap.",
            "",
        ),
        // RFC 2018, section 3.
        Kind::SackRight => (
            "Right edge",
            "Marks the byte immediately after the last received byte in one reported range beyond a gap.",
            "",
        ),
        // RFC 7323, section 3.
        Kind::Timestamp => (
            "Timestamps",
            "Helps measure how long a reply takes and distinguish old packets from current ones, using counters from both computers.",
            "",
        ),
        // RFC 7323, section 3.2.
        Kind::TimestampValue => (
            "Timestamp value",
            "Gives the sender's current timing counter so the other computer can echo it back.",
            "",
        ),
        // RFC 7323, section 3.2.
        Kind::TimestampEcho => (
            "Timestamp echo",
            "Copies a timing counter received from the other computer so it can measure how long the exchange took.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Nop => (
            "No operation",
            "Adds one padding byte so another TCP option can start at a convenient position.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::End => (
            "End of option list",
            "Tells the receiver that the TCP options have ended and any following header bytes are padding.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::UnknownOption => (
            "Unknown option",
            "Carries a TCP setting netmon does not recognise. Its type and length let the receiver skip it.",
            "",
        ),
        // RFC 9293, section 3.1.
        Kind::Payload => (
            "Payload size",
            "Shows how many data bytes the packet headers declare after the TCP header. A cut-short capture may contain fewer bytes.",
            "",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, field: &Field, packet: &Decoded) -> String {
    let n = field.num.unwrap_or(0);
    match key {
        Kind::Src | Kind::Dst => port_meaning(n as u16),
        Kind::Seq | Kind::Ack => sequence_meaning(key, n, packet),
        Kind::Cwr => flag_text(n, Flag::Cwr),
        Kind::Ece => flag_text(n, Flag::Ece),
        Kind::Urg => flag_text(n, Flag::Urg),
        // A reset may acknowledge a refused SYN or data without accepting a connection (RFC 9293, section 3.5.2).
        Kind::AckFlag
            if n != 0
                && packet
                    .summary
                    .tcp
                    .as_ref()
                    .is_some_and(|t| t.flags & 4 != 0) =>
        {
            "Set. The acknowledgment number is part of a connection refusal or abort.".into()
        }
        Kind::AckFlag => flag_text(n, Flag::Ack),
        Kind::Psh => flag_text(n, Flag::Psh),
        Kind::Rst => flag_text(n, Flag::Rst),
        Kind::Syn => flag_text(n, Flag::Syn),
        Kind::Fin => flag_text(n, Flag::Fin),
        Kind::Window => window_meaning(n, packet.summary.tcp.as_ref()),
        Kind::Mss => format!(
            "The sender can receive up to {} TCP data bytes in one packet. IP and TCP header bytes are extra.",
            number(n)
        ),
        Kind::Checksum => transport_checksum(&field.value),
        Kind::Offset => format!(
            "{} bytes belong to the TCP header, including {} bytes of extra settings.",
            number(n),
            number(n.saturating_sub(20))
        ),
        Kind::Scale => scale_meaning(n),
        Kind::Urgent => {
            if packet
                .summary
                .tcp
                .as_ref()
                .is_some_and(|t| t.flags & 32 != 0)
            {
                format!(
                    "The urgent data ends at an offset of {} from this packet's sequence number.",
                    number(n)
                )
            } else {
                "This pointer is ignored because URG is not set.".into()
            }
        }
        Kind::Flags
        | Kind::Options
        | Kind::SackPermitted
        | Kind::Sack
        | Kind::SackLeft
        | Kind::SackRight
        | Kind::Timestamp
        | Kind::TimestampValue
        | Kind::TimestampEcho
        | Kind::Nop
        | Kind::End
        | Kind::UnknownOption
        | Kind::Payload => String::new(),
    }
}

fn flag_text(n: u64, flag: Flag) -> String {
    flag_meaning(flag, n != 0).into()
}

fn scale_meaning(n: u64) -> String {
    // RFC 7323, sections 2.2–2.3: both sides must offer scaling; maximum shift is 14.
    if n > 14 {
        format!(
            "{} exceeds the maximum scale of 14. This is not a valid multiplier offer.",
            number(n)
        )
    } else {
        let multiplier = 1u64.checked_shl(n as u32).unwrap_or(0);
        format!(
            "Scale {n} offers a multiplier of {} for later windows. It takes effect only if both computers offer scaling during setup.",
            number(multiplier)
        )
    }
}

fn sequence_meaning(key: Kind, n: u64, packet: &Decoded) -> String {
    // Reset numbers identify the rejected traffic, not an ordinary receive acknowledgment (RFC 9293, section 3.5.2).
    if packet
        .summary
        .tcp
        .as_ref()
        .is_some_and(|t| t.flags & 4 != 0)
    {
        return if key == Kind::Ack {
            format!(
                "This reset carries acknowledgment number {}. It identifies refused or aborted traffic, without promising that data was accepted.",
                n
            )
        } else {
            format!(
                "This reset carries sequence number {}. Its meaning depends on the packet or connection being refused or stopped.",
                n
            )
        };
    }
    if key == Kind::Seq {
        // SYN precedes the first data byte in sequence space (RFC 9293, section 3.4).
        if packet
            .summary
            .tcp
            .as_ref()
            .is_some_and(|t| t.flags & 2 != 0)
        {
            format!(
                "The starting number is {}. SYN uses this number, so the first data byte starts at the next number.",
                n
            )
        } else {
            format!(
                "The byte number is {}. Comparing it with other packets helps locate gaps or repeated data.",
                n
            )
        }
    } else if packet
        .summary
        .tcp
        .as_ref()
        .is_some_and(|t| t.flags & 16 != 0)
    {
        format!(
            "{} is the next byte number expected from the other computer. The sender reports receipt of earlier bytes in this connection.",
            n
        )
    } else {
        format!("{} does not confirm receipt because ACK is not set.", n)
    }
}
