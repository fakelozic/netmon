//! Holds DNS field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use super::meanings::{duration, port_meaning};
use crate::decode::FieldKey as K;
use crate::decode::{Decoded, Field};
use crate::explain::dns_type;
use crate::explain::tables::dns_rcode;

/// Closed set of DNS fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Id,
    Flags,
    Response,
    Opcode,
    Authoritative,
    Truncated,
    RecursionDesired,
    RecursionAvailable,
    Rcode,
    Questions,
    Answers,
    Authorities,
    Additionals,
    Question,
    Name,
    Type,
    Class,
    Unicast,
    Record,
    Ttl,
    Data,
    CacheFlush,
    MxPreference,
    MxExchange,
    SoaPrimary,
    SoaMailbox,
    SoaSerial,
    SoaRefresh,
    SoaRetry,
    SoaExpire,
    SoaMinimum,
    SrvPriority,
    SrvWeight,
    SrvPort,
    SrvTarget,
    OptSize,
    OptRcode,
    OptVersion,
    OptFlags,
    OptCode,
    OptData,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 1035, section 4.1.1.
        Kind::Id => (
            "Transaction identifier",
            "Labels a name lookup so the client can recognise the reply to its question.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Flags => (
            "Flags",
            "Tells the client or server whether this is a question or reply and how the lookup is handled.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Response => (
            "Query or response",
            "Distinguishes a name-lookup question from a reply.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Opcode => (
            "Operation code",
            "Tells the server what kind of name operation the client wants, usually a lookup.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Authoritative => (
            "Authoritative answer",
            "Says the replying server is responsible for the queried name. This is called an authoritative answer.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Truncated => (
            "Truncated response",
            "Warns that the server left out part of the reply because it did not fit.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::RecursionDesired => (
            "Recursion desired",
            "Asks the server to contact other name servers if needed to find the answer.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::RecursionAvailable => (
            "Recursion available",
            "Tells the client that this server can contact other name servers to find answers.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Rcode => (
            "Response code",
            "Tells the client whether the name operation succeeded or why it failed.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Questions => (
            "Question count",
            "Tells the server how many lookup questions follow the header.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Answers => (
            "Answer count",
            "Tells the client how many answer records follow. A record is one named piece of DNS information.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Authorities => (
            "Authority count",
            "Counts records pointing to responsible name servers or describing the part of DNS they manage.",
            "",
        ),
        // RFC 1035, section 4.1.1.
        Kind::Additionals => (
            "Additional count",
            "Counts extra records that help use the answer, such as a name server's IP address.",
            "",
        ),
        // RFC 1035, section 4.1.2.
        Kind::Question => (
            "Question",
            "Asks for a particular kind of information about a name, such as its IPv4 address.",
            "",
        ),
        // RFC 1035, section 4.1.2–4.1.3.
        Kind::Name => (
            "Name",
            "Identifies the name being looked up or described by this DNS record.",
            "",
        ),
        // RFC 1035, section 4.1.2–4.1.3.
        Kind::Type => (
            "Record type",
            "Tells the reader what kind of information is requested or supplied, such as an address or another name.",
            "",
        ),
        // RFC 1035, section 3.2.4.
        Kind::Class => (
            "Record class",
            "Selects which set of DNS naming rules applies. Class 1 is the usual Internet class, for both IPv4 and IPv6.",
            "",
        ),
        // RFC 6762, section 5.4.
        Kind::Unicast => (
            "Unicast response requested",
            "Asks for a local name-lookup reply sent only to this device, instead of to the whole listening group.",
            "",
        ),
        // RFC 1035, section 4.1.3.
        Kind::Record => (
            "Resource record",
            "Gives one piece of information about a name. Most records also say how long a saved copy can be kept.",
            "",
        ),
        // RFC 1035, section 4.1.3.
        Kind::Ttl => (
            "Record time to live",
            "Limits how long a saved DNS answer may be reused, measured in seconds. It does not count routers like the IP TTL.",
            "",
        ),
        // RFC 1035, section 4.1.3.
        Kind::Data => (
            "Record data",
            "Gives the answer's information, such as an IP address, another name, or text.",
            "",
        ),
        // RFC 6762, section 10.2.
        Kind::CacheFlush => (
            "Cache flush",
            "Asks local devices to replace older saved answers with the same name, type, and class.",
            "",
        ),
        // RFC 1035, section 3.3.9.
        Kind::MxPreference => (
            "Mail preference",
            "Helps choose a mail server. Lower numbers are tried first.",
            "",
        ),
        // RFC 1035, section 3.3.9.
        Kind::MxExchange => (
            "Mail exchange",
            "Names the computer that accepts mail for this domain.",
            "",
        ),
        // RFC 1035, section 3.3.13.
        Kind::SoaPrimary => (
            "Primary name server",
            "Names the main server for a group of DNS names managed together, called a zone.",
            "",
        ),
        // RFC 1035, section 3.3.13.
        Kind::SoaMailbox => (
            "Responsible mailbox",
            "Gives the DNS administrator's email address, encoded as a name instead of with an @ sign.",
            "",
        ),
        // RFC 1035, section 3.3.13; RFC 1982, section 3.
        Kind::SoaSerial => (
            "Zone serial",
            "Lets backup name servers notice that their copy of a group of DNS records needs updating.",
            "",
        ),
        // RFC 1035, section 3.3.13.
        Kind::SoaRefresh => (
            "Refresh interval",
            "Tells backup name servers how many seconds to wait between checks for updated records.",
            "",
        ),
        // RFC 1035, section 3.3.13.
        Kind::SoaRetry => (
            "Retry interval",
            "Tells backup name servers how many seconds to wait before retrying a failed update check.",
            "",
        ),
        // RFC 1035, section 3.3.13.
        Kind::SoaExpire => (
            "Expiry interval",
            "Limits how long a backup name server may answer from its copy without a successful update check.",
            "",
        ),
        // RFC 2308, section 4–5.
        Kind::SoaMinimum => (
            "Negative cache duration",
            "Helps limit how long a failed name lookup may be remembered, so a newly created name can be found later.",
            "",
        ),
        // RFC 2782, Priority.
        Kind::SrvPriority => (
            "Service priority",
            "Helps choose a computer offering a service. Lower numbers are tried first.",
            "",
        ),
        // RFC 2782, Weight.
        Kind::SrvWeight => (
            "Service weight",
            "Shares requests among service computers with the same priority. Larger weights usually receive more choices.",
            "",
        ),
        // RFC 2782, Port.
        Kind::SrvPort => (
            "Service port",
            "Tells a client which port to contact for the named service.",
            "",
        ),
        // RFC 2782, Target.
        Kind::SrvTarget => (
            "Service target",
            "Names the computer offering this service.",
            "",
        ),
        // RFC 6891, section 6.1.2.
        Kind::OptSize => (
            "Extended UDP size",
            "Tells the other computer the largest DNS message this computer can receive over UDP, measured in bytes.",
            "",
        ),
        // RFC 6891, section 6.1.3.
        Kind::OptRcode => (
            "Extended response code",
            "Adds more bits to the lookup result code so DNS can report additional kinds of errors.",
            "",
        ),
        // RFC 6891, section 6.1.3.
        Kind::OptVersion => (
            "Extension version",
            "Tells the other computer which version of the extra DNS features is used.",
            "",
        ),
        // RFC 6891, section 6.1.3; RFC 3225, section 3.
        Kind::OptFlags => (
            "Extension flags",
            "Carries extra DNS controls, such as asking for DNSSEC records used to check signed answers.",
            "",
        ),
        // RFC 6891, section 6.1.2.
        Kind::OptCode => (
            "Extension option code",
            "Tells the receiver what one extra DNS setting is for.",
            "",
        ),
        // RFC 6891, section 6.1.2.
        Kind::OptData => (
            "Extension option data",
            "Carries the value of one extra DNS setting as encoded bytes.",
            "",
        ),
    }
}

/// Interprets the field in this packet; an empty string means no further interpretation applies.
pub(super) fn here(key: Kind, field: &Field, packet: &Decoded) -> String {
    let n = field.num.unwrap_or(0);
    match key {
        Kind::SrvPort => port_meaning(n as u16),
        Kind::Rcode if matches!(packet.summary.app, Some(crate::decode::AppInfo::DnsQuery { .. })) => "This is a question, so this field does not report a lookup result.".into(),
        Kind::Rcode => format!("{n} means {}.", dns_rcode(n as u8)),
        Kind::Response => "Set. This is a reply to a name lookup.".into(),
        Kind::Authoritative => "Set. The replying server says it is responsible for the queried name.".into(),
        Kind::Truncated => "Set. Part of the reply was left out, so the client may need to retry over TCP.".into(),
        Kind::RecursionDesired => "Set. The client asks the server to find an answer using other name servers if needed.".into(),
        Kind::RecursionAvailable => "Set. The server offers to find answers using other name servers.".into(),
        Kind::Unicast => "Set. The device asks for a reply sent directly to it.".into(),
        Kind::CacheFlush => "Set. Receivers are asked to replace older saved answers with this name, type, and class.".into(),
        Kind::Class if n == 1 => "Class 1 uses Internet DNS rules. It covers both IPv4 and IPv6 address records.".into(),
        Kind::Opcode if n == 0 => "This is a standard name lookup.".into(),
        Kind::OptFlags if n == 0 => "Not set.".into(),
        Kind::OptFlags if n & 0x8000 != 0 => "DO is set. The sender can receive DNSSEC records used to check signed answers, but this does not prove an answer was checked.".into(),
        Kind::Name if field.value == "." => {
            "This is the root of the Domain Name System name tree.".into()
        }
        Kind::Data if field.range.is_empty() => "No record data bytes are present.".into(),
        Kind::Ttl => format!("A saved copy of this answer may be reused for {}.", duration(n)),
        Kind::Type => {
            let meaning = match n {
                1 => "an IPv4 address",
                28 => "an IPv6 address",
                5 => "an alias to another name",
                2 => "a name server",
                12 => "a name associated with an address or service",
                15 => "a mail server with a preference",
                16 => "text strings",
                6 => "authority and timing for a zone",
                33 => "a service host and port",
                41 => "extended Domain Name System capabilities",
                _ => "a record format identified by this number",
            };
            format!("{}: {meaning}.", dns_type(n as u16))
        }
        Kind::Record
            if field
                .children
                .iter()
                .any(|f| f.key == K::DnsType && f.num == Some(41)) =>
        {
            "This record advertises Domain Name System extensions. It is not a cached name answer."
                .into()
        }
        Kind::Id
        | Kind::Flags
        | Kind::Opcode
        | Kind::Questions
        | Kind::Answers
        | Kind::Authorities
        | Kind::Additionals
        | Kind::Question
        | Kind::Class
        | Kind::MxPreference
        | Kind::MxExchange
        | Kind::SoaPrimary
        | Kind::SoaMailbox
        | Kind::SoaSerial
        | Kind::SoaRefresh
        | Kind::SoaRetry
        | Kind::SoaExpire
        | Kind::SoaMinimum
        | Kind::SrvPriority
        | Kind::SrvWeight
        | Kind::SrvTarget
        | Kind::OptSize
        | Kind::OptRcode
        | Kind::OptVersion
        | Kind::OptFlags
        | Kind::OptCode
        | Kind::OptData
        | Kind::Name
        | Kind::Data
        | Kind::Record => String::new(),
    }
}
