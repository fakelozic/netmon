//! Supplies wording for the packet screen.
//! Field-specific explanations remain in explain::field_text.
//! Read HELP for commands, KEY_HELP for interaction, and layer for protocol purpose.
//! Network headers describe delivery rules; they do not authenticate the sender.
use crate::{
    decode::{Proto, Summary},
    text,
};
/// Command-line usage for the packet screen and existing text commands.
pub const HELP: &str = "netmon [-i IFACE] [-f CAPTURE_FILTER] [--max-packets N]\nnetmon -r FILE [--max-packets N]\nnetmon web [-i IFACE | -r FILE] [-f CAPTURE_FILTER] [--port N] [--no-open]\n           [--log-dir DIR] [--record] [--no-log] [--max-packets N]\nnetmon interfaces\nnetmon explain <FILE|-> [--tsv | --fields | --packet N]\nnetmon glossary [TERM]\nnetmon --help | --version\n\nScreen keys: ? help, g glossary, / filter, q quit\n";
/// Display wording for screen requires terminal.
pub const SCREEN_REQUIRES_TERMINAL: &str =
    "the screen needs a terminal; try: netmon explain <file>";
/// Install advice naming both the Wireshark package and permission group.
pub(crate) const INSTALL_DUMPCAP: &str = "cannot find the capture program; install dumpcap from the Wireshark package and add your user to the wireshark group";
/// Display wording for pipe error.
pub(crate) const PIPE_ERROR: &str = "cannot open the capture program's output pipe";
/// Display wording for no interface.
pub(crate) const NO_INTERFACE: &str =
    "no suitable capture interface is available; use netmon interfaces, then netmon -i NAME";
/// Display wording for max packets error.
pub const MAX_PACKETS_ERROR: &str = "max-packets must be between 1 and 200000";
/// Display wording for screen options error.
pub const SCREEN_OPTIONS_ERROR: &str = "choose a saved file or live capture options";
/// Display wording for capture advice.
pub(crate) const CAPTURE_ADVICE: &str = "Check the interface and capture filter. Install Wireshark's dumpcap and check membership of the wireshark group. Press i to choose an interface, or q to quit.";
/// Recovery advice for a saved-file read failure, without unavailable live controls.
pub(crate) const FILE_ADVICE: &str = "Check that the file exists and is a complete pcap or pcapng capture. Press q to quit, or use netmon explain FILE for text output.";
/// Display wording for filter too long.
pub(crate) const FILTER_TOO_LONG: &str = "use a filter of at most 4096 bytes";
/// Display wording for filter too complex.
pub(crate) const FILTER_TOO_COMPLEX: &str = "use fewer terms or fewer nested brackets";
/// Display wording for filter quote.
pub(crate) const FILTER_QUOTE: &str = "expected a closing quote";
/// Display wording for filter operator.
pub(crate) const FILTER_OPERATOR: &str = "expected and, or, or the end of the filter";
/// Display wording for filter close.
pub(crate) const FILTER_CLOSE: &str = "expected a closing bracket";
/// Display wording for filter term.
pub(crate) const FILTER_TERM: &str = "expected a protocol, search word, or bracketed filter";
/// Display wording for filter value.
pub(crate) const FILTER_VALUE: &str = "expected a value after port, host, or app";
/// Display wording for filter port.
pub(crate) const FILTER_PORT: &str = "expected a port number from 0 to 65535";
/// Display wording for too small.
pub(crate) const TOO_SMALL: &str =
    "Terminal too small. Resize to at least 60 columns and 15 rows. Press q to quit.";
/// Display wording for wait live.
pub(crate) const WAIT_LIVE: &str = "Waiting for packets. Open a web page or ping a host to generate traffic. Press i to choose an interface.";
/// Display wording for wait file.
pub(crate) const WAIT_FILE: &str = "Reading the capture file. Packets appear as they are read.";
/// Display wording for no matches.
pub(crate) const NO_MATCHES: &str =
    "No packets match this filter. Press c to clear it or / to change it.";
/// Display wording for empty file.
pub(crate) const EMPTY_FILE: &str = "This capture contains no packets.";
/// Display wording for filter hint.
pub(crate) const FILTER_HINT: &str =
    "/ filter   f conversation   c clear   Space pause   Tab pane   q quit";
/// Display wording for filter edit.
pub(crate) const FILTER_EDIT: &str = "Filter: ";
/// Display wording for filter keys.
pub(crate) const FILTER_KEYS: &str =
    "Enter applies; Esc cancels. Example: dns or (tcp and port 443)";
/// Display wording for tabs.
pub(crate) const TABS: &str = "[1] Packets";
/// Display wording for tab hints.
pub(crate) const TAB_HINTS: &str = "? help  g glossary";
/// Display wording for layers.
pub(crate) const LAYERS: &str = "Layers";
/// Display wording for explain.
pub(crate) const EXPLAIN: &str = "Explain";
/// Display wording for bytes.
pub(crate) const BYTES: &str = "Bytes";
/// Display wording for packets.
pub(crate) const PACKETS: &str = "Packets";
/// Prefix for a field definition.
pub(crate) const WHAT: &str = "What: ";
/// Prefix for the meaning of a field in this packet.
pub(crate) const HERE: &str = "Here: ";
/// Prefix for a field consequence.
pub(crate) const WHY: &str = "Why: ";
/// Display wording for help title.
pub(crate) const HELP_TITLE: &str = "Help - Esc closes";
/// Display wording for glossary title.
pub(crate) const GLOSSARY_TITLE: &str = "Glossary - type to search; Esc closes";
/// Display wording for interfaces title.
pub(crate) const INTERFACES_TITLE: &str = "Interfaces - Enter chooses; Esc closes";
/// Display wording for interfaces loading.
pub(crate) const INTERFACES_LOADING: &str = "Reading the interface list...";
/// Display wording for no glossary.
pub(crate) const NO_GLOSSARY: &str = "No glossary terms match your search.";
/// Packet metadata headings in left-to-right order, followed by the sentence heading.
pub(crate) const COLUMN_LABELS: [&str; 7] = [
    "No",
    "Time",
    "From",
    "To",
    "Proto",
    "Bytes",
    "What is happening",
];
/// Keyboard, mouse, filter, and sensitive-byte behaviour shown by the help overlay.
pub(crate) const KEY_HELP: &str = "netmon explains the packets you select.\n\n1                 Packets tab\nTab / Shift-Tab   Move between panes; switch details on small screens\nArrows / j k      Move in the focused pane\nPgUp / PgDn       Move one page\nHome / End        First / last; End follows new packets\nEnter / Left / Right   Open / close layers and fields\nSpace             Pause / resume following (capture continues)\n/                 Edit display filter; Enter applies; Esc cancels\nf                 Filter to this packet's conversation\nc                 Clear the display filter\nt                 Seconds since start / local clock time\ni                 Choose capture interface (live mode)\ng                 Search the networking glossary\n?                 Open this help\nq / Ctrl-C        Quit\n\nClick selects a row or field. The wheel scrolls its pane.\nDisplay filters: tcp udp icmp arp dns mdns dhcp http tls quic ip ipv6\nport N, host TEXT, app TEXT, problem, and, or, not, (brackets).\nOther words search the packet sentence. Quotes keep words together.\nThis view currently has no learned hostnames or app labels.\nBytes marked ** and ASCII * hide sensitive HTTP headers.";
/// Formats sanitized child stderr; empty input reports a failure with no diagnostic.
pub(crate) fn capture_failed(stderr: &str) -> String {
    if stderr.is_empty() {
        "capture program failed without an error message".into()
    } else {
        format!("Capture failed: {stderr}")
    }
}
/// Formats a parser message with a zero-based byte position.
pub(crate) fn filter_error(position: usize, message: &str) -> String {
    format!("At byte {position}: {message}")
}
/// Already-sanitized header values; counts include all arrivals and retained matches.
pub(crate) struct Header<'a> {
    pub mode: &'a str,
    pub source: &'a str,
    /// All arrivals since this capture started, including dropped packets.
    pub total: u64,
    /// Current matching row count; may be partial during rebuilding.
    pub shown: usize,
    /// Packets discarded by storage limits.
    pub dropped: u64,
    /// Observed bytes in the current packet-timestamp second, not a wall-clock measurement.
    pub rate: u64,
    /// True for live capture; files show duration and total wire bytes instead.
    pub live: bool,
    /// Packet-time span since the first arrival; zero for empty captures.
    pub duration: std::time::Duration,
    /// Original wire bytes across all arrivals, independent of retention limits.
    pub total_bytes: u64,
    /// Active filter label; empty means every packet.
    pub filter: &'a str,
    /// Whether historical filter evaluation is still in progress.
    pub rebuilding: bool,
}
/// Formats counts plus live rate or file totals; empty filter means all packets.
pub(crate) fn header(header: Header<'_>) -> String {
    let Header {
        mode,
        source,
        total,
        shown,
        dropped,
        rate,
        live,
        duration,
        total_bytes,
        filter,
        rebuilding,
    } = header;
    let dropped = if dropped > 0 {
        format!("  {} dropped", text::number(dropped))
    } else {
        String::new()
    };
    let filter = if filter.is_empty() { "all" } else { filter };
    let statistics = if live {
        format!("{} B/s", text::number(rate))
    } else {
        format!(
            "{}.{:06} s  {} bytes",
            duration.as_secs(),
            duration.subsec_micros(),
            text::number(total_bytes)
        )
    };
    format!(
        "netmon {mode}  {} packets / {} shown  {statistics}{dropped}\n{source}  filter: {filter}{}",
        text::number(total),
        text::number(shown as u64),
        if rebuilding { " (updating)" } else { "" }
    )
}
/// Names the selected protocol in the Layers pane border.
pub(crate) fn layer_title(proto: Proto) -> String {
    format!("Layers - {}", proto.name())
}
/// Labels a single detail pane with the key that switches its visible content.
pub(crate) fn detail_title(title: &str, single: bool) -> String {
    if single {
        format!("{title} - Tab switches")
    } else {
        title.into()
    }
}
/// Selects PAUSED before LIVE or FILE; pausing changes following, not capture.
pub(crate) fn mode(live: bool, paused: bool) -> &'static str {
    if paused {
        "PAUSED"
    } else if live {
        "● LIVE"
    } else {
        "FILE"
    }
}
/// Formats an editable display filter using both addresses, both ports, and transport.
pub(crate) fn conversation(summary: &Summary) -> String {
    let mut terms = Vec::new();
    if let Some(src) = &summary.src {
        terms.push(format!("host {}", text::address(src)));
    }
    if let Some(dst) = &summary.dst {
        terms.push(format!("host {}", text::address(dst)));
    }
    if let Some(port) = summary.src_port {
        terms.push(format!("port {port}"));
    }
    if let Some(port) = summary.dst_port {
        terms.push(format!("port {port}"));
    }
    match summary.ip_proto {
        Some(6) => terms.push("tcp".into()),
        Some(17) => terms.push("udp".into()),
        _ => {}
    }
    terms.join(" and ")
}
/// Explains the purpose of one protocol; fields retain their separate detailed wording.
pub(crate) fn layer(proto: Proto) -> &'static str {
    // Protocol purposes follow their base specifications: Ethernet/IP layering
    // (RFC 1122, 2-3), TCP streams (RFC 9293, 2.2), UDP messages (RFC 768),
    // DNS (RFC 1035, 1), DHCP (RFC 2131, 1), HTTP (RFC 9110, 1), TLS hello and
    // encryption (RFC 8446, 2), and QUIC over UDP (RFC 9000, 1).
    match proto {
        Proto::Ethernet => {
            "Ethernet delivers a frame across the local link, using hardware addresses."
        }
        Proto::LinuxCooked => {
            "Linux cooked capture describes the interface and link information recorded by Linux."
        }
        Proto::Arp => {
            "Address Resolution Protocol asks which hardware address belongs to a local IPv4 address."
        }
        Proto::Ipv4 => {
            "Internet Protocol version 4 addresses packets and lets routers forward them toward a destination."
        }
        Proto::Ipv6 => {
            "Internet Protocol version 6 uses larger addresses and lets routers forward packets toward a destination."
        }
        Proto::Icmp | Proto::Icmpv6 => {
            "Internet Control Message Protocol carries ping requests, replies and network error reports."
        }
        Proto::Tcp => {
            "Transmission Control Protocol provides an ordered byte stream. Sequence numbers and acknowledgments let the peers detect missing data."
        }
        Proto::Udp => {
            "User Datagram Protocol delivers individual messages to ports. It does not promise delivery or ordering."
        }
        Proto::Dns | Proto::Mdns => {
            "Domain Name System maps names to addresses and other records. Multicast DNS asks nearby devices on the local link."
        }
        Proto::Dhcp => {
            "Dynamic Host Configuration Protocol lets a device request an address and network settings."
        }
        Proto::Http => {
            "Hypertext Transfer Protocol carries web requests and responses. These packets are readable because they are not encrypted."
        }
        Proto::Tls => {
            "Transport Layer Security negotiates encryption. Hello messages can be readable, but encrypted application contents are hidden."
        }
        Proto::Quic => {
            "QUIC carries encrypted streams over UDP. Packet headers identify connections, but the application contents are hidden."
        }
        Proto::Data => {
            "These payload bytes have no recognized protocol here. A port label is a convention, not proof of the application."
        }
    }
}

/// Column heading when both packet endpoints share one narrow-screen cell.
pub(crate) const COMBINED_ENDPOINTS: &str = "From → To";
/// Combines already abbreviated endpoint values without hiding packet direction.
pub(crate) fn combined_endpoints(from: &str, to: &str) -> String {
    format!("{from} → {to}")
}
