//! Builds beginner wording for observed alert patterns.
//! Detection belongs to `crate::alerts`; these functions receive only safe scalar values.
//! Read `Text` first to see the four parts of each explanation.
//! A matching network pattern does not identify its cause or establish malicious intent.

use crate::text::{mac, number};
use std::fmt::Write;
use std::net::IpAddr;
use std::time::Duration;

/// Wording for one observation; credential values and raw packet text are never inputs.
pub(crate) struct Text {
    pub title: String,
    pub seen: String,
    pub why: &'static str,
    pub next: &'static str,
}

/// Cleartext protocol recognized by the packet-local credential rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialProtocol {
    Http,
    Ftp,
    Telnet,
}

/// Character counts from wire DNS labels, before display escaping.
pub(crate) struct DnsShape {
    pub name_len: usize,
    pub longest_label: usize,
    /// Zero means no label meets the 24-character/4-bit entropy criterion.
    pub random_label_len: usize,
    /// Shannon entropy in bits per wire character of the qualifying label, or zero.
    pub entropy: f64,
}

fn duration(value: Duration) -> String {
    let seconds = value.as_secs_f64();
    if seconds >= 1.0 {
        format!("{seconds:.1} s")
    } else if seconds >= 0.001 {
        format!("{:.0} ms", seconds * 1_000.0)
    } else if seconds >= 0.000_001 {
        format!("{:.0} µs", seconds * 1_000_000.0)
    } else {
        format!("{} ns", value.as_nanos())
    }
}

/// Describes distinct destination ports in an inclusive packet-time window.
pub(crate) fn port_scan(
    source: IpAddr,
    destination: IpAddr,
    ports: usize,
    window: Duration,
) -> Text {
    // SYN initiates TCP synchronization; UDP has no connection handshake
    // (RFC 9293, 3.5; RFC 768, Format). A usual service port does not identify its program.
    Text {
        title: format!("Port scan pattern from {source}"),
        seen: format!(
            "{source} sends TCP connection requests or UDP packets to {} different ports on {destination} within the last {}.",
            number(ports as u64),
            duration(window)
        ),
        why: "TCP opens a reliable byte stream and UDP sends independent messages to ports, the numbered entry points for network services. Trying many ports quickly can reveal which services are listening. Diagnostic tools and software on your own computer can also do this, so the pattern does not prove an attack.",
        next: "Check whether you or an administrator ran a service discovery tool, and inspect the first and triggering packets for the destination ports.",
    }
}

/// Describes a credential pattern by protocol/server only, never a login value.
/// Telnet data establishes exposure risk, not that an actual login occurred.
pub(crate) fn credentials(protocol: CredentialProtocol, server: IpAddr, port: u16) -> Text {
    // Authorization and proxy authorization carry credentials (RFC 9110, 11.6.2/11.7.2).
    // FTP USER/PASS are login commands (RFC 959, 4.1.1). Neither proves credential theft.
    let (name, seen, why, next) = match protocol {
        CredentialProtocol::Http => (
            "HTTP",
            "An HTTP request carries an authorization header. Login credentials are sent without encryption, and their values are hidden.",
            "HTTP carries web requests and replies. Without Transport Layer Security (TLS), someone who can read this traffic can copy the login credentials. This observation shows exposed credentials, not that someone has used them.",
            "Check that the client uses HTTPS, which protects HTTP with TLS, before sending credentials. Check the server or proxy configuration for an encrypted login endpoint.",
        ),
        CredentialProtocol::Ftp => (
            "FTP",
            "An FTP login command sends a user name or password without encryption. The login value is hidden.",
            "File Transfer Protocol (FTP) transfers files, but its unencrypted login commands expose the user name or password. Someone who can read this traffic can copy that value. Seeing the command does not show that anyone has copied it.",
            "Check that the client uses SFTP, an encrypted file transfer service, or FTP with Transport Layer Security (TLS). Disable unencrypted logins on the server if they are not needed.",
        ),
        CredentialProtocol::Telnet => (
            "Telnet",
            "Telnet data is exchanged without encryption. Any login sent this way is exposed, but this packet alone does not establish that a login occurred.",
            "Telnet provides a remote terminal without encrypting its data. Someone who can read the traffic can read a login sent through it. Other Telnet data can trigger this pattern too.",
            "Check which program uses this connection and whether the server offers SSH for an encrypted remote terminal.",
        ),
    };
    Text {
        title: format!("Unencrypted {name} login pattern at {server}"),
        seen: format!("Server {server}, port {port}. {seen}"),
        why,
        next,
    }
}

/// Describes a sender mapping change with both six-byte MAC addresses and innocent causes.
pub(crate) fn arp_change(ip: IpAddr, old: [u8; 6], new: [u8; 6], gateway: bool) -> Text {
    // ARP learns sender hardware/protocol address associations (RFC 826, Packet Reception).
    Text {
        title: format!(
            "ARP mapping changes for {ip}{}",
            if gateway { " (gateway)" } else { "" }
        ),
        seen: format!(
            "ARP now associates {ip} with {}, after previously associating it with {}.",
            mac(&new),
            mac(&old)
        ),
        why: "Address Resolution Protocol (ARP) maps an IPv4 address to a MAC address, the address used to reach a device on the local link. A changed mapping can redirect traffic to a different device. It also happens innocently when a device is replaced or an address is reassigned.",
        next: "Compare both MAC addresses with the device or router's settings and check for a planned replacement or address reassignment. Repeated switching without an expected change deserves investigation.",
    }
}

const DNS_WHY: &str = "DNS tunnelling hides other data inside name lookups to carry it past network controls. Name-guessing malware tries many possible names to find a server it can contact. Content networks also use long random names, and these patterns do not prove either activity.";
const DNS_NEXT: &str = "Check which program makes these lookups and whether the domain belongs to a service you use. Compare nearby queries and replies to see whether names keep changing or repeatedly fail.";

/// Reports name/label lengths and qualifying entropy without reproducing queried text.
pub(crate) fn dns_name(client: IpAddr, shape: &DnsShape) -> Text {
    let mut seen = format!(
        "{client} sends a DNS query, a request to look up a name, with {} characters in the name and {} in its longest label (the part between dots).",
        number(shape.name_len as u64),
        number(shape.longest_label as u64)
    );
    if shape.random_label_len > 0 {
        let _ = write!(
            seen,
            " A {}-character label has {:.2} bits per character of entropy, a measure of character variety.",
            number(shape.random_label_len as u64),
            shape.entropy
        );
    }
    Text {
        title: format!("Unusual DNS name from {client}"),
        seen,
        why: DNS_WHY,
        next: DNS_NEXT,
    }
}

/// Describes at least `count` missing-name responses received inside a packet-time window.
pub(crate) fn dns_failures(client: IpAddr, count: usize, window: Duration) -> Text {
    Text {
        title: format!("Repeated missing DNS names for {client}"),
        seen: format!(
            "{client} receives at least {} NXDOMAIN replies within the last {}. DNS looks up names, and NXDOMAIN means the requested name does not exist.",
            number(count as u64),
            duration(window)
        ),
        why: DNS_WHY,
        next: DNS_NEXT,
    }
}

/// Describes a SYN+ACK acceptance with a usual service name, without claiming a completed login.
pub(crate) fn inbound(remote: IpAddr, local: IpAddr, port: u16) -> Text {
    // SYN, SYN+ACK and final ACK are distinct steps (RFC 9293, 3.5).
    // An observed acceptance reply must not be described as a completed handshake.
    let service = super::service(port).unwrap_or("no usual service name known");
    Text {
        title: format!("Accepted inbound connection request from {remote}"),
        seen: format!(
            "{remote} sends a TCP SYN connection request to this computer at {local}, port {port} (usually {service}). This computer replies with SYN+ACK."
        ),
        why: "TCP starts a connection with a SYN request and a SYN+ACK acceptance reply. This reply indicates a listening service accepts a request from a public address, although the final handshake step has not yet been observed. The service may be intentional, so this is not proof of an intrusion.",
        next: "Check which program listens on this port and whether you intend it to accept outside connections. Check the host firewall and router forwarding rules for that service.",
    }
}

/// Usage shown when the saved-capture example is missing its single capture path.
pub const EXAMPLE_USAGE: &str = "usage: cargo run --offline --example alerts -- <CAPTURE>";
/// Prefix for sanitized errors from the saved-capture example.
pub const EXAMPLE_ERROR: &str = "cannot read alerts from capture";

/// Display label for an informational pattern.
pub(crate) const NOTICE: &str = "Notice";
/// Display label for a pattern warranting investigation.
pub(crate) const WARNING: &str = "Warning";
/// Display label for exposed credentials or a changed gateway mapping.
pub(crate) const SERIOUS: &str = "Serious";

/// Formats safe alert fields. Packet numbers are capture numbers, not buffer offsets.
/// The caller supplies sanitized text; the formatter never reads raw traffic or credentials.
pub(crate) fn printed(
    severity: &str,
    title: &str,
    packets: (u64, u64),
    explanation: (&str, &str, &str),
) -> String {
    format!(
        "{severity}: {}\nPackets: {} to {}\nSeen: {}\nWhy: {}\nNext: {}\n\n",
        title, packets.0, packets.1, explanation.0, explanation.1, explanation.2
    )
}
