//! Maps protocol numbers to their display names.
//! Value formatting belongs to `values`; interpretation belongs to `fields`.
//! Start with `service`.

/// Names a TLS extension number; unrecognised numbers return the unknown-extension label.
pub fn tls_extension(n: u16) -> &'static str {
    match n {
        0 => "server name",
        5 => "certificate status request",
        10 => "supported groups",
        11 => "elliptic curve point formats",
        13 => "signature algorithms",
        16 => "application protocols",
        18 => "signed certificate timestamp",
        27 => "certificate compression",
        21 => "padding",
        22 => "encrypt then MAC",
        23 => "extended master secret",
        35 => "session ticket",
        41 => "pre-shared key",
        42 => "early data",
        43 => "supported versions",
        44 => "cookie",
        45 => "pre-shared key exchange modes",
        49 => "post-handshake authentication",
        50 => "certificate signature algorithms",
        51 => "key share",
        65281 => "renegotiation information",
        _ => "unknown extension",
    }
}
/// Formats a TLS wire version; unrecognised numbers retain their hexadecimal value.
pub fn tls_version(n: u16) -> String {
    match n {
        0x300 => "SSL 3.0".into(),
        0x301 => "TLS 1.0".into(),
        0x302 => "TLS 1.1".into(),
        0x303 => "TLS 1.2".into(),
        0x304 => "TLS 1.3".into(),
        _ => format!("version 0x{n:04x}"),
    }
}
/// Formats a DNS record type; unrecognised types retain their numeric value.
pub fn dns_type(n: u16) -> String {
    match n {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        255 => "ANY".into(),
        _ => format!("TYPE{n}"),
    }
}

/// Usual service labels for selected transport ports; a port number alone does not identify an application.
pub const PORTS: &[(u16, &str)] = &[
    (20, "FTP data"),
    (21, "FTP control"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP mail"),
    (37, "Time"),
    (53, "DNS"),
    (67, "DHCP server"),
    (68, "DHCP client"),
    (69, "TFTP"),
    (80, "HTTP"),
    (88, "Kerberos"),
    (110, "POP3 mail"),
    (111, "RPC port mapper"),
    (119, "NNTP news"),
    (123, "NTP clock synchronisation"),
    (135, "Microsoft RPC"),
    (137, "NetBIOS name service"),
    (138, "NetBIOS datagrams"),
    (139, "NetBIOS sessions"),
    (143, "IMAP mail"),
    (161, "SNMP management"),
    (162, "SNMP notifications"),
    (179, "BGP routing"),
    (389, "LDAP directory"),
    (443, "HTTPS / QUIC"),
    (445, "SMB file sharing"),
    (465, "SMTP over TLS"),
    (514, "Syslog / remote shell"),
    (587, "Mail submission"),
    (636, "LDAP over TLS"),
    (853, "DNS over TLS"),
    (993, "IMAP over TLS"),
    (995, "POP3 over TLS"),
    (1433, "Microsoft SQL Server"),
    (1900, "SSDP discovery"),
    (2049, "NFS file sharing"),
    (3306, "MySQL"),
    (3389, "Remote Desktop"),
    (5432, "PostgreSQL"),
    (5353, "mDNS"),
    (6379, "Redis"),
    (8080, "HTTP alternate"),
    (8443, "HTTPS alternate"),
];
/// Display names for selected IP protocol numbers.
pub const IP_PROTOCOLS: &[(u8, &str)] = &[
    (1, "ICMP"),
    (2, "IGMP"),
    (4, "IPv4 encapsulation"),
    (6, "TCP"),
    (17, "UDP"),
    (41, "IPv6 encapsulation"),
    (47, "GRE"),
    (50, "ESP encrypted IP"),
    (51, "AH authenticated IP"),
    (58, "ICMPv6"),
    (89, "OSPF routing"),
    (132, "SCTP"),
];
/// Display names for selected Ethernet payload type numbers.
pub const ETHERTYPES: &[(u16, &str)] = &[
    (0x0800, "IPv4"),
    (0x0806, "ARP"),
    (0x8100, "802.1Q VLAN"),
    (0x86dd, "IPv6"),
    (0x8847, "MPLS"),
    (0x8848, "MPLS multicast"),
    (0x8863, "PPPoE discovery"),
    (0x8864, "PPPoE session"),
    (0x88a8, "provider VLAN"),
    (0x88cc, "LLDP discovery"),
    (0x888e, "802.1X authentication"),
];
/// Returns the usual service for a port, or `None` when this small table has no label.
pub fn service(n: u16) -> Option<&'static str> {
    PORTS.iter().find_map(|(p, s)| (*p == n).then_some(*s))
}

/// Names the delivery reason for an ICMP destination-unreachable code in the selected IP version.
pub(super) fn unreachable(v6: bool, code: u8) -> &'static str {
    match (v6, code) {
        (false, 0) => "the network cannot be reached",
        (false, 1) => "the host cannot be reached",
        (false, 2) => "the destination does not support this protocol",
        (false, 3) | (true, 4) => "nothing listens on that port",
        (false, 4) => "the packet is too large and cannot be split",
        (false, 9 | 10 | 13) | (true, 1) => "a network rule blocks delivery",
        (true, 0) => "there is no route to the destination",
        (true, 2) => "the address is outside the reachable scope",
        (true, 3) => "the address cannot be reached",
        _ => "the destination cannot be reached",
    }
}
/// Names an ICMP message type in the selected IP version; unknown types retain their number.
pub(super) fn icmp_type(v6: bool, kind: u8) -> String {
    match (v6, kind) {
        (false, 0) | (true, 129) => "echo reply".into(),
        (false, 8) | (true, 128) => "echo request".into(),
        (false, 3) | (true, 1) => "destination unreachable".into(),
        (false, 5) => "redirect".into(),
        (false, 11) | (true, 3) => "time exceeded".into(),
        (false, 12) | (true, 4) => "parameter problem".into(),
        (true, 2) => "packet too big".into(),
        (true, 133) => "router solicitation".into(),
        (true, 134) => "router advertisement".into(),
        (true, 135) => "neighbour solicitation".into(),
        (true, 136) => "neighbour advertisement".into(),
        _ => format!("type {kind}"),
    }
}
/// Names a DNS response code, with an unknown-code label for unlisted values.
pub(super) fn dns_rcode(n: u8) -> &'static str {
    match n {
        0 => "success",
        1 => "a malformed query (FORMERR)",
        2 => "a server failure (SERVFAIL)",
        3 => "a missing name (NXDOMAIN)",
        4 => "an unsupported operation (NOTIMP)",
        5 => "a refused query (REFUSED)",
        _ => "an unknown response code",
    }
}
/// Names a DHCP message type, with an unknown-type label for unlisted values.
pub(super) fn dhcp_type(n: u8) -> &'static str {
    match n {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "unknown message type",
    }
}
