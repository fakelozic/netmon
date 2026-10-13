//! Explains DNS packet facts in one sentence.
//! Field definitions belong to `crate::explain::fields`; dispatch belongs to `super`.
//! Start with `query`.

use crate::decode::Proto;
use crate::explain::{dns_type, tables::dns_rcode};

/// Formats the decoded query facts without reading packet bytes.
pub(super) fn query(d: &crate::decode::Decoded, name: &str, qtype: &u16) -> String {
    let s = &d.summary;
    if s.proto == Proto::Mdns {
        format!("Asks the local network: who is {name}?")
    } else {
        match qtype {
            1 => format!("Asks: what is the IPv4 address of {name}?"),
            28 => format!("Asks: what is the IPv6 address of {name}?"),
            12 => format!("Asks: what name belongs to {}?", reverse_name(name)),
            _ => format!("Asks for the {} record of {name}", dns_type(*qtype)),
        }
    }
}

/// Formats the decoded response facts without reading packet bytes.
pub(super) fn response(
    d: &crate::decode::Decoded,
    name: &str,
    qtype: &u16,
    rcode: &u8,
    answers: &[crate::decode::DnsAnswer],
) -> String {
    let s = &d.summary;
    let name = if name.is_empty() {
        answers.first().map(|a| a.name.as_str()).unwrap_or("")
    } else {
        name
    };
    if s.proto == Proto::Mdns {
        format!(
            "Tells the local network: {name} is {}",
            answers
                .first()
                .map(|a| a.value.as_str())
                .unwrap_or("unreported")
        )
    } else if *rcode == 3 {
        format!("Answer: {name} does not exist (NXDOMAIN)")
    } else if *rcode == 2 {
        format!("Answer: the DNS server could not look up {name} (SERVFAIL)")
    } else if *rcode != 0 {
        format!(
            "Answer: the DNS server reports {} for {name}",
            dns_rcode(*rcode)
        )
    } else {
        let addresses = answers
            .iter()
            .filter(|a| matches!(a.rr_type, 1 | 28))
            .collect::<Vec<_>>();
        if let Some(first) = addresses.first() {
            let mut text = format!("Answer: {name} is {}", first.value);
            if addresses.len() > 1 {
                text.push_str(&format!(" (and {} more)", addresses.len() - 1));
            }
            if let Some(alias) = answers.iter().find(|a| a.rr_type == 5) {
                text.push_str(&format!(" (via {})", alias.value));
            }
            text
        } else if let Some(first) = answers.first() {
            format!(
                "Answer: {name} has {} {}",
                dns_type(first.rr_type),
                first.value
            )
        } else {
            format!("Answer: {name} has no {} record", dns_type(*qtype))
        }
    }
}

fn reverse_name(name: &str) -> String {
    if let Some(s) = name.strip_suffix(".in-addr.arpa") {
        let labels = s.split('.').collect::<Vec<_>>();
        if labels.len() == 4 && labels.iter().all(|s| s.parse::<u8>().is_ok()) {
            return labels.into_iter().rev().collect::<Vec<_>>().join(".");
        }
    }
    if let Some(s) = name.strip_suffix(".ip6.arpa") {
        let digits = s.split('.').collect::<Vec<_>>();
        if digits.len() == 32
            && digits
                .iter()
                .all(|s| s.len() == 1 && s.chars().all(|c| c.is_ascii_hexdigit()))
        {
            let hex = digits.into_iter().rev().collect::<String>();
            if let Ok(n) = u128::from_str_radix(&hex, 16) {
                return std::net::Ipv6Addr::from(n).to_string();
            }
        }
    }
    name.into()
}
