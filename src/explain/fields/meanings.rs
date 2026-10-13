//! Interprets addresses, ports and counters shared by field families.
//! Static field definitions belong to each family module.
//! Start with `address_meaning`.

use crate::explain::{service, values::count};
use crate::text::number;

/// Interprets the advertised receive capacity from this packet; missing TCP context gives no text.
pub(super) fn window_meaning(n: u64, tcp: Option<&crate::decode::TcpInfo>) -> String {
    let Some(t) = tcp else {
        return String::new();
    };
    // Reset packets do not offer space for data (RFC 9293, section 3.5.2).
    if t.flags & 4 != 0 {
        return format!(
            "The window field is {}, but this reset stops or refuses the connection. Its window is not an offer to receive data.",
            number(n)
        );
    }
    if n == 0 {
        return "The receiver reports zero space for ordinary data. The other computer must wait for the window to open, apart from small probes checking for space.".into();
    }
    // SYN windows are never scaled, even when scaling is offered (RFC 7323, section 2.2).
    if t.flags & 2 != 0 {
        return format!(
            "The receiver offers space for {} data bytes. Opening packets always use the window without a multiplier.",
            number(n)
        );
    }
    let Some(scale) = t.window_scale else {
        return format!(
            "The window field is {}. A multiplier may have been agreed during setup, so this packet alone cannot show the receive space in bytes.",
            number(n)
        );
    };
    // Window scaling is limited to an exponent of 14 (RFC 7323, section 2.3).
    if scale > 14 {
        return format!(
            "Scale {} exceeds the limit of 14. The window field is {}, but a valid receive size cannot be calculated.",
            number(u64::from(scale)),
            number(n)
        );
    }
    let multiplier = 1u64.checked_shl(u32::from(scale)).unwrap_or(0);
    format!(
        "With multiplier {}, the receiver offers space for {} data bytes.",
        number(multiplier),
        number(n.saturating_mul(multiplier))
    )
}

/// Interprets the group and local-administration bits of a formatted MAC address; unreadable values give no text.
pub(super) fn mac_meaning(value: &str) -> String {
    let bytes = value
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect::<Vec<_>>();
    if bytes == [0; 6] {
        "All zeros: no device address is supplied.".into()
    } else if bytes == [255; 6] {
        "This is broadcast: every device on the local link can receive it.".into()
    } else if let Some(first) = bytes.first() {
        format!(
            "This is a {} address. Its bits indicate that it was {}.",
            if first & 1 != 0 {
                "multicast group"
            } else {
                "single-device"
            },
            if first & 2 != 0 {
                "chosen locally rather than assigned by the hardware maker"
            } else {
                "assigned from the globally managed address space"
            }
        )
    } else {
        String::new()
    }
}
/// Classifies a formatted IP address without asserting reachability; unreadable values give no text.
pub(super) fn address_meaning(value: &str) -> String {
    let category = match value.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => {
            let [first, second, third, _] = a.octets();
            if a.is_unspecified() {
                "unspecified: no address is assigned"
            } else if a.is_loopback() {
                "loopback: traffic stays on this computer"
            } else if a.is_private() {
                "private: used inside local networks"
            } else if a.is_link_local() {
                "link-local: used only on the attached network"
            } else if a.is_multicast() {
                "multicast: addressed to a group"
            } else if a.is_broadcast() {
                "broadcast: addressed to every host on a network"
            } else if a.is_documentation() {
                "reserved for documentation"
            } else if first == 0
                || first >= 240
                || first == 100 && (64..=127).contains(&second)
                || first == 198 && matches!(second, 18 | 19)
                || first == 192 && second == 0 && third == 0
            {
                "special-use: public reachability is not established"
            } else {
                "probably public: its presence here does not prove reachability"
            }
        }
        Ok(std::net::IpAddr::V6(a)) => {
            if a.is_unspecified() {
                "unspecified: no address is assigned"
            } else if a.is_loopback() {
                "loopback: traffic stays on this computer"
            } else if a.is_multicast() {
                "multicast: addressed to a group"
            } else if a.is_unicast_link_local() {
                "link-local: used only on the attached network"
            } else if a.is_unique_local() {
                "private: intended for use inside local networks"
            } else if (u128::from(a) >> 96) == 0x20010db8 {
                "reserved for documentation"
            } else {
                "probably public: its presence here does not prove reachability"
            }
        }
        _ => return String::new(),
    };
    format!("{value} is {category}.")
}
/// Explains a port using a usual service label or its allocation range, preserving uncertainty about the application.
pub(super) fn port_meaning(n: u16) -> String {
    if let Some(s) = service(n) {
        format!(
            "Port {n} is usually used for {s}. A program can use a different port, so this is a clue about the service."
        )
    // The dynamic/private port range starts at 49152 (RFC 6335, section 6).
    } else if n >= 49152 {
        format!(
            "Port {} is in the range set aside for temporary or private use. The operating system often picks a temporary port for a client.",
            n
        )
    } else {
        format!(
            "Port {} has no usual service listed in netmon. It may be chosen by the program or temporarily assigned by the operating system.",
            n
        )
    }
}
/// Explains a remaining hop count using an explicitly uncertain starting-value estimate.
pub(super) fn hop_meaning(n: u64) -> String {
    if n == 0 {
        return "The counter is zero, so a router must not forward this packet. The original count is unknown.".into();
    }
    if n == 1 {
        return "The counter is 1, so a router cannot forward this packet. A deliberately small starting count is possible, so this does not show how far it travelled.".into();
    }
    // Below half the smallest guessed default, decline a distance estimate rather than suggest a very long route.
    if n <= 32 {
        return format!(
            "The counter is {n}, so at most {} more routers can forward this packet. The starting count is unknown, so no travelled distance can be inferred.",
            n.saturating_sub(1)
        );
    }
    // Starting at 64, 128 or 255 is a common convention, not an RFC rule or an observed fact.
    if let Some(start) = [64u64, 128, 255].into_iter().find(|v| *v >= n) {
        let hops = start.saturating_sub(n);
        if hops == 0 {
            format!(
                "The counter is {n}. Systems often start at 64, 128 or 255, so this packet has probably crossed no routers."
            )
        } else {
            format!(
                "The counter is {n}. If it started at the common value of {start}, it has crossed about {hops} routers."
            )
        }
    } else {
        format!(
            "{n} exceeds the eight-bit counter's maximum of 255. No route length can be inferred."
        )
    }
}
/// Formats a DNS cache duration in seconds using the largest exact whole unit; zero says not to cache.
pub(super) fn duration(n: u64) -> String {
    if n == 0 {
        "0 seconds (do not cache it)".into()
    } else if n.is_multiple_of(86400) {
        count(n / 86400, "day")
    } else if n.is_multiple_of(3600) {
        count(n / 3600, "hour")
    } else if n.is_multiple_of(60) {
        count(n / 60, "minute")
    } else {
        count(n, "second")
    }
}
/// The eight TCP flags with individual explanatory fields.
#[derive(Clone, Copy)]
pub(super) enum Flag {
    Syn,
    Ack,
    Fin,
    Rst,
    Psh,
    Urg,
    Ece,
    Cwr,
}

/// Explains one TCP control flag; clear bits return the required brief wording.
pub(super) fn flag_meaning(k: Flag, set: bool) -> &'static str {
    if !set {
        return "Not set.";
    }
    match k {
        Flag::Syn => "Set. The sender proposes a starting byte number to open a connection.",
        Flag::Ack => {
            "Set. The acknowledgment number tells the other computer which byte is expected next."
        }
        Flag::Fin => "Set. The sender has finished sending data but can still receive it.",
        Flag::Rst => "Set. The sender stops or refuses the connection.",
        Flag::Psh => {
            "Set. The sender asks for the waiting data to be passed to the receiving program."
        }
        Flag::Urg => "Set. The urgent pointer locates the end of data needing special attention.",
        Flag::Ece => {
            "Set. This reports a busy router, or helps agree to use congestion reports during setup."
        }
        Flag::Cwr => {
            "Set. This reports that sending slowed down, or helps agree to use congestion reports during setup."
        }
    }
}

/// Explains an unverified transport checksum without treating capture offload as corruption.
pub(super) fn transport_checksum(value: &str) -> String {
    format!(
        "{} has not been checked by netmon. A network card may calculate it after capture, so an outgoing packet can appear to have a bad checksum.",
        value
    )
}
