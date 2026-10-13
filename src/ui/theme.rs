//! Supplies the packet screen colours.
//! Rendering belongs to packets and details; this file only returns styles.
//! Read protocol first for protocol colours and warning for problem rows.
//! A protocol label identifies how the observed packet was decoded.
use crate::decode::Proto;
use ratatui::style::{Color, Modifier, Style};
/// Ordinary pane text.
pub(super) fn base() -> Style {
    Style::default().fg(Color::Gray)
}
/// The focused pane border or active hint.
pub(super) fn focus() -> Style {
    Style::default().fg(Color::Cyan)
}
/// The selected row, using background and bold as well as its marker.
pub(super) fn selected() -> Style {
    Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD)
}
/// Problem row text; rows also carry a visible exclamation mark.
pub(super) fn warning() -> Style {
    Style::default().fg(Color::Yellow)
}
/// Selected byte ranges in both the hex and ASCII columns.
pub(super) fn bytes() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}
/// Protocol row colour; the protocol name remains visible without colour.
pub(super) fn protocol(proto: Proto) -> Style {
    Style::default().fg(match proto {
        Proto::Dns | Proto::Mdns => Color::Cyan,
        Proto::Http => Color::Green,
        Proto::Tls | Proto::Quic => Color::Magenta,
        Proto::Icmp | Proto::Icmpv6 | Proto::Arp => Color::Yellow,
        Proto::Tcp => Color::Blue,
        _ => Color::Gray,
    })
}
