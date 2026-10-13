//! Exposes the wording used by packet views and higher-level consumers.
//! Parsing belongs to `decode`; output layout belongs to `render` and the screen.
//! Start with `sentence`.

/// Exposes traffic alert rules.
pub mod alerts;
/// Exposes conversation wording.
pub mod flows;
/// Exposes session log writers.
pub mod log;
pub mod pipeline;

mod cli;
mod fields;
mod glossary;
mod sentence;
mod tables;
pub mod ui;
mod values;
pub mod web;

pub use cli::{COMMAND_ERROR, FILE_ERROR, HELP, LIVE_NOT_BUILT, MODE_ERROR, PACKET_NUMBER_ERROR};
pub use fields::{FieldText, field_text};
pub use glossary::GLOSSARY;
pub use sentence::sentence;
pub use tables::{ETHERTYPES, IP_PROTOCOLS, PORTS, dns_type, service, tls_extension, tls_version};
pub use values::{
    CHECKSUM_INCOMPLETE, HIDDEN_HEADER, byte_count, checksum_status, encrypted, http_header_value,
    http_sensitive_header, tcp_flags,
};
