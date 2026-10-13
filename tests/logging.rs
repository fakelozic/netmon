//! Entry point for the logging library's integration checks.
//! Focused assertions live in `log/`; reusable fixtures and JSON parsing
//! live in `log_support`. Read `log/session.rs` first for the session contract.

mod log_support;

#[path = "log/clock.rs"]
mod clock;
#[path = "log/json.rs"]
mod json;
#[path = "log/markdown.rs"]
mod markdown;
#[path = "log/record.rs"]
mod record;
#[path = "log/session.rs"]
mod session;
