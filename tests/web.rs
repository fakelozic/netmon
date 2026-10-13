//! Exercises the web core without requiring a page build or network access.
//! Helpers live in `web/mod.rs`; only `web/sockets.rs` opens real loopback sockets.
//! Read the parser tests first, then the access-rule and response-header tests.

#[path = "web/build.rs"]
mod build;
#[path = "web/headers.rs"]
mod headers;
#[path = "web/parser.rs"]
mod parser;
#[path = "web/robustness.rs"]
mod robustness;
#[path = "web/rules.rs"]
mod rules;
#[path = "web/sockets.rs"]
mod sockets;
#[path = "web/mod.rs"]
mod support;
#[path = "web/token.rs"]
mod token;
