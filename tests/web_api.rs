//! Exercises every JSON API endpoint through the real packet engine.
//! HTTP security stays in `tests/web`; independent JSON parsing stays in log_support.
//! Start with fixture tests, then controls and fixed-seed hostile requests.

// These area helpers include builders used by their original test binaries.
// Reuse their independent JSON reader and packet builders without duplicating them.
#[path = "web_api/control.rs"]
mod control;
#[path = "web_api/fixture.rs"]
mod fixture;
#[allow(dead_code)]
mod flow_support;
#[path = "web_api/hidden.rs"]
mod hidden;
#[path = "web_api/hostile.rs"]
mod hostile;
#[allow(dead_code)]
mod log_support;
#[allow(dead_code, unused_imports)]
mod pipeline_support;
#[path = "web_api/robustness.rs"]
mod robustness;
#[path = "web_api/sockets.rs"]
mod sockets;
#[path = "web_api/support.rs"]
mod support;

#[path = "web_api/edges.rs"]
mod edges;

#[path = "web_api/cli.rs"]
mod cli;

#[path = "web_api/review.rs"]
mod review;
