//! Provides the packet engine behind authenticated web requests.
//! HTTP access checks stay in `web::routing`; wording stays in `explain::web`.
//! `engine` owns capture and pipeline state; `packets` builds cached filter indexes.
//! `flows` projects conversations; `packet` decodes details; `records` encodes shared values.
//! `state` holds publication state; `store` applies eviction; `control` parses commands.
//! Start with `Engine::start`, then pass `Engine::api` to the HTTP server.

mod control;
mod engine;
mod flows;
mod packet;
mod packets;
mod records;
mod state;
mod store;

use crate::{pipeline, store::DEFAULT_MAX_PACKETS};
pub use engine::{Engine, WebApi};
use std::time::Duration;

/// Source identity and retention policy for one engine, independent of HTTP ports.
pub struct Options {
    /// True for dumpcap, false for saved-file playback.
    pub live: bool,
    /// Interface name or file path; sanitised before it appears in a reply.
    pub source: String,
    /// Session start since the Unix epoch; packet-relative times start at the first packet.
    pub started: Duration,
    /// Retained packet count, clamped to 200,000; zero retains no raw packets.
    pub max_packets: usize,
    /// Logging, recording, alert thresholds and optional background process lookup.
    pub pipeline: pipeline::Options,
}

impl Options {
    /// Creates a file-playback policy with default retention and the supplied pipeline.
    /// Logging and process lookup are determined entirely by `pipeline`.
    pub fn file(source: String, started: Duration, pipeline: pipeline::Options) -> Self {
        Self {
            live: false,
            source,
            started,
            max_packets: DEFAULT_MAX_PACKETS,
            pipeline,
        }
    }
}

#[cfg(test)]
mod paging_tests;
