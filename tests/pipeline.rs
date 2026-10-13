//! Integration checks for the capture-to-row pipeline.
//! Byte builders live in `pipeline_support`; focused checks live in `pipeline/`.
//! Read fixture.rs first for the saved capture contract.

#[path = "pipeline/apps.rs"]
mod apps;
#[path = "pipeline/behaviour.rs"]
mod behaviour;
#[path = "pipeline/fixture.rs"]
mod fixture;
mod log_support;
#[path = "pipeline/markdown.rs"]
mod markdown;
mod pipeline_support;
#[path = "pipeline/robustness.rs"]
mod robustness;
#[path = "pipeline/summary.rs"]
mod summary;
