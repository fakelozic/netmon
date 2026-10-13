//! Entry point for the saved-capture conversation acceptance tests.
//! Builders stay in `flow_support`; focused assertions live beside those builders.
//! Read `fixture_tests` first for the independently recorded fixture facts.
mod flow_support;
use flow_support::*;
#[path = "flow_support/fixture_tests.rs"]
mod fixture_tests;
#[path = "flow_support/names_tests.rs"]
mod names_tests;
#[path = "flow_support/table_tests.rs"]
mod table_tests;
#[path = "flow_support/tcp_tests.rs"]
mod tcp_tests;
