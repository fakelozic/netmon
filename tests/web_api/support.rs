//! Shared direct-API test setup and JSON contract assertions.
//! Packet construction stays in pipeline_support; the decoder owns field ranges.
//! Read `fixture` for a complete file source and `manual` for ordered controls.

use crate::log_support::{Value, number, parse, string};
use netmon::{
    live::{Message, Source},
    pipeline,
    web::{
        Api, ApiReply, Method,
        api::{Engine, Options, WebApi},
    },
};
use std::{
    path::Path,
    sync::mpsc::{self, SyncSender},
    time::Duration,
};

/// Creates file-mode policies with optional logging and no process reads.
pub(super) fn options(log: Option<netmon::log::Options>) -> Options {
    Options::file(
        "loopback-mixed.pcapng".into(),
        Duration::ZERO,
        pipeline::Options {
            log,
            record: false,
            proc_root: None,
            alerts: Default::default(),
        },
    )
}
/// Starts saved-file capture and waits for its terminal engine state.
pub(super) fn fixture() -> (Engine, WebApi) {
    let engine = Engine::start(
        Source::file(Path::new("tests/fixtures/loopback-mixed.pcapng")).unwrap(),
        options(None),
    )
    .unwrap();
    let api = engine.api();
    for _ in 0..1000 {
        if get(&api, "session", &[]).field("state") == Some(&string("ended")) {
            return (engine, api);
        }
        std::thread::yield_now();
    }
    panic!("fixture did not end");
}
/// Starts an engine whose ordered input is controlled by this test.
pub(super) fn manual(
    log: Option<netmon::log::Options>,
    max: usize,
) -> (Engine, WebApi, SyncSender<Message>) {
    let (send, recv) = mpsc::sync_channel(8192);
    let mut opts = options(log);
    opts.max_packets = max;
    let engine = Engine::channel(recv, opts).unwrap();
    let api = engine.api();
    (engine, api, send)
}
/// Submits a bounded request and validates every success or error JSON reply.
pub(super) fn request(
    api: &WebApi,
    method: Method,
    path: &str,
    query: &[(&str, &str)],
    body: &[u8],
) -> ApiReply {
    let query: Vec<_> = query
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect();
    let reply = api.handle(method, path, &query, body);
    parse(&reply.json).expect("every API reply is valid JSON");
    reply
}
/// Asserts a successful GET and returns its independently parsed document.
pub(super) fn get(api: &WebApi, path: &str, query: &[(&str, &str)]) -> Value {
    let reply = request(api, Method::Get, path, query, b"");
    assert_eq!(reply.status, 200, "{}", reply.json);
    parse(&reply.json).unwrap()
}
/// Asserts a successful control and returns its independently parsed document.
pub(super) fn control(api: &WebApi, body: &[u8]) -> Value {
    let reply = request(api, Method::Post, "control", &[], body);
    assert_eq!(reply.status, 200, "{}", reply.json);
    parse(&reply.json).unwrap()
}
/// Borrows a required array field; a wrong type fails the test.
pub(super) fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    match value.field(key).unwrap() {
        Value::Array(values) => values,
        other => panic!("{key} is {other:?}"),
    }
}
/// Borrows a required string field; a wrong type fails the test.
pub(super) fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    match value.field(key).unwrap() {
        Value::String(text) => text,
        other => panic!("{key} is {other:?}"),
    }
}
/// Reads an exact nonnegative integer field without floating-point rounding.
pub(super) fn num(value: &Value, key: &str) -> u64 {
    match value.field(key).unwrap() {
        Value::Number(n) => n.parse().unwrap(),
        other => panic!("{key} is {other:?}"),
    }
}
/// Asserts that every named contract field is present, including null values.
pub(super) fn keys(value: &Value, names: &[&str]) {
    for key in names {
        assert!(value.field(key).is_some(), "missing {key}: {value:?}");
    }
}
/// Waits for a packet count, asserting content rather than elapsed scan speed.
pub(super) fn wait_packets(api: &WebApi, count: u64) {
    for _ in 0..1000 {
        if get(api, "session", &[]).field("packets") == Some(&number(count)) {
            return;
        }
        std::thread::yield_now();
    }
    panic!("engine did not reach {count} packets");
}
