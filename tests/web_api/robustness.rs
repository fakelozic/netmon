//! Exercises bounded invalid request handling with a reproducible generator.
//! Endpoint semantics stay in fixture.rs; real HTTP parsing stays in tests/web.
//! Read `fixed_seed_paths_queries_and_bodies_never_panic` for the finite input scope.

use super::support::*;
use crate::log_support::parse;
use netmon::web::{Api, Method};

#[test]
fn fixed_seed_paths_queries_and_bodies_never_panic() {
    let (_engine, api) = fixture();
    let mut seed = 0x8f91_7b03_425e_1cadu64;
    let mut random = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let names = [
        "session", "packets", "packet/", "flows", "flow/", "alerts", "glossary", "control",
        "unknown",
    ];
    for _ in 0..5000 {
        let name = names[random() as usize % names.len()];
        let value: String = (0..random() % 40)
            .map(|_| char::from((random() % 95 + 32) as u8))
            .collect();
        let path = if name.ends_with('/') {
            format!("{name}{value}")
        } else {
            name.into()
        };
        let query = vec![(
            if random() % 2 == 0 { "filter" } else { "limit" }.into(),
            value.clone(),
        )];
        let method = if name == "control" {
            Method::Post
        } else {
            Method::Get
        };
        let reply = api.handle(method, &path, &query, value.as_bytes());
        parse(&reply.json).unwrap();
        assert!([200, 400, 404].contains(&reply.status), "{}", reply.json);
    }
}
#[test]
fn unknown_paths_methods_and_failed_capture_are_json_errors() {
    let (_engine, api, send) = manual(None, 200000);
    for path in ["", "not-real", "session/no", "packetish/3"] {
        let reply = request(&api, Method::Get, path, &[], b"");
        assert_eq!(reply.status, 404);
    }
    assert_eq!(request(&api, Method::Post, "session", &[], b"").status, 400);
    send.send(netmon::live::Message::Failed("bad\n\x1b file".into()))
        .unwrap();
    let session = get(&api, "session", &[]);
    assert_eq!(text(&session, "state"), "failed");
    assert_eq!(text(&session, "error"), "bad\\x0A\\x1B file");
}
