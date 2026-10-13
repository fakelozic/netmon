//! Checks fixture counts, packet fields and conversation stories against the contract.
//! Engine setup stays in support; malicious text and controls have their own tests.
//! Read `session_and_pages` for the fixture's independently documented totals.

use super::support::*;
use crate::log_support::{Value, number, string};
use netmon::web::Method;

#[test]
fn session_and_pages() {
    let (_engine, api) = fixture();
    let session = get(&api, "session", &[]);
    keys(
        &session,
        &[
            "version",
            "mode",
            "source",
            "state",
            "error",
            "started",
            "packets",
            "dropped",
            "bytes",
            "conversations",
            "alerts",
            "rate",
            "log_dir",
            "recording",
            "problem",
        ],
    );
    assert_eq!(session.field("packets"), Some(&number(75)));
    assert_eq!(session.field("conversations"), Some(&number(12)));
    assert_eq!(session.field("state"), Some(&string("ended")));
    assert_eq!(session.field("bytes"), Some(&number(17_764)));
    assert_eq!(session.field("log_dir"), Some(&Value::Null));
    assert!(array(&session, "rate").len() <= 60);
    let rows = get(&api, "packets", &[]);
    keys(&rows, &["total", "matched", "filter_error", "rows"]);
    assert_eq!(array(&rows, "rows").len(), 75);
    for row in array(&rows, "rows") {
        keys(
            row,
            &[
                "no",
                "time",
                "clock",
                "src",
                "dst",
                "src_label",
                "dst_label",
                "app",
                "proto",
                "bytes",
                "info",
                "problem",
                "alerts",
                "flow",
                "dir",
            ],
        );
    }
}
#[test]
fn paging_and_bad_queries() {
    let (_engine, api) = fixture();
    let after = get(&api, "packets", &[("after", "70"), ("limit", "2")]);
    assert_eq!(
        array(&after, "rows")
            .iter()
            .map(|r| num(r, "no"))
            .collect::<Vec<_>>(),
        [71, 72]
    );
    let before = get(&api, "packets", &[("before", "10"), ("limit", "3")]);
    assert_eq!(
        array(&before, "rows")
            .iter()
            .map(|r| num(r, "no"))
            .collect::<Vec<_>>(),
        [7, 8, 9]
    );
    let dns = get(&api, "packets", &[("filter", "dns")]);
    assert_eq!(array(&dns, "rows").len(), 8);
    assert_eq!(num(&dns, "matched"), 8);
    assert_eq!(
        array(
            &get(
                &api,
                "packets",
                &[("before", "13"), ("limit", "2"), ("filter", "dns")]
            ),
            "rows"
        )
        .iter()
        .map(|r| num(r, "no"))
        .collect::<Vec<_>>(),
        [11, 12]
    );
    let error = get(&api, "packets", &[("filter", "port")]);
    keys(
        error.field("filter_error").unwrap(),
        &["position", "message"],
    );
    assert!(array(&error, "rows").is_empty());
    for query in [
        vec![("limit", "0")],
        vec![("limit", "501")],
        vec![("after", "x")],
        vec![("before", "-1")],
        vec![("after", "1"), ("before", "2")],
        vec![("unknown", "x")],
        vec![("limit", "1"), ("limit", "2")],
    ] {
        assert_eq!(
            request(&api, Method::Get, "packets", &query, b"").status,
            400
        );
    }
}
#[test]
fn packet_details_have_ordered_layers_and_checked_ranges() {
    let (_engine, api) = fixture();
    let packet = get(&api, "packet/18", &[]);
    keys(
        &packet,
        &[
            "no",
            "time",
            "clock",
            "info",
            "wire_len",
            "captured_len",
            "truncated",
            "flow",
            "hex",
            "hidden",
            "layers",
        ],
    );
    let len = num(&packet, "captured_len");
    assert!(array(&packet, "hidden").is_empty());
    assert_eq!(text(&packet, "hex").len() as u64, 2 * len);
    assert!(
        text(&packet, "hex")
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let layers = array(&packet, "layers");
    assert_eq!(
        layers.iter().map(|l| text(l, "proto")).collect::<Vec<_>>(),
        ["Ethernet", "IPv4", "TCP"]
    );
    for layer in layers {
        keys(layer, &["proto", "range", "line", "about", "fields"]);
        check_range(layer, len);
        for field in array(layer, "fields") {
            check_field(field, len);
        }
    }
    assert_eq!(
        request(&api, Method::Get, "packet/9999", &[], b"").status,
        404
    );
    assert_eq!(
        request(&api, Method::Get, "packet/no", &[], b"").status,
        400
    );
}
fn check_range(value: &Value, len: u64) {
    let range = array(value, "range");
    assert_eq!(range.len(), 2);
    let n = |v: &Value| match v {
        Value::Number(n) => n.parse::<u64>().unwrap(),
        _ => panic!("bad range"),
    };
    assert!(n(&range[0]) <= n(&range[1]) && n(&range[1]) <= len);
}
fn check_field(value: &Value, len: u64) {
    keys(
        value,
        &["label", "value", "range", "what", "here", "why", "children"],
    );
    assert!(!text(value, "label").is_empty());
    check_range(value, len);
    for child in array(value, "children") {
        check_field(child, len);
    }
}
#[test]
fn flows_stories_sorting_alerts_and_glossary() {
    let (_engine, api) = fixture();
    let list = get(&api, "flows", &[]);
    assert_eq!(num(&list, "total"), 12);
    for flow in array(&list, "flows") {
        flow_keys(flow);
    }
    let tls = array(&list, "flows")
        .iter()
        .find(|f| f.field("remote_name") == Some(&string("netmon.test")))
        .unwrap();
    assert_eq!(tls.field("app_proto"), Some(&string("TLS 1.3")));
    let story = get(&api, &format!("flow/{}", num(tls, "id")), &[]);
    flow_keys(&story);
    let steps = array(&story, "story");
    assert_eq!(
        steps
            .iter()
            .take(3)
            .map(|s| text(s, "kind"))
            .collect::<Vec<_>>(),
        ["syn", "syn_ack", "handshake_ack"]
    );
    assert_eq!(
        steps
            .iter()
            .take(3)
            .map(|s| text(s, "dir"))
            .collect::<Vec<_>>(),
        ["out", "in", "out"]
    );
    let mut previous = 0;
    for (index, step) in steps.iter().enumerate() {
        keys(
            step,
            &[
                "n",
                "dir",
                "kind",
                "text",
                "first_packet",
                "last_packet",
                "at_ms",
                "took_ms",
                "packets",
                "bytes",
                "problem",
            ],
        );
        assert_eq!(num(step, "n"), index as u64 + 1);
        assert!(num(step, "first_packet") >= previous);
        previous = num(step, "last_packet");
    }
}
#[test]
fn sorting_limits_alerts_and_glossary() {
    let (_engine, api) = fixture();
    for sort in ["bytes", "problems"] {
        let sorted = get(&api, "flows", &[("sort", sort)]);
        let rows = array(&sorted, "flows");
        let amount = |f: &Value| {
            if sort == "bytes" {
                num(f, "up_bytes") + num(f, "down_bytes")
            } else {
                num(f, "problems")
            }
        };
        assert!(
            rows.windows(2)
                .all(|pair| amount(&pair[0]) >= amount(&pair[1]))
        );
    }
    assert_eq!(
        array(&get(&api, "flows", &[("limit", "1")]), "flows").len(),
        1
    );
    for query in [vec![("sort", "wrong")], vec![("limit", "1001")]] {
        assert_eq!(request(&api, Method::Get, "flows", &query, b"").status, 400);
    }
    let alerts = get(&api, "alerts", &[]);
    assert_eq!(num(&alerts, "total"), 0);
    assert!(array(&alerts, "alerts").is_empty());
    let terms = get(&api, "glossary", &[]);
    let terms = array(&terms, "terms");
    assert!(!terms.is_empty());
    for term in terms {
        keys(term, &["term", "text"]);
    }
    assert!(
        terms
            .windows(2)
            .all(|pair| text(&pair[0], "term") <= text(&pair[1], "term"))
    );
}
fn flow_keys(flow: &Value) {
    keys(
        flow,
        &[
            "id",
            "title",
            "app",
            "pid",
            "local",
            "remote",
            "remote_name",
            "proto",
            "app_proto",
            "state",
            "status",
            "started",
            "duration_ms",
            "up_bytes",
            "down_bytes",
            "packets",
            "problems",
            "first_packet",
            "last_packet",
        ],
    );
}
