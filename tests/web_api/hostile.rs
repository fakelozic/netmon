//! Checks JSON escaping at packet and conversation boundaries.
//! Packet builders stay in existing area helpers; normal schemas stay in fixture.rs.
//! Read `dns_and_server_names_are_data` for attacker-controlled bytes.

use super::support::*;
use crate::{
    flow_support::client_hello,
    pipeline_support::{dns, tcp},
};
use netmon::live::Message;

#[test]
fn dns_and_server_names_are_data() {
    let (_engine, api, send) = manual(None, 200000);
    let name = "bad\"\\\n<script>.test";
    let tls = client_hello(name.as_bytes());
    send.send(Message::Packet(tcp(1, false, [50000, 443], 24, &tls)))
        .unwrap();
    send.send(Message::Packet(dns(2, false, name, 0))).unwrap();
    send.send(Message::Packet(dns(3, true, name, 0))).unwrap();
    wait_packets(&api, 3);
    let flows = get(&api, "flows", &[]);
    let tls = array(&flows, "flows")
        .iter()
        .find(|f| text(f, "proto") == "TCP")
        .unwrap();
    assert_eq!(text(tls, "remote_name"), "bad\"\\\\x0A<script>.test");
    let packets = get(&api, "packets", &[("filter", "dns")]);
    assert_eq!(array(&packets, "rows").len(), 2);
    assert!(text(&array(&packets, "rows")[0], "info").contains("\\x0A<script>"));
    for path in ["packet/1", "packet/2", "packet/3"] {
        let packet = get(&api, path, &[]);
        assert!(!format!("{packet:?}").contains("\n<script>"));
    }
    let reply = request(&api, netmon::web::Method::Get, "flows", &[], b"");
    assert!(
        reply.json.contains("\\\"")
            && reply.json.contains("\\\\")
            && reply.json.contains("\\u003Cscript\\u003E")
    );
    assert!(!reply.json.contains("<script>"));
}
#[test]
fn summary_fixes_have_direct_fixture_evidence() {
    let dir = crate::log_support::TestDir::new();
    let packets = crate::log_support::packets("loopback-mixed.pcapng");
    let mut pipeline = netmon::pipeline::Pipeline::new(
        options(Some(crate::log_support::options(dir.path()))).pipeline,
        packets[0].ts,
    );
    for packet in packets {
        pipeline.push(&packet);
    }
    pipeline.finish();
    let summary =
        std::fs::read_to_string(pipeline.session().unwrap().dir().join("summary.md")).unwrap();
    assert!(!summary.contains("0 more finished conversations"));
    assert!(summary.contains("20.207.73.82 \\(via github.com\\)"));
    assert!(summary.contains("550 µs") && summary.contains("95 µs"));
    assert!(!summary.contains("still open when the capture ended"));
}
