//! Verifies the reviewed full alert display.
//! Packet construction belongs to `../alert_support`; shared assertions belong to `../alerts.rs`.
//! Read the test functions below first.
//! Observed network patterns do not establish malicious intent.

use super::*;

fn golden_alerts() -> Vec<Alert> {
    let mut alerts = scan(&mut engine(), 25, 100, false);
    alerts.extend(observe(
        &mut engine(),
        &http(30, 3000, Some(&format!("Authorization: Basic {BASE64}"))),
    ));
    let mut arp_engine = engine();
    let gateway = Ipv4Addr::new(10, 0, 0, 1);
    arp_engine.set_gateway(Some(gateway.into()));
    assert!(observe(&mut arp_engine, &arp(40, 4000, gateway, [2, 0, 0, 0, 0, 1])).is_empty());
    alerts.extend(observe(
        &mut arp_engine,
        &arp(41, 4100, gateway, [2, 0, 0, 0, 0, 2]),
    ));
    alerts.extend(observe(
        &mut engine(),
        &dns_query(50, 5000, CLIENT, "abcdefghijklmnopqrstuvwxyz012345.test"),
    ));
    let mut inbound_engine = engine();
    inbound_engine.set_local(&[CLIENT]);
    assert!(
        observe(
            &mut inbound_engine,
            &tcp(60, 6000, (PUBLIC, 50_000), (CLIENT, 22), 2, &[])
        )
        .is_empty()
    );
    alerts.extend(observe(
        &mut inbound_engine,
        &tcp(61, 6025, (CLIENT, 22), (PUBLIC, 50_000), 0x12, &[]),
    ));
    assert_eq!(alerts.len(), 5);
    alerts
}

#[test]
fn full_printed_examples_match_reviewed_golden() {
    let output = golden_alerts().iter().map(printed).collect::<String>();
    let path = Path::new("tests/golden/alerts-examples.txt");
    if std::env::var_os("NETMON_BLESS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        fs::write(path, &output).unwrap();
    }
    assert_eq!(output, fs::read_to_string(path).unwrap());
}

#[test]
fn printed_alerts_include_severity_numbers_and_all_explanations() {
    // Integration tests use the same formatting function as the example program.
    // Build and execution of the example is separately required by acceptance commands.
    let alerts = golden_alerts();
    for alert in alerts {
        let text = printed(&alert);
        assert!(text.starts_with(match alert.severity {
            Severity::Notice => "Notice: ",
            Severity::Warning => "Warning: ",
            Severity::Serious => "Serious: ",
        }));
        for label in ["\nPackets: ", "\nSeen: ", "\nWhy: ", "\nNext: "] {
            assert!(text.contains(label));
        }
    }
}
