//! Verifies capture worker lifecycle with deterministic inputs.
//! Shared fixture reading belongs to ui_support; real capture is never started.
//! Read the fixture tests first for the observable acceptance requirements.
use netmon::live::{self, Message, Source};
use std::{path::Path, sync::mpsc, thread, time::Duration};
#[test]
fn interface_sample_default_and_sanitising() {
    let interfaces = live::parse_interfaces(
        "1. enp5s0\n2. br-000000000001\n7. any\n8. lo (Loopback)\n12. bluetooth-monitor\n13. usbmon2\n16. nflog\n",
    );
    assert_eq!(interfaces.len(), 7);
    assert_eq!(interfaces[3].description, "Loopback");
    assert_eq!(live::default_interface(&interfaces).unwrap().name, "enp5s0");
    assert_eq!(
        live::default_interface(&interfaces[1..]).unwrap().name,
        "lo"
    );
    assert!(live::default_interface(&interfaces[4..]).is_none());
    assert!(live::default_interface(&[]).is_none());
    let hostile = live::parse_interfaces("not a row\n1. eth0 (hi\x1b[2J)\n2. \n");
    assert_eq!(hostile.len(), 1);
    assert!(hostile[0].description.contains("\\x1B"));
    let all =
        live::parse_interfaces("1. docker0\n2. br-foo\n3. vethx\n4. nfqueue\n5. usbmon1\n6. wlan0");
    assert_eq!(live::default_interface(&all).unwrap().name, "wlan0");
}
fn count(mut source: Source) {
    let mut packets = 0;
    loop {
        match source
            .receiver()
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
        {
            Message::Packet(p) => {
                packets += 1;
                assert_eq!(p.number, packets);
            }
            Message::Ended => break,
            Message::Failed(e) => panic!("{e}"),
        }
    }
    assert_eq!(packets, 75);
    source.stop();
    source.stop();
}
#[test]
fn command_and_file_deliver_packets_then_ended() {
    count(Source::command("sh", &["-c", "cat tests/fixtures/loopback-mixed.pcapng"]).unwrap());
    count(Source::file(Path::new("tests/fixtures/loopback-mixed.pcapng")).unwrap());
}
#[test]
fn standard_error_is_reported_and_sanitised() {
    let source = Source::command("sh", &["-c", "printf 'denied\\033[2J' >&2; exit 1"]).unwrap();
    match source
        .receiver()
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
    {
        Message::Failed(e) => {
            assert!(e.contains("denied\\x1B[2J"));
            assert!(!e.contains('\x1b'));
        }
        message => panic!("{message:?}"),
    }
}
#[test]
fn missing_program_names_install_package_and_group() {
    let error = Source::command("netmon-nonexistent-capture-command-73829", &[])
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("Wireshark"));
    assert!(error.contains("wireshark group"));
}
#[test]
fn stop_and_drop_release_a_blocked_reader_and_shell_descendants() {
    for explicit_stop in [true, false] {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            // sleep inherits the shell's stdout. Killing only the shell would
            // leave the capture reader waiting for 60 seconds.
            let mut source = Source::command(
                "sh",
                &[
                    "-c",
                    "sleep 60 & cat tests/fixtures/loopback-mixed.pcapng; wait",
                ],
            )
            .unwrap();
            assert!(matches!(
                source
                    .receiver()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap(),
                Message::Packet(_)
            ));
            if explicit_stop {
                source.stop();
            }
            drop(source);
            sender.send(()).unwrap();
        });
        // This is a deadlock watchdog, not an elapsed-time performance assertion.
        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}
#[test]
fn bad_file_is_an_asynchronous_failure() {
    let source = Source::file(Path::new("Cargo.toml")).unwrap();
    assert!(
        matches!(source.receiver().recv_timeout(Duration::from_secs(5)).unwrap(),Message::Failed(error) if error.contains("not a pcap"))
    );
}
