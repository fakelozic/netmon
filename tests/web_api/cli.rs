//! Verifies the web command's argument dispatch without opening sockets.
//! Full endpoint behavior stays in fixture.rs; capture startup belongs to command.rs.
//! Read `help_lists_every_web_option` before validation-error cases.

use std::process::{Command, Stdio};

#[test]
fn help_lists_every_web_option() {
    for args in [vec!["--help"], vec!["web", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_netmon"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        for option in [
            "netmon web",
            "-i IFACE",
            "-r FILE",
            "-f CAPTURE_FILTER",
            "--port",
            "--no-open",
            "--log-dir",
            "--record",
            "--no-log",
            "--max-packets",
        ] {
            assert!(text.contains(option), "missing {option}");
        }
    }
}
#[test]
fn invalid_web_options_fail_before_socket_or_capture_startup() {
    for args in [
        vec!["web", "--port", "0"],
        vec!["web", "--max-packets", "0"],
        vec![
            "web",
            "-r",
            "tests/fixtures/loopback-mixed.pcapng",
            "-i",
            "lo",
        ],
        vec!["web", "--unknown"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_netmon"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!output.stderr.is_empty());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn bad_values_name_the_option_and_valid_range() {
    for (option, value, expected) in [
        ("--port", "invalid", "web port must be between 1 and 65535"),
        ("--port", "65536", "web port must be between 1 and 65535"),
        ("--port", "-1", "web port must be between 1 and 65535"),
        (
            "--max-packets",
            "invalid",
            "max-packets must be between 1 and 200000",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_netmon"))
            .args(["web", option, value])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr).unwrap().contains(expected));
        assert!(output.stdout.is_empty());
    }
}
