use std::{
    io::Write,
    process::{Command, Stdio},
};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_netmon"))
}
#[test]
fn commands_exit_codes_and_standard_input() {
    let no_args = command().output().unwrap();
    assert_eq!(no_args.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(no_args.stderr).unwrap(),
        "netmon: the screen needs a terminal; try: netmon explain <file>\n"
    );
    for flag in ["--help", "--version"] {
        let out = command().arg(flag).output().unwrap();
        assert!(out.status.success());
        assert!(out.stderr.is_empty());
    }
    let invalid = command().args(["explain", "Cargo.toml"]).output().unwrap();
    assert_eq!(invalid.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(invalid.stderr).unwrap(),
        "netmon: not a pcap or pcapng capture\n"
    );
    let fixture = std::fs::read("tests/fixtures/loopback-mixed.pcapng").unwrap();
    let mut child = command()
        .args(["explain", "-", "--tsv"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&fixture).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 76);
    let mut child = command()
        .args(["explain", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&fixture[..fixture.len() - 3])
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .starts_with("netmon: warning:")
    );
    assert_eq!(String::from_utf8(out.stdout).unwrap().lines().count(), 76);
}
#[test]
fn closed_pipe_exits_quietly() {
    let mut child = command()
        .args([
            "explain",
            "tests/fixtures/loopback-mixed.pcapng",
            "--fields",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Closing the only read end forces a broken pipe without invoking a shell.
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty(), "{:?}", out.stderr);
}
