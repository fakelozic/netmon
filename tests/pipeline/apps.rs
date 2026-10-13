//! Check snapshot app ownership and local-side byte orientation.
//! Fake procfs files belong to pipeline_support/proc.rs.
//! Read remembered_app_reaches_rows_events_and_finished_json first.

use crate::pipeline_support::{
    proc::{fake_proc, ready},
    *,
};
use netmon::{pipeline::Pipeline, procs::local_addresses};
use std::{fs, time::Duration};

#[test]
fn address_refresh_uses_packet_time_and_publishes_without_waiting_in_push() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::thread;
    let base = TestDir::new();
    let root = fake_proc(&base, "known");
    let mut opts = options(None);
    opts.proc_root = Some(root.clone());
    let mut pipeline = Pipeline::new(opts, Duration::ZERO);
    assert!(
        pipeline
            .tracker()
            .names()
            .is_local(&"10.0.0.1".parse().unwrap())
    );
    fs::write(
        root.join("net/fib_trie"),
        " |-- 10.0.0.2\n /32 host LOCAL\n",
    )
    .unwrap();
    let gateway = u32::from_ne_bytes([10, 0, 0, 3]);
    fs::write(
        root.join("net/route"),
        format!("eth0 00000000 {gateway:08X} 0003\n"),
    )
    .unwrap();
    pipeline.tick(Duration::from_secs(29));
    assert!(
        !pipeline
            .tracker()
            .names()
            .is_local(&"10.0.0.2".parse().unwrap())
    );
    let stop = AtomicBool::new(false);
    // A watchdog detects deadlock only; scheduling speed is not the assertion.
    thread::scope(|scope| {
        let (send, receive) = mpsc::channel();
        let stop_ref = &stop;
        let worker = scope.spawn(move || {
            while !stop_ref.load(Ordering::Relaxed) {
                pipeline.tick(Duration::from_secs(30));
                if pipeline
                    .tracker()
                    .names()
                    .is_local(&"10.0.0.2".parse().unwrap())
                {
                    assert_eq!(
                        pipeline
                            .tracker()
                            .names()
                            .label(&"10.0.0.3".parse().unwrap()),
                        "router"
                    );
                    let _ = send.send(());
                    break;
                }
                thread::yield_now();
            }
        });
        let published = receive.recv_timeout(Duration::from_secs(10));
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
        published.expect("address worker did not publish its requested snapshot");
    });
}

#[test]
fn remembered_app_reaches_rows_events_and_finished_json() {
    let base = TestDir::new();
    let root = fake_proc(&base, "test-browser");
    let mut opts = options(Some(&base));
    opts.proc_root = Some(root.clone());
    let mut pipeline = ready(Pipeline::new(opts, Duration::ZERO));
    let row = pipeline.push(&sequence(
        tcp(1_000_001, false, [40000, 80], 2, &[]),
        900_000,
        0,
    ));
    let id = row.flow.unwrap();
    assert_eq!(row.app.as_deref(), Some("test-browser"));
    assert_eq!(pipeline.app_of(id).unwrap().pid, 42);
    assert_eq!(row.src_label, "this computer:40000");
    assert_eq!(row.dst_label, "router:80");
    fs::write(root.join("42/comm"), "changed-owner\n").unwrap();
    let row = pipeline.push(&sequence(
        tcp(1_000_002, true, [40000, 80], 0x14, &[]),
        100,
        900_001,
    ));
    assert_eq!(row.app.as_deref(), Some("test-browser"));
    pipeline.finish();
    let dir = pipeline.session().unwrap().dir();
    let rows = json_lines(dir, "flows.jsonl");
    let matched = rows
        .iter()
        .find(|row| {
            row.field("app") == Some(&string("test-browser"))
                && row.field("end") == Some(&string("refused"))
        })
        .unwrap();
    assert_eq!(matched.field("pid"), Some(&number(42)));
    let events = fs::read_to_string(dir.join("events.md")).unwrap();
    assert!(
        events
            .lines()
            .any(|line| line.contains(" | Open | test-browser -&gt; 10.0.0.2:80"))
    );
    assert_eq!(
        local_addresses(&root),
        vec!["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[test]
fn unmatched_conversation_stays_unknown_and_opens_with_unknown_app() {
    let base = TestDir::new();
    let root = fake_proc(&base, "known");
    let mut opts = options(Some(&base));
    opts.proc_root = Some(root);
    let mut pipeline = ready(Pipeline::new(opts, Duration::ZERO));
    for number in 1_000_000..1_000_020 {
        let row = pipeline.push(&tcp(number, false, [49999, 80], 16, &[]));
        assert!(row.app.is_none());
        assert!(pipeline.app_of(row.flow.unwrap()).is_none());
    }
    pipeline.finish();
    let events = fs::read_to_string(pipeline.session().unwrap().dir().join("events.md")).unwrap();
    assert!(
        events
            .lines()
            .any(|line| line.contains(" | Open | unknown app"))
    );
}

#[test]
fn incoming_conversation_logs_bytes_from_this_computer_as_up() {
    let base = TestDir::new();
    let root = fake_proc(&base, "known");
    let mut opts = options(Some(&base));
    opts.proc_root = Some(root);
    let mut pipeline = Pipeline::new(opts, Duration::ZERO);
    pipeline.push(&tcp(1, true, [40001, 80], 0x18, b"1234567"));
    pipeline.push(&tcp(2, false, [40001, 80], 0x18, b"123"));
    pipeline.finish();
    let rows = json_lines(pipeline.session().unwrap().dir(), "flows.jsonl");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].field("local"), Some(&string("10.0.0.1:40001")));
    assert_eq!(rows[0].field("up_bytes"), Some(&number(3)));
    assert_eq!(rows[0].field("down_bytes"), Some(&number(7)));
}
