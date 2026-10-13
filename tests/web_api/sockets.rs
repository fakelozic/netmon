//! Checks authenticated HTTP replies from a fixture-backed engine on loopback.
//! Socket-free endpoint assertions stay in the other web_api files.
//! Permission-denied bind/connect attempts print a notice rather than claiming coverage.

use super::support::*;
use netmon::web::{Api, Server, Token};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[test]
fn real_server_serves_fixture_session_and_packets() {
    let server = match Server::bind(0, 0) {
        Ok(server) => server,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("SKIPPED web_api socket integration: {e}");
            return;
        }
        Err(e) => panic!("loopback bind: {e}"),
    };
    let (_engine, api) = fixture();
    let port = server.port();
    let token = Token::generate().unwrap();
    let key = token.to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let api: Arc<dyn Api> = Arc::new(api);
    let worker = thread::spawn(move || server.serve(token, api, flag));
    for (path, field, expected) in [("session", "packets", 75), ("packets", "matched", 75)] {
        let mut stream = match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => stream,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("SKIPPED web_api socket integration connect: {e}");
                break;
            }
            Err(e) => panic!("loopback connect: {e}"),
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "GET /api/{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Netmon-Token: {key}\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        let body = response.split_once("\r\n\r\n").unwrap().1;
        let json = crate::log_support::parse(body).unwrap();
        assert_eq!(num(&json, field), expected);
    }
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}
