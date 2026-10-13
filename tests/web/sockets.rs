//! Exercises real loopback HTTP serving where socket permissions permit it.
//! Socket-free protocol assertions live in the other web test files.
//! Read `fetch_routes` first. Permission failures print a skip notice and pass.

use super::support::Stub;
use netmon::web::{Server, Token};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

struct Running {
    port: u16,
    token: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Running {
    fn start(name: &str) -> Option<Self> {
        let server = permitted(Server::bind(0, 0), name)?;
        let token = Token::generate().expect("OS token");
        let port = server.port();
        assert_eq!(
            server.url(&token),
            format!("http://127.0.0.1:{port}/#k={token}")
        );
        let text = token.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let worker = thread::spawn(move || server.serve(token, Arc::new(Stub), flag));
        Some(Self {
            port,
            token: text,
            stop,
            worker: Some(worker),
        })
    }

    fn connect(&self, name: &str) -> Option<TcpStream> {
        let stream = permitted(TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)), name)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .expect("client timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("client write timeout");
        Some(stream)
    }

    fn fetch(&self, method: &str, path: &str, token: Option<&str>, name: &str) -> Option<String> {
        let mut client = self.connect(name)?;
        let auth = token
            .map(|value| format!("X-Netmon-Token: {value}\r\n"))
            .unwrap_or_default();
        write!(
            client,
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{auth}\r\n",
            self.port
        )
        .expect("send request");
        Some(read_reply(&mut client))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("server exited");
        }
    }
}

fn permitted<T>(result: io::Result<T>, name: &str) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("SKIPPED {name}: socket permission denied ({error})");
            None
        }
        Err(error) => panic!("{name}: {error}"),
    }
}

fn read_reply(client: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    client
        .read_to_end(&mut bytes)
        .expect("reply followed by connection close");
    String::from_utf8(bytes).expect("UTF-8 test reply")
}

#[test]
fn fetch_routes() {
    let Some(server) = Running::start("fetch_routes") else {
        return;
    };
    for (method, path, token, status) in [
        ("GET", "/", None, 200),
        ("GET", "/api/session", None, 401),
        ("GET", "/api/session", Some("wrong"), 401),
        ("GET", "/api/session", Some(server.token.as_str()), 200),
        ("HEAD", "/", None, 200),
    ] {
        let Some(reply) = server.fetch(method, path, token, "fetch_routes") else {
            return;
        };
        assert!(reply.starts_with(&format!("HTTP/1.1 {status} ")));
        assert!(reply.contains("Connection: close\r\n"));
        assert!(reply.contains("Content-Security-Policy: default-src 'none';"));
        if path == "/api/session" && status == 200 {
            assert!(reply.ends_with("{\"state\":\"ended\"}"));
        }
        if method == "HEAD" {
            assert!(reply.ends_with("\r\n\r\n"));
        }
    }
}

#[test]
fn thirty_third_connection_is_refused() {
    let Some(server) = Running::start("thirty_third_connection_is_refused") else {
        return;
    };
    let mut idle = Vec::new();
    for _ in 0..32 {
        let Some(mut client) = server.connect("thirty_third_connection_is_refused") else {
            return;
        };
        client
            .write_all(b"G")
            .expect("partial request keeps worker busy");
        idle.push(client);
    }
    let Some(mut excess) = server.connect("thirty_third_connection_is_refused") else {
        return;
    };
    let reply = read_reply(&mut excess);
    assert!(reply.starts_with("HTTP/1.1 500 "));
    assert!(reply.contains("Cache-Control: no-store\r\n"));
    assert!(reply.contains("\"error\":"));
    drop(idle);
}

#[test]
fn empty_client_times_out() {
    let Some(server) = Running::start("empty_client_times_out") else {
        return;
    };
    let Some(mut idle) = server.connect("empty_client_times_out") else {
        return;
    };
    let started = Instant::now();
    let reply = read_reply(&mut idle);
    assert!(reply.starts_with("HTTP/1.1 400 "));
    // This real-socket deadline test is the brief's exception to timeless tests.
    assert!(started.elapsed() >= Duration::from_millis(4900));
}

#[test]
fn stop_wakes_idle_connections_and_ends_serve() {
    let Some(mut server) = Running::start("stop_wakes_idle_connections_and_ends_serve") else {
        return;
    };
    let Some(_idle) = server.connect("stop_wakes_idle_connections_and_ends_serve") else {
        return;
    };
    server.stop.store(true, Ordering::Release);
    let worker = server.worker.take().expect("worker");
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        worker.join().expect("server exit");
        send.send(()).expect("completion");
    });
    receive
        .recv_timeout(Duration::from_secs(2))
        .expect("stop returns promptly");
}

#[test]
fn occupied_ports_and_invalid_range() {
    assert_eq!(
        Server::bind(7999, 7979)
            .err()
            .expect("invalid range")
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let Some(occupied) = permitted(Server::bind(0, 0), "occupied_ports_and_invalid_range") else {
        return;
    };
    let port = occupied.port();
    assert_eq!(
        Server::bind(port, port)
            .err()
            .expect("port occupied")
            .kind(),
        io::ErrorKind::AddrInUse
    );
    if port < u16::MAX {
        let Some(next) = permitted(
            Server::bind(port, port.saturating_add(20)),
            "occupied_ports_and_invalid_range",
        ) else {
            return;
        };
        assert!(next.port() > port);
    }
}

#[test]
fn partial_bad_and_pipelined_requests() {
    let Some(server) = Running::start("partial_bad_and_pipelined_requests") else {
        return;
    };
    let Some(mut client) = server.connect("partial_bad_and_pipelined_requests") else {
        return;
    };
    for part in [
        format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n", server.port),
        "\r\nGET /api/session HTTP/1.1\r\n\r\n".into(),
    ] {
        client.write_all(part.as_bytes()).expect("split request");
    }
    let reply = read_reply(&mut client);
    assert!(reply.starts_with("HTTP/1.1 200 "));
    assert_eq!(reply.matches("HTTP/1.1 ").count(), 1);
    for (headers, status) in [
        ("Content-Length: 4097\r\n".to_owned(), 400),
        (format!("X: {}\r\n", "x".repeat(8192)), 400),
        ("Transfer-Encoding: chunked\r\n".into(), 400),
    ] {
        let Some(mut client) = server.connect("partial_bad_and_pipelined_requests") else {
            return;
        };
        write!(client, "POST / HTTP/1.1\r\n{headers}\r\n").expect("invalid request");
        let reply = read_reply(&mut client);
        assert!(reply.starts_with(&format!("HTTP/1.1 {status} ")));
        assert!(reply.contains("X-Content-Type-Options: nosniff\r\n"));
    }
}
