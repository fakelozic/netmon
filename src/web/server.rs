//! Owns the loopback listener and its bounded set of connection workers.
//! Individual reads belong to `connection`; request rules belong to `routing`.
//! Read `Server::bind` first. Loopback traffic stays on this computer.

use super::{Api, Config, Token, connection, response};
use crate::explain::web;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// Each worker holds at most 12 KiB of request bytes. Refuse excess connections
// instead of spawning an unbounded number of threads on a busy desktop.
const MAX_CONNECTIONS: usize = 32;
const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// A listener bound only to IPv4 loopback. Private fields prevent address overrides.
pub struct Server {
    listener: TcpListener,
    port: u16,
}

impl Server {
    /// Tries the inclusive port range in order, continuing only on occupied ports.
    /// Port zero requests an OS-selected free port, useful in socket tests.
    pub fn bind(first_port: u16, last_port: u16) -> io::Result<Server> {
        if first_port > last_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                web::PORT_RANGE_ERROR,
            ));
        }
        for port in first_port..=last_port {
            match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
                Ok(listener) => {
                    listener.set_nonblocking(true)?;
                    let port = listener.local_addr()?.port();
                    return Ok(Self { listener, port });
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(io::ErrorKind::AddrInUse, web::PORTS_BUSY))
    }

    /// Returns the actual bound port, including when `bind` was called with zero.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns a local URL with the secret in its fragment, which HTTP never sends.
    pub fn url(&self, token: &Token) -> String {
        format!("http://127.0.0.1:{}/#k={token}", self.port)
    }

    /// Serves one request per connection until `stop` is set, then joins all workers.
    /// At most 32 workers run. API handlers must return for shutdown to complete.
    pub fn serve(self, token: Token, api: Arc<dyn Api>, stop: Arc<AtomicBool>) {
        let cfg = Arc::new(Config {
            port: self.port,
            token,
        });
        let mut workers = Vec::with_capacity(MAX_CONNECTIONS);
        while !stop.load(Ordering::Acquire) {
            reap(&mut workers);
            match self.listener.accept() {
                Ok((stream, _)) if workers.len() >= MAX_CONNECTIONS => {
                    // Refusing capacity must not block the accept loop on a slow
                    // extra client. This small diagnostic is a best-effort single write.
                    let _ = stream.set_nonblocking(true);
                    let mut bytes = Vec::new();
                    super::write_response(&response::error(503), &mut bytes);
                    let mut stream = stream;
                    let _ = std::io::Write::write(&mut stream, &bytes);
                }
                Ok((stream, _)) => {
                    let cfg = Arc::clone(&cfg);
                    let api = Arc::clone(&api);
                    let stop = Arc::clone(&stop);
                    if let Ok(worker) = thread::Builder::new().spawn(move || {
                        connection::handle(stream, &cfg, api.as_ref(), &stop);
                    }) {
                        workers.push(worker);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL)
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // Wake idle readers even if accepting stopped because the listener failed.
        stop.store(true, Ordering::Release);
        for worker in workers {
            let _ = worker.join();
        }
    }
}

fn reap(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers.get(index).is_some_and(JoinHandle::is_finished) {
            let _ = workers.swap_remove(index).join();
        } else {
            index += 1;
        }
    }
}
