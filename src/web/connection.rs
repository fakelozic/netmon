//! Handles a single socket with bounded request storage and a total read deadline.
//! Accepting belongs to `server`; parsing and access rules remain socket-free.
//! Read `handle` first. Closing the socket prevents HTTP request pipelining here.

use super::{
    Api, BODY_LIMIT, Config, HEADER_LIMIT, Parsed, Response, parse_request, respond, response,
    write_response,
};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// A total deadline also defeats clients sending one byte just before each timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
// Short waits allow shutdown to wake idle readers without unsafe signal handling.
const STOP_POLL: Duration = Duration::from_millis(100);

pub(super) fn handle(mut stream: TcpStream, cfg: &Config, api: &dyn Api, stop: &AtomicBool) {
    let started = Instant::now();
    let mut bytes = Vec::with_capacity(HEADER_LIMIT + BODY_LIMIT);
    let mut chunk = [0; 1024];
    let reply = loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        let remaining = READ_TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break response::error(408);
        }
        if stream
            .set_read_timeout(Some(remaining.min(STOP_POLL)))
            .is_err()
        {
            return;
        }
        let room = (HEADER_LIMIT + BODY_LIMIT)
            .saturating_sub(bytes.len())
            .min(chunk.len());
        let Some(buffer) = chunk.get_mut(..room) else {
            return;
        };
        match stream.read(buffer) {
            Ok(0) => {
                // Empty EOF is a closed client; partial EOF is an invalid request.
                if bytes.is_empty() {
                    return;
                }
                break response::error(400);
            }
            Ok(count) => {
                if let Some(part) = buffer.get(..count) {
                    bytes.extend_from_slice(part);
                }
                match parse_request(&bytes) {
                    Parsed::Complete(req, _) => break respond(&req, cfg, api),
                    Parsed::Bad(status) => break response::error(status),
                    Parsed::Incomplete => continue,
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return,
        }
    };
    send(stream, &reply, stop);
}

pub(super) fn send(mut stream: TcpStream, reply: &Response, stop: &AtomicBool) {
    let mut bytes = Vec::new();
    write_response(reply, &mut bytes);
    let started = Instant::now();
    // Per-write timeouts alone reset after every partial write, allowing a client
    // to hold a worker forever. Bound the whole reply and check shutdown between writes.
    write_bounded(
        &bytes,
        stop,
        || READ_TIMEOUT.saturating_sub(started.elapsed()),
        |part, timeout| {
            stream.set_write_timeout(Some(timeout.min(STOP_POLL)))?;
            stream.write(part)
        },
    );
    let _ = stream.shutdown(Shutdown::Both);
}

fn write_bounded(
    mut bytes: &[u8],
    stop: &AtomicBool,
    remaining: impl Fn() -> Duration,
    mut write: impl FnMut(&[u8], Duration) -> io::Result<usize>,
) {
    while !bytes.is_empty() && !stop.load(Ordering::Acquire) {
        let timeout = remaining();
        if timeout.is_zero() {
            break;
        }
        match write(bytes, timeout) {
            Ok(0) => break,
            Ok(n) => bytes = bytes.get(n..).unwrap_or_default(),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn partial_writes_share_one_deadline_and_stop_interrupts_retries() {
        let stop = AtomicBool::new(false);
        let left = Cell::new(3);
        let calls = Cell::new(0);
        write_bounded(
            b"long reply",
            &stop,
            || Duration::from_secs(left.get()),
            |_, _| {
                left.set(left.get() - 1);
                calls.set(calls.get() + 1);
                Ok(1)
            },
        );
        assert_eq!(calls.get(), 3);
        calls.set(0);
        write_bounded(
            b"reply",
            &stop,
            || Duration::from_secs(5),
            |_, _| {
                calls.set(calls.get() + 1);
                stop.store(true, Ordering::Release);
                Err(io::ErrorKind::WouldBlock.into())
            },
        );
        assert_eq!(calls.get(), 1);
    }
}
