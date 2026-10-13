# Task 04a — which program owns a connection

Read `AGENTS.md`, `PLAN.md` (section 8, "Which app is talking"), and the area guide for `tests` first.

## Goal

Given a packet's addresses and ports, say which program on this computer owns that socket, by reading
`/proc`. Also report this computer's own addresses and its default router. No screen and no wiring
into other code in this task: a library module, an example program, and tests.

## Parallel work

Four other agents are working at the same time on conversations, the packets screen, logging and alerts.
You cannot see their work.

**You own:** `src/procs.rs`, `examples/procs.rs`, `tests/procs.rs`, `tests/procs_support/mod.rs`.

**Shared files:** `src/lib.rs` — add `pub mod procs;` only.

Do not touch anything else. This module has no user-facing sentences, so it needs no file under `src/explain`.

## 1. Interface (`src/procs.rs`)

```rust
pub enum Transport { Tcp, Udp }

pub struct ProcInfo {
    pub pid: u32,
    pub name: String,   // from /proc/<pid>/comm, sanitised
}

pub struct ProcTable { /* private */ }
impl ProcTable {
    pub fn empty() -> Self;
    pub fn scan(proc_root: &Path) -> ProcTable;   // "/proc" in real use; never fails, returns what it could read
    pub fn lookup(&self, transport: Transport, local: SocketAddr, remote: SocketAddr) -> Option<&ProcInfo>;
    pub fn lookup_packet(&self, ip_proto: u8, src: SocketAddr, dst: SocketAddr) -> Option<(&ProcInfo, bool)>;
        // tries src as the local side, then dst; the bool is true when src was local (outgoing)
    pub fn sockets(&self) -> usize;
    pub fn unreadable(&self) -> usize;            // processes whose sockets could not be read
}

pub fn local_addresses(proc_root: &Path) -> Vec<IpAddr>;
pub fn default_gateway(proc_root: &Path) -> Option<Ipv4Addr>;

pub struct Refresher { /* private */ }
impl Refresher {
    pub fn start(proc_root: PathBuf, every: Duration) -> Refresher;  // background thread
    pub fn latest(&self) -> Arc<ProcTable>;                          // cheap; never blocks on a scan
    pub fn request_now(&self);                                       // ask for an early rescan
}   // Drop stops and joins the thread
```

## 2. How it works

1. Read `net/tcp`, `net/tcp6`, `net/udp` and `net/udp6` under `proc_root`. Each line after the header
   has local address and port, remote address and port (hex), and the socket's inode. IPv4 addresses
   are four bytes in host byte order as printed; IPv6 addresses are four 32-bit words. Parse both
   correctly and prove it with tests against known addresses.
2. Walk the numeric directories under `proc_root`. In each, read the links in `fd/`. A link that reads
   `socket:[N]` means that process holds the socket with inode `N`. Read `comm` for the name.
3. Join the two on inode.

Rules:

- **Match order in `lookup`:** exact local and remote; then local address and port with any remote
  (unconnected UDP, listening TCP); then local port on the wildcard address (`0.0.0.0` or `::`).
- An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) in the `tcp6` or `udp6` table is the same as that IPv4
  address. Normalise both sides before matching.
- When several processes hold one socket, prefer the one with the lowest pid that is not pid 1.
- Processes owned by another user cannot be read. Skip them silently and count them in `unreadable`.
- Processes come and go during a scan. A missing file is never an error.
- Everything read from `/proc` is untrusted text. Sanitise `comm`. Skip malformed lines. Never panic.
- **Bounds:** read at most 200,000 socket lines and 100,000 file-descriptor links per scan; read at
  most 4 KB of any one small file.
- `local_addresses`: IPv4 from `net/fib_trie` (addresses followed by a line containing `host LOCAL`),
  IPv6 from `net/if_inet6`. Deduplicated; loopback included.
- `default_gateway`: from `net/route`, the row with destination `00000000` and the gateway flag set.
- `Refresher` scans off the caller's thread, so the screen never waits on `/proc`. `request_now` is
  rate-limited to one extra scan per 200 ms.

Known limit, to state in a comment and in your report: sockets inside containers or other network
namespaces do not appear in this computer's `/proc/net`, so their traffic has no owner here.

## 3. Example program (`examples/procs.rs`)

`cargo run --offline --example procs` scans `/proc` and prints one line per socket that has an owner
(transport, local, remote, pid, name), then the local addresses and the gateway.
`cargo run --offline --example procs -- <DIR>` uses another root.

## 4. Tests

Build a fake `/proc` tree under `env!("CARGO_TARGET_TMPDIR")` in the test (helpers in
`tests/procs_support/mod.rs`): `net/` files as text, process directories with `comm`, and `fd/` entries
made with `std::os::unix::fs::symlink` pointing at `socket:[N]`.

1. Parsing: known IPv4 and IPv6 lines give the right addresses and ports, including `127.0.0.1`,
   a private address, `::1`, a global IPv6 address and an IPv4-mapped one.
2. Lookup: exact match; unconnected UDP; a listener; wildcard address; IPv4-mapped; `lookup_packet` in
   both directions; a socket held by two processes; a socket with no visible owner.
3. Robustness: empty files, a header only, malformed lines, non-UTF-8 bytes, a `comm` containing byte
   `0x1b` (stored sanitised), a process directory that vanishes, a missing `net/` folder, a root that
   does not exist. None may panic; all return an empty or partial table.
4. Addresses and gateway: sample `fib_trie`, `if_inet6` and `route` contents give the expected values;
   no default route gives `None`.
5. Refresher: `latest` returns immediately; a rescan picks up a socket added to the fake tree; dropping
   it stops the thread (the test must finish).
6. Real `/proc`: bind a UDP socket on `127.0.0.1:0`, scan `/proc`, and expect `lookup` to return this
   test's own pid. If `/proc/net/udp` cannot be read, print a notice and pass.

## 5. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
cargo run --offline --example procs | head -20
```
