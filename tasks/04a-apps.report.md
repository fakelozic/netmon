**Built**

Direct evidence: [netmon::procs](src/procs/mod.rs) provides socket ownership lookup, address discovery, gateway discovery, and background refreshes. The [example](examples/procs.rs) supports `/proc` or a supplied directory.

Owned files have headers, public documentation, and decision comments. All are below 500 lines; the longest function is 69 lines.

**Acceptance results**

Direct evidence from the final runs:

| Command | Outcome | Last output |
|---|---|---|
| `cargo fmt --check` | Pass | Empty output; exit 0 |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass | ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.28s`` |
| `cargo test --offline` | Pass, with real-socket skip | `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | Pass | ``Finished `release` profile [optimized] target(s) in 3.87s`` |
| `ls -l target/release/netmon` | Pass | `-rwxr-xr-x. 2 user user 543416 Oct 12 23:35 target/release/netmon` |
| `cargo run --offline --example procs \| head -20` | Pass | `gateway: None` |

The ownership integration suite reported:

```text
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.30s
```

The fifth gate passed:

```sh
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
```

Its entire output contains only the five permitted exceptions:

```text
   559 src/decode/dns.rs
   573 src/decode/ip.rs
   655 src/decode/mod.rs
  1114 src/explain.rs
  1021 src/explain/fields.rs
```

Release binary: **543,416 bytes**. Created or changed Rust file counts:

```text
    6 src/lib.rs
   87 src/procs/addresses.rs
  153 src/procs/mod.rs
   77 src/procs/reader.rs
  245 src/procs/refresh.rs
  175 src/procs/scan.rs
  134 src/procs/sockets.rs
   42 examples/procs.rs
    6 tests/procs.rs
   37 tests/procs_support/addresses.rs
  235 tests/procs_support/lookup.rs
  133 tests/procs_support/mod.rs
  125 tests/procs_support/parsing.rs
   34 tests/procs_support/real.rs
   47 tests/procs_support/refresh.rs
  142 tests/procs_support/robustness.rs
```

An additional check, `git diff --check`, failed on the existing guide change:

```text
AGENTS.md:190: trailing whitespace.
```

**Public interface**

All paths remain under `netmon::procs`:

```rust
pub enum Transport { Tcp, Udp }
pub struct ProcInfo { pub pid: u32, pub name: String }
pub struct ProcTable { /* private fields */ }

impl ProcTable {
    pub fn empty() -> Self;
    pub fn scan(proc_root: &Path) -> ProcTable;
    pub fn lookup(&self, transport: Transport, local: SocketAddr, remote: SocketAddr) -> Option<&ProcInfo>;
    pub fn lookup_packet(&self, ip_proto: u8, src: SocketAddr, dst: SocketAddr) -> Option<(&ProcInfo, bool)>;
    pub fn sockets(&self) -> usize;
    pub fn unreadable(&self) -> usize;
    pub fn iter(&self) -> impl Iterator<Item = (Transport, SocketAddr, SocketAddr, &ProcInfo)>;
}

pub fn local_addresses(proc_root: &Path) -> Vec<IpAddr>;
pub fn default_gateway(proc_root: &Path) -> Option<Ipv4Addr>;

pub struct Refresher { /* private fields */ }
impl Refresher {
    pub fn start(proc_root: PathBuf, every: Duration) -> Refresher;
    pub fn latest(&self) -> Arc<ProcTable>;
    pub fn request_now(&self);
}
```

`Drop` stops and joins the refresher worker.

**Deviations**

- The later instructions require folder modules, superseding the brief’s original file layout.
- Added `iter()` for the required example.
- The real `/proc` test also skips when socket creation returns `PermissionDenied`.
- Additional safeguards cap root-directory visits at 100,000 and table lines at 4 KiB. Refresh periods below 1 ms are clamped to 1 ms.

**Needed elsewhere**

The shared [src/lib.rs](src/lib.rs) needs a file header; its authorized edit was limited to the module declaration. Remove the trailing whitespace at [AGENTS.md:190](AGENTS.md:190).

**Not verified**

No evidence found for a successful real socket PID match inside this sandbox. The test printed:

```text
notice: sandbox denied UDP socket creation (Operation not permitted (os error 1)); real-proc ownership is not verified
```

Big-endian hardware was not tested. The namespace limit is documented verbatim:

> Sockets inside containers or other network namespaces do not appear in this computer's `/proc/net`, so their traffic has no owner here.

Indirect evidence: the bounded-memory conclusion follows from the scan ceilings and snapshot replacement. Logical fallacy check: finite passing tests do not establish correctness for every possible input; the skipped test supplies no PID-match evidence.

**Suggested guide updates**

Update the proc module path to `src/procs/mod.rs` and document the real-socket sandbox skip.

**Questions**

Should future address labels retain all `host LOCAL` entries, as the brief specifies, or restrict IPv4 entries to `/32`? The current example printed:

```text
addresses: [127.0.0.0, 127.0.0.1, ::1]
```