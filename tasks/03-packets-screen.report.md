**1. Built**

Implemented task 03: live/file capture workers, bounded packet storage, display filters, the Packets screen, layers/explanations/highlighted bytes, overlays, keyboard/mouse handling, and CLI dispatch.

Owned code now has file headers, public-item documentation, and required why-comments. The live module was split while preserving `netmon::live::*` paths.

**2. Acceptance results**

**Direct evidence:** exact command output is preserved in [task03-acceptance.json](target/task03-acceptance.json).

| Command | Outcome and final output |
|---|---|
| `cargo fmt --check` | PASS, status 0; no rustfmt diagnostics. Shell output quoted below. |
| `cargo clippy --offline --all-targets -- -D warnings` | PASS: ``Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.30s`` |
| `cargo test --offline` | PASS, **53 tests**, zero failures. Final line: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` |
| `cargo build --release --offline` | PASS: ``Finished `release` profile [optimized] target(s) in 6.22s`` |
| `ls -l target/release/netmon` | PASS: `-rwxr-xr-x. 2 user user 931368 Oct 13 10:38 target/release/netmon` |
| `./target/release/netmon --help` | PASS; final line: `Screen keys: ? help, g glossary, / filter, q quit` |
| `./target/release/netmon -r tests/fixtures/loopback-mixed.pcapng < /dev/null \| cat ; echo "exit=$?"` | PASS, expected terminal rejection; exact output below. |
| `./target/release/netmon explain tests/fixtures/loopback-mixed.pcapng \| head -5` | PASS; final line quoted below. |

Formatter command’s shell output:

```text
mise WARN  failed to write cache file: ~/.cache/mise/neovim/0.12.6/exec_env_23edce6bdfd8cc4-9d683.msgpack.z Read-only file system (os error 30)
```

Screen pipeline output:

```text
netmon: the screen needs a terminal; try: netmon explain <file>
exit=0
```

The independent screen invocation returned **status 2**. Logical inference check: `exit=0` above belongs to `cat`, not netmon.

Explain command’s final line:

```text
    4    0.301229  127.0.0.2              127.0.0.1              ICMP         98  Ping reply (seq 2)
```

The required size command was run exactly:

```sh
find src tests examples -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
```

Its output was:

```text
find: ‘examples’: No such file or directory
   559 src/decode/dns.rs
   573 src/decode/ip.rs
   655 src/decode/mod.rs
  1115 src/explain.rs
  1021 src/explain/fields.rs
```

**PASS for the size criterion:** only the five permitted exceptions appear. Repeating the check over existing `src/` and `tests/` produced the same list without the diagnostic. The function-length check, owned-file documentation audit, and `git diff --check -- src tests` also passed.

Release binary: **931,368 bytes**.

Line counts for every created or changed Rust file:

```text
    10 src/lib.rs
  1115 src/explain.rs
   188 src/main.rs
   329 src/filter.rs
   283 src/store.rs
    27 src/sys.rs
   248 src/explain/ui.rs
   104 src/live/mod.rs
   244 src/live/source.rs
   198 src/ui/details.rs
   102 src/ui/editing.rs
   184 src/ui/events.rs
   131 src/ui/layout.rs
   107 src/ui/mod.rs
   135 src/ui/overlays.rs
   198 src/ui/packets.rs
   273 src/ui/state.rs
   193 src/ui/supervisor.rs
   133 src/ui/terminal.rs
    37 src/ui/text_layout.rs
    42 src/ui/theme.rs
   132 src/ui/tree.rs
    35 src/ui/widgets.rs
    80 tests/cli.rs
   195 tests/filter.rs
   114 tests/live.rs
   456 tests/ui.rs
    12 tests/ui_support/mod.rs
    71 tests/ui_support/store.rs
```

**3. Public interface**

Added modules: `netmon::{filter, live, store, sys, ui}` and `netmon::explain::ui`. Types described as opaque below have private storage.

`netmon::filter`:

```rust
pub struct Row<'a> {
    pub summary: &'a Summary,
    pub sentence: &'a str,
    pub src_name: Option<&'a str>,
    pub dst_name: Option<&'a str>,
    pub app: Option<&'a str>,
    pub problem: bool,
}
pub struct FilterError {
    pub position: usize,
    pub message: String,
}
// Opaque public type: Filter.
pub fn parse(input: &str) -> Result<Filter, FilterError>;

impl Filter {
    pub fn matches(&self, row: &Row<'_>) -> bool;
    pub fn is_empty(&self) -> bool;
    pub fn conversation(summary: &Summary) -> Option<Self>;
}
```

`netmon::live`:

```rust
pub struct Interface {
    pub name: String,
    pub description: String,
}
pub struct LiveError(String);
pub enum Message {
    Packet(RawPacket),
    Ended,
    Failed(String),
}
// Opaque public type: Source.
pub fn parse_interfaces(output: &str) -> Vec<Interface>;
pub fn list_interfaces() -> Result<Vec<Interface>, LiveError>;
pub fn default_interface(list: &[Interface]) -> Option<&Interface>;

impl Source {
    pub fn dumpcap(
        interface: &str,
        capture_filter: Option<&str>,
    ) -> Result<Source, LiveError>;
    pub fn command(program: &str, args: &[&str]) -> Result<Source, LiveError>;
    pub fn file(path: &Path) -> Result<Source, LiveError>;
    pub fn receiver(&self) -> &Receiver<Message>;
    pub fn stop(&mut self);
}
```

`netmon::store`:

```rust
pub const DEFAULT_MAX_PACKETS: usize = 200_000;
pub const MAX_PACKET_BYTES: usize = 256 * 1024 * 1024;
pub const REBUILD_SLICE: usize = 20_000;

pub struct Entry {
    pub id: u64,
    pub raw: RawPacket,
    pub summary: Summary,
    pub sentence: String,
    pub problem: bool,
}
// Opaque public type: Store.
impl Store {
    pub fn new(max_packets: usize) -> Self;
    pub fn with_limits(max_packets: usize, max_bytes: usize) -> Self;
    pub fn push(&mut self, raw: RawPacket);
    pub fn set_filter(&mut self, text: String, filter: Filter);
    pub fn on_tick(&mut self);
    pub fn get(&self, id: u64) -> Option<&Entry>;
    pub fn visible_id(&self, index: usize) -> Option<u64>;
    pub fn visible(&self, index: usize) -> Option<&Entry>;
    pub fn visible_len(&self) -> usize;
    pub fn visible_index(&self, id: u64) -> Option<usize>;
    pub fn len(&self) -> usize;
    pub fn max_packets(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn bytes(&self) -> usize;
    pub fn dropped(&self) -> u64;
    pub fn total(&self) -> u64;
    pub fn first_ts(&self) -> Option<Duration>;
    pub fn filter_text(&self) -> &str;
    pub fn rebuilding(&self) -> bool;
}
```

`netmon::sys`:

```rust
pub fn local_time(timestamp: Duration) -> Option<String>;
```

`netmon::ui`:

```rust
pub enum Pane { Packets, Layers, Explain, Bytes }
pub enum Overlay { Help, Glossary, Interfaces }

pub struct ScreenOptions {
    pub file: Option<PathBuf>,
    pub interface: Option<String>,
    pub capture_filter: Option<String>,
    pub max_packets: usize,
}
pub fn run(options: ScreenOptions) -> io::Result<()>;

// App has pub store: Store; remaining fields are private.
impl App {
    pub fn new(source: &str, live: bool, max_packets: usize) -> Self;
    pub fn on_message(&mut self, message: Message);
    pub fn push(&mut self, packet: RawPacket);
    pub fn on_tick(&mut self);
    pub fn on_event(&mut self, event: Event);
    pub fn draw(&mut self, frame: &mut Frame<'_>);
    pub fn selected_packet(&self) -> Option<u64>;
    pub fn focus(&self) -> Pane;
    pub fn overlay(&self) -> Option<&Overlay>;
    pub fn paused(&self) -> bool;
    pub fn following(&self) -> bool;
    pub fn should_quit(&self) -> bool;
    pub fn filter_input(&self) -> Option<&str>;
    pub fn filter_error(&self) -> Option<&filter::FilterError>;
    pub fn selected_range(&self) -> Option<Range<usize>>;
    pub fn select_packet(&mut self, number: u64);
    pub fn select_field(&mut self, proto: Proto, key: FieldKey);
    pub fn set_interfaces(&mut self, result: Result<Vec<Interface>, String>);
    pub fn take_interface_request(&mut self) -> Option<String>;
    pub fn take_interfaces_request(&mut self) -> bool;
    pub fn restart(&mut self, interface: &str);
}
```

`netmon::explain::ui`:

```rust
pub const HELP: &str;
pub const SCREEN_REQUIRES_TERMINAL: &str;
pub const MAX_PACKETS_ERROR: &str;
pub const SCREEN_OPTIONS_ERROR: &str;
```

Integration-test helper: `ui_support::packets() -> Vec<RawPacket>`.

**4. Deviations**

- Used `src/live/mod.rs` and `source.rs`, plus focused store test helpers, to comply with the updated modular rules.
- Added new CLI coverage in owned `tests/ui.rs`; shared `tests/cli.rs` contains only the permitted assertion update.
- Followed the brief’s interface exclusions rather than PLAN’s “first one that is up” default.
- Interpreted the byte cap as 256 MiB: 268,435,456 bytes.
- Kept `interfaces` pipeable following §5’s restriction to screen modes; §6.5’s non-terminal wording is broader. Missing-program failure is tested.

**5. Needed elsewhere**

None.

**6. Not verified**

**Direct evidence** covers fixture playback, TestBackend rendering/events, and synthetic child-process lifecycle tests. Those provide **indirect evidence** for dumpcap lifecycle behavior.

**No evidence found from real-terminal/live execution:** actual `dumpcap -D`, default live launch, `-i`, `-f`, real-terminal `-r`, interface selection/restart, resize, mouse clicks/wheel, or terminal restoration on quit, error, or panic.

Real-terminal keys still requiring manual exercise: `1`, Tab, Shift-Tab, arrows, `j`, `k`, PgUp, PgDn, Home, End, Enter, Space, `/`, Esc, `f`, `c`, `t`, `g`, `?`, `i`, `q`, and Ctrl-C. Test success does not establish those live paths.

**7. Suggested guide updates**

Make `examples/` optional in the size command when absent, and document the folder-module path for `live`.

**8. Questions**

None.