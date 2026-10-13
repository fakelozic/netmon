**1. Built**

Implemented the standard-library web server core: bounded HTTP parsing, loopback binding, token authentication, Host/Origin checks, safety headers, embedded assets, fallback page, and [webstub](examples/webstub.rs). API requests dispatch through `Api`.

**2. Acceptance results**

All Cargo commands used `CARGO_BUILD_JOBS=4`.

| Command | Outcome and final output |
|---|---|
| `cargo fmt --check` | **PASS**; empty output |
| `cargo clippy --offline --all-targets -- -D warnings` | **PASS**; `Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.63s` |
| `cargo test --offline` | **FAIL**, three pre-existing UI failures; output below |
| `cargo build --release --offline` | **PASS**; `Finished `release` profile [optimized] target(s) in 8.35s` |
| `ls -l target/release/netmon` | **PASS**; binary size **954224 bytes** |

Direct evidence from the [acceptance test log](target/web-acceptance-tests.log):

```text
failures:
    layout_tests::reference_overlays_fit_content_and_center
    movement_pages_focus_expansion_pause_and_time
    screen_goldens

test result: FAILED. 14 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.44s

error: test failed, to rerun pass `--test ui`
```

The same failures occurred [before editing](target/web-ui-baseline.log). The run using `--no-fail-fast` ended with:

```text
error: 1 target failed:
    `--test ui`
```

The final web integration run reported:

```text
test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
```

Six of those cases were permission skips, listed below. The remaining tests include 20,000 fixed-seed mutations. The example also builds successfully.

Both remaining acceptance commands **PASS**, with empty output. `grep` exits 1 because it finds no matches:

```sh
find src tests examples build.rs -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
grep -rn "0\.0\.0\.0\|INADDR_ANY\|UNSPECIFIED" src/web build.rs
```

Line counts for every created or changed Rust file:

```text
 70 build.rs
 38 src/lib.rs
 29 src/explain.rs
 53 src/explain/web.rs
 64 src/web/assets.rs
 83 src/web/connection.rs
 95 src/web/mod.rs
114 src/web/parser.rs
 91 src/web/response.rs
 93 src/web/routing.rs
 52 src/web/routing_tests.rs
109 src/web/server.rs
 57 src/web/target.rs
 56 src/web/token.rs
 41 examples/webstub.rs
 20 tests/web.rs
111 tests/web/build.rs
155 tests/web/headers.rs
 61 tests/web/mod.rs
159 tests/web/parser.rs
 64 tests/web/robustness.rs
177 tests/web/rules.rs
247 tests/web/sockets.rs
 35 tests/web/token.rs
```

**3. Public interface**

Available through [netmon::web](src/web/mod.rs):

```rust
pub enum Method { Get, Head, Post, Options, Other }

pub struct Request {
    pub method: Method,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

pub enum Parsed { Complete(Request, usize), Incomplete, Bad(u16) }
pub struct Config { pub port: u16, pub token: Token }
pub struct ApiReply { pub status: u16, pub json: String }

pub trait Api: Send + Sync {
    fn handle(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &[u8],
    ) -> ApiReply;
}

pub fn parse_request(bytes: &[u8]) -> Parsed;
pub fn write_response(r: &Response, out: &mut Vec<u8>);
pub fn respond(req: &Request, cfg: &Config, api: &dyn Api) -> Response;
```

`Token` has private storage and implements `Clone` and `Display`:

```rust
pub fn generate() -> io::Result<Token>;
pub fn matches(&self, candidate: &str) -> bool;
```

`Server` has private fields:

```rust
pub fn bind(first_port: u16, last_port: u16) -> io::Result<Server>;
pub fn port(&self) -> u16;
pub fn url(&self, token: &Token) -> String;
pub fn serve(self, token: Token, api: Arc<dyn Api>, stop: Arc<AtomicBool>);
```

[netmon::explain::web](src/explain/web.rs) exposes:

```rust
pub fn error(status: u16) -> &'static str;
pub fn reason(status: u16) -> &'static str;
pub fn open_url(url: &str) -> String;
```

Its public `&str` constants are `UNBUILT_PAGE`, `TOKEN_ERROR`, `PORT_RANGE_ERROR`, and `PORTS_BUSY`.

**4. Deviations**

None from the brief. The three documented UI failures remain unchanged.

**5. Needed elsewhere**

Repair the three UI tests. Later integration must implement `Api` and wire the CLI, browser opening, capture shutdown, and log flushing.

**6. Not verified**

No execution evidence found for real socket behavior. These tests printed permission-denied notices and passed as instructed:

- `empty_client_times_out`
- `fetch_routes`
- `occupied_ports_and_invalid_range`
- `partial_bad_and_pipelined_requests`
- `stop_wakes_idle_connections_and_ends_serve`
- `thirty_third_connection_is_refused`

Browser behavior and the unavailable-`/dev/urandom` failure path were not exercised. Source inspection provides indirect evidence for constant-time comparison; hardware timing was not measured.

Logical fallacy check: skipped tests do not establish socket correctness, and fixed-seed mutations do not prove safety for every possible input.

**7. Suggested guide updates**

Clarify the test guide’s exceptions for explicitly required OS token randomness and real socket deadline tests.

**8. Questions**

None.