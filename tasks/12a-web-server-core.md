# Task 12a — the web server's core

Read the root `AGENTS.md` in full, then `docs/web-api.md`. The "Safety rules" table in that file is
the specification for most of this task.

## Goal

A small HTTP server inside netmon that serves the web page's files and passes `/api/` requests to a
handler, enforcing every safety rule in the contract. It uses only the standard library.

This task builds the server and its rules. It does **not** build the data endpoints: the pipeline they
read from is being finished by another agent. Requests under `/api/` go to a trait, and a later task
implements that trait.

## Parallel work

Two other agents are working at the same time: one on the pipeline (`src/pipeline/`, `src/log/`), one
on the web page (`web/`). You cannot see their work. Do not touch those paths, `src/main.rs`, or `src/ui/`.

**You own:** everything in `src/web/`, `src/explain/web.rs`, `build.rs`, `examples/webstub.rs`,
`tests/web.rs` and everything in `tests/web/`.

**Shared files:**
- `src/lib.rs` — add `pub mod web;` with a doc comment. Nothing else.
- `src/explain.rs` — add one line, `pub mod web;`, with the other `mod` lines. Nothing else.

## 1. Two layers

Codex's sandbox cannot open sockets, so the logic must be testable without one.

**The pure layer** has no sockets and no threads:

```rust
pub struct Request { pub method: Method, pub path: String, pub query: Vec<(String, String)>,
                     pub headers: Vec<(String, String)>, pub body: Vec<u8> }
pub struct Response { pub status: u16, pub content_type: &'static str,
                      pub headers: Vec<(&'static str, String)>, pub body: Vec<u8> }

pub enum Parsed { Complete(Request, usize), Incomplete, Bad(u16) }   // usize: bytes consumed
pub fn parse_request(bytes: &[u8]) -> Parsed;
pub fn write_response(r: &Response, out: &mut Vec<u8>);

pub struct Config { pub port: u16, pub token: Token }
pub trait Api: Send + Sync {
    /// `path` is what follows `/api/`, without the query string.
    fn handle(&self, method: Method, path: &str, query: &[(String, String)], body: &[u8]) -> ApiReply;
}
pub struct ApiReply { pub status: u16, pub json: String }

pub fn respond(req: &Request, cfg: &Config, api: &dyn Api) -> Response;
```

`respond` applies every rule and routes: static files, `/api/…` to the trait, anything else `404`.

**The socket layer** is thin: bind, accept, read with limits and a timeout, call `parse_request` and
`respond`, write, close.

```rust
pub struct Server { /* private */ }
impl Server {
    pub fn bind(first_port: u16, last_port: u16) -> io::Result<Server>;   // 127.0.0.1 only
    pub fn port(&self) -> u16;
    pub fn url(&self, token: &Token) -> String;      // http://127.0.0.1:<port>/#k=<token>
    pub fn serve(self, token: Token, api: Arc<dyn Api>, stop: Arc<AtomicBool>);  // returns when stop is set
}
```

## 2. Rules to enforce (all from `docs/web-api.md`)

- Bind `127.0.0.1` only. There must be no code path that binds any other address.
- `Token`: 16 bytes read from `/dev/urandom`, shown as 32 lowercase hex characters. Compared in
  constant time. If `/dev/urandom` cannot be read, starting fails with a clear error; never fall back
  to a weaker source.
- `/api/` requests: `401` without a correct `X-Netmon-Token` header.
- Every request: `403` unless `Host` is `127.0.0.1:<port>` or `localhost:<port>`.
- Every request with an `Origin` header: `403` unless it is this server's own origin.
- No CORS headers, ever. An `OPTIONS` request gets `405`.
- Every response carries the `Content-Security-Policy` given in the contract, exactly, plus
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
  `Content-Length` and `Connection: close`.
- Methods: `GET` and `HEAD` for files; `GET` and `POST` for `/api/`. Others get `405`.
- Limits: request line plus headers at most 8 KB (`431`), body at most 4 KB (`413`), a 5-second read
  timeout, at most 32 connections at once (further ones get `503` and are closed).
- One request per connection. HTTP/1.1 and 1.0 are accepted; anything else is `400`.
- Error replies are JSON `{"error": "plain sentence"}`, with wording from `src/explain/web.rs`.
- Request bytes are untrusted: the parser never panics, never allocates beyond the limits, and
  rejects a path containing `..`, a NUL byte, or a backslash.

## 3. The page's files

The page is a Vite build in `web/dist` (`index.html`, `assets/app.js`, `assets/app.css`, font files).
It may not exist when netmon is compiled, so:

- `build.rs` looks for `web/dist`. If it exists, it generates Rust code that embeds every file under it
  with `include_bytes!`, keyed by its path relative to `web/dist`. If it does not exist, it embeds a
  single built-in `index.html` that says the page has not been built and how to build it
  (`cd web && nub install && nub run build`, then rebuild netmon).
- `build.rs` prints `cargo:rerun-if-changed=web/dist`, uses only the standard library, and skips any
  file over 8 MB and any path that is not plain ASCII without `..`.
- `/` serves `index.html`. `/assets/<name>` serves that file. Lookup is an exact match in the embedded
  table, so no path can reach the disk.
- `Content-Type` by extension: `html`, `js`, `css`, `svg`, `woff2`, `woff`, `png`, `ico`, `json`,
  `map`; anything else `application/octet-stream`.

## 4. Example program (`examples/webstub.rs`)

`cargo run --offline --example webstub` binds the server, prints its URL, and serves the embedded page
with an `Api` that answers `/api/session` with a fixed "ended" session and everything else with `404`.
It runs until interrupted. This is how the server will be tried in a real browser after your report.

## 5. Tests

Everything except item 6 must run without sockets.

1. **Parser**: a simple `GET`; a `POST` with a body; query strings with percent-encoding and `+`;
   header names in any case; a request split across reads (`Incomplete`); each limit; bad request
   lines; unsupported versions; paths with `..`, NUL and backslash.
2. **Rules**, each with a passing and a failing case: token missing, wrong, and right; `Host` values
   including another port, another name, and none; `Origin` own, foreign, and `null`; `OPTIONS`;
   disallowed methods.
3. **Headers**: every response, including every error, carries the exact policy and the other headers.
   No response ever contains a header starting with `Access-Control-`.
4. **Files**: `/` and an asset are served with the right type; `/assets/../Cargo.toml`,
   `/assets/%2e%2e/x`, `//etc/passwd` and an unknown asset are `404` or `400` and never read the disk.
5. **Never panics**: 20,000 fixed-seed mutations of valid requests, and every prefix of a valid request.
6. **Sockets** (`tests/web/sockets.rs`): bind, fetch `/` and `/api/session` with and without the token
   over a real connection, check the 33rd simultaneous connection gets `503`, check a client that
   sends nothing is dropped after the timeout, check `stop` ends `serve`. **If creating a socket fails
   with a permission error, print a notice and pass**: the sandbox forbids sockets, and these will be
   run outside it.
7. **Token**: 32 hex characters; two tokens differ; comparison is correct for equal, different and
   different-length input.

## 6. Acceptance commands

```sh
cargo fmt --check
cargo clippy --offline --all-targets -- -D warnings
cargo test --offline
cargo build --release --offline
ls -l target/release/netmon
find src tests examples build.rs -name '*.rs' -exec wc -l {} + | awk '$2 != "total" && $1 > 500'
grep -rn "0\.0\.0\.0\|INADDR_ANY\|UNSPECIFIED" src/web build.rs
```

The size check and the last `grep` must print nothing. Three `ui` tests fail on `main` for a known
reason that is not yours to fix (they quote older field text); report them as pre-existing and make
sure nothing else fails. In the report, say which tests were skipped because the sandbox has no sockets.
