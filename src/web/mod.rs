//! Serves an embedded page through a bounded loopback HTTP server.
//! `parser` reads requests, `routing` checks access, and `response` writes replies.
//! `assets` contains compiled files; `token` supplies the per-session secret.
//! `server` accepts sockets and `connection` handles their bounded reads.
//! Start with `respond` for socket-free use or `Server::bind` for serving.
//! `api` implements packet queries and controls; `command` starts a complete session.

/// Packet engine and authenticated JSON endpoint implementation.
pub mod api;
mod assets;
/// Complete browser-session startup and graceful shutdown.
pub mod command;
mod connection;
mod parser;
mod response;
mod routing;
mod server;
mod target;
mod token;

pub use parser::parse_request;
pub use response::write_response;
pub use routing::respond;
pub use server::Server;
pub use token::Token;

// These bounds cap each connection's request storage even before parsing succeeds.
const HEADER_LIMIT: usize = 8 * 1024;
const BODY_LIMIT: usize = 4 * 1024;

/// HTTP methods understood by the router. Other valid method names become `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Options,
    Other,
}

/// One parsed HTTP request. Header names are lowercase; query values are decoded.
/// The parser bounds headers to 8 KiB and the body to 4 KiB, without reading sockets.
#[derive(Debug)]
pub struct Request {
    pub method: Method,
    /// Decoded absolute path, without a query string or a fragment.
    pub path: String,
    /// Ordered query pairs, with percent escapes decoded and `+` changed to spaces.
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// One HTTP reply. `write_response` enforces safety headers on the wire as well.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    /// Includes safety headers and byte length. HEAD preserves the GET length.
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

/// A complete request plus bytes consumed, a need for more bytes, or an HTTP error.
#[derive(Debug)]
pub enum Parsed {
    /// The offset includes the body; any remaining bytes belong to another request.
    Complete(Request, usize),
    Incomplete,
    /// Status to return through the server's standard JSON error response.
    Bad(u16),
}

/// Access settings for a server already bound to this loopback port.
pub struct Config {
    pub port: u16,
    pub token: Token,
}

/// A thread-safe provider of authenticated JSON API replies.
/// Implementations sanitise outside text and hide secrets before returning JSON.
pub trait Api: Send + Sync {
    /// `path` is what follows `/api/`, without the query string.
    /// Query pairs are decoded. Bodies have at most 4 KiB; no socket locks are held.
    fn handle(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &[u8],
    ) -> ApiReply;
}

/// A complete UTF-8 JSON document from an API provider, including error documents.
pub struct ApiReply {
    /// Final HTTP status, from 200 through 599; invalid values become a 500 error.
    pub status: u16,
    pub json: String,
}
