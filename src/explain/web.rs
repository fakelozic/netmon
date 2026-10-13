//! Wording for the local web server's errors and unbuilt page.
//! HTTP parsing and access checks belong to `crate::web`.
//! Start with `error` for a reply sentence or `UNBUILT_PAGE` for build instructions.

/// Embedded page used when `web/dist` is absent. It loads no scripts or remote files.
pub const UNBUILT_PAGE: &str = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>netmon</title><body><h1>The netmon page has not been built.</h1><p>Run <code>cd web &amp;&amp; nub install &amp;&amp; nub run build</code>, then rebuild netmon.</p></body></html>";

/// Command-line help for source selection, private logging and browser startup.
pub const HELP: &str = "Usage: netmon web [-i IFACE | -r FILE] [-f CAPTURE_FILTER]\n                  [--port N] [--no-open] [--log-dir DIR] [--record]\n                  [--no-log] [--max-packets N]\n\n-i, --interface IFACE       Capture on this interface; otherwise choose one.\n-r, --read FILE             Read a saved pcap or pcapng; stay open after EOF.\n-f, --capture-filter TEXT   Limit live capture with a dumpcap filter.\n    --port N               First loopback port, 1-65535 (default 7979).\n                           Try through 7999; ports above 7999 use only N.\n    --no-open              Print the URL without launching a browser.\n    --log-dir DIR          Parent folder for private session logs.\n    --record               Record original bytes, including private payloads.\n    --no-log               Create no files; also disables recording/export.\n    --max-packets N        Retain 1-200000 packets (default 200000).\n-h, --help                 Show this help.\n\nCtrl-C or SIGTERM stops capture and flushes logs. Keep the URL token private.\n";

/// Plain error wording for server-generated HTTP failures, without request text.
pub fn error(status: u16) -> &'static str {
    match status {
        400 => "The web request is not valid.",
        401 => "The web session token is missing or incorrect.",
        403 => "This request does not come from the local netmon page.",
        404 => "The requested page or API endpoint was not found.",
        405 => "This request method is not supported here.",
        408 => "The web request took longer than five seconds.",
        413 => "The request body exceeds 4 KB.",
        431 => "The request line and headers exceed 8 KB.",
        503 => "The web server already has 32 active connections. Try again.",
        _ => "The web server could not complete the request.",
    }
}

/// HTTP reason phrases used in the status line, rather than explanatory text.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Response",
    }
}

/// Startup error when the operating system cannot provide all 128 random bits.
pub const TOKEN_ERROR: &str = "Cannot read the web session token from /dev/urandom";
/// Startup error when the first candidate port is above the last candidate.
pub const PORT_RANGE_ERROR: &str = "The first web port must not exceed the last web port.";
/// Startup error when every candidate port is occupied.
pub const PORTS_BUSY: &str = "Every port in the requested web port range is busy.";
/// Terminal line for a URL whose token is kept in the fragment, not an HTTP path.
pub fn open_url(url: &str) -> String {
    format!("netmon web: open {url}")
}

/// Reply when the engine response exceeds the two-second deadline.
pub const ENGINE_TIMEOUT: &str = "The packet engine did not answer within two seconds. Try again.";
/// Reply when packet retention has removed the requested bytes.
pub const PACKET_GONE: &str = "The requested packet is no longer in memory.";
/// Reply when conversation retention has removed the requested evidence.
pub const FLOW_GONE: &str = "The requested conversation is no longer in memory.";
/// Reply for an action requiring a private log session.
pub const LOGGING_OFF: &str = "Logging is off. Recording and story export need a log session.";
/// Reply when raw recording cannot accept further writes.
pub const RECORDING_FAILED: &str = "Raw recording failed. Check the session logging problem.";
/// Reply when the recording size cap cannot fit a capture header.
pub const RECORDING_FULL: &str = "The recording size limit cannot fit another capture.";
/// Reply for a story export write failure.
pub const EXPORT_FAILED: &str =
    "The conversation story could not be written to the session folder.";
/// Reply for an action outside the documented control vocabulary.
pub const UNKNOWN_ACTION: &str = "This control action is not supported.";
/// Startup notice when only the embedded placeholder is available.
pub const PLACEHOLDER_NOTE: &str = "netmon web: the page is a placeholder; run cd web && nub install && nub run build, then rebuild netmon.";
/// Startup note when a desktop browser cannot be launched.
pub const OPEN_FAILED: &str =
    "netmon web: could not open the browser; open the printed URL yourself.";
/// Command-line error for an unusable web port.
pub const PORT_ERROR: &str = "The web port must be between 1 and 65535.";
/// Conversation title from an optional process name and remote endpoint.
pub(crate) fn flow_title(app: Option<&str>, remote: &str) -> String {
    format!("{} → {remote}", app.unwrap_or("unknown app"))
}

/// Reply when the bounded engine request queue is full or disconnected.
pub const ENGINE_BUSY: &str = "The packet engine is busy or unavailable. Try again.";
