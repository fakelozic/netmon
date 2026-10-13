//! Holds HTTP field definitions and their packet-specific interpretations.
//! Field routing belongs to `super`; protocol parsing belongs to `crate::decode`.
//! Start with `description`.

use crate::decode::{Decoded, Field};

/// Closed set of HTTP fields; names mirror `FieldKey`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    RequestLine,
    Method,
    Target,
    Version,
    StatusLine,
    Status,
    Reason,
    Header,
    Body,
}

/// Returns the static label, definition and significance for this family's closed keys.
pub(super) fn description(key: Kind) -> (&'static str, &'static str, &'static str) {
    match key {
        // RFC 9112, section 3.
        Kind::RequestLine => (
            "Request line",
            "Tells the web server what action is wanted, which page or service it concerns, and which HTTP rules to use.",
            "",
        ),
        // RFC 9110, section 9.
        Kind::Method => (
            "Method",
            "Tells the web server what to do, such as fetch a page with GET or submit data with POST.",
            "",
        ),
        // RFC 9112, section 3.2.
        Kind::Target => (
            "Request target",
            "Identifies the page, file, or service the client wants the web server to act on.",
            "",
        ),
        // RFC 9112, section 2.3.
        Kind::Version => (
            "HTTP version",
            "Tells the receiver which HTTP rules to use to read this web message.",
            "",
        ),
        // RFC 9112, section 4.
        Kind::StatusLine => (
            "Status line",
            "Tells the client which HTTP rules the server uses and how the request turned out.",
            "",
        ),
        // RFC 9110, section 15.
        Kind::Status => (
            "Status code",
            "Reports the web request's result, such as success, redirection to another location, or an error.",
            "",
        ),
        // RFC 9112, section 4.
        Kind::Reason => (
            "Reason phrase",
            "Adds a short human-readable description of the web result. The numeric status code decides its meaning.",
            "",
        ),
        // RFC 9110, section 6.3.
        Kind::Header => (
            "Header",
            "Gives extra details about a web request or reply, such as the site name or content type. netmon hides credentials and cookie values.",
            "",
        ),
        // RFC 9112, section 6.
        Kind::Body => (
            "Body size",
            "Shows how many bytes are captured after the web headers in this packet. These usually carry the page or submitted data.",
            "Other packets may carry more of the message. This field does not show the complete response size.",
        ),
    }
}

/// Interprets web actions and results; fields without a further conclusion return empty text.
pub(super) fn here(key: Kind, field: &Field, _packet: &Decoded) -> String {
    match key {
        // RFC 9110, sections 9 and 15: methods request actions; status classes describe results.
        Kind::Method => match field.value.as_str() {
            "GET" => "The client asks for the contents of a page or other resource.",
            "HEAD" => {
                "The client asks for the same headers as GET would return, with no response body."
            }
            "POST" => "The client submits data for the server to process.",
            "PUT" => "The client asks to create or replace the target's contents.",
            "DELETE" => "The client asks the server to delete the target.",
            "CONNECT" => "The client asks a proxy to open a tunnel to another server.",
            "OPTIONS" => "The client asks which communication choices the server supports.",
            "TRACE" => {
                "The client asks for a diagnostic copy of its request as the server received it."
            }
            "PATCH" => "The client asks to apply changes to the target's contents.",
            _ => "",
        }
        .into(),
        Kind::Status => status_meaning(field.num.unwrap_or(0)),
        Kind::Header if field.value.starts_with("Host:") => {
            "This tells the server which site the client wants when several sites share an address."
                .into()
        }
        Kind::RequestLine
        | Kind::Target
        | Kind::Version
        | Kind::StatusLine
        | Kind::Reason
        | Kind::Header
        | Kind::Body => String::new(),
    }
}

fn status_meaning(n: u64) -> String {
    // RFC 9110, sections 15.1–15.6; RFC 9112, section 6.3: some successes carry no body.
    let meaning = match n {
        200 => "the request succeeded",
        204 => "the request succeeded and the response has no body",
        301 | 302 | 307 | 308 => "the server directs the client to a different location",
        304 => "the client's saved copy can be reused",
        400 => "the server could not process the request as sent",
        401 => "the request needs valid login credentials",
        403 => "the server refuses this request",
        404 => "the server cannot find the requested resource or will not reveal it",
        500 => "the server encountered an unexpected problem",
        _ => status_class(n),
    };
    format!("{n} means {meaning}.")
}

fn status_class(n: u64) -> &'static str {
    match n / 100 {
        1 => "this is an interim reply, with a final reply still expected",
        2 => "the server reports success",
        3 => "the result concerns redirection or a saved copy",
        4 => "the server reports a problem with the request",
        5 => "the server reports a failure while handling the request",
        _ => "this is outside the usual HTTP status classes",
    }
}
