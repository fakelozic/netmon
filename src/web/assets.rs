//! Looks up page files compiled into the executable by `build.rs`.
//! Access checks belong to `routing`; no runtime request reaches the filesystem.
//! Read `serve` first. Content types tell a browser how to interpret a file's bytes.

use super::{Response, response};

include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

pub(super) fn serve(path: &str, files: &[(&str, &[u8])]) -> Response {
    let key = if path == "/" {
        "index.html"
    } else if let Some(key) = path.strip_prefix("/assets/") {
        if key.is_empty() {
            return response::error(404);
        }
        path.trim_start_matches('/')
    } else {
        return response::error(404);
    };
    // An exact table match prevents both traversal and accidental disk fallback.
    match files.iter().find(|(name, _)| *name == key) {
        Some((name, bytes)) => response::reply(200, content_type(name), bytes.to_vec()),
        None => response::error(404),
    }
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("json" | "map") => "application/json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_types() {
        for (extension, expected) in [
            ("html", "text/html; charset=utf-8"),
            ("js", "text/javascript; charset=utf-8"),
            ("css", "text/css; charset=utf-8"),
            ("svg", "image/svg+xml"),
            ("woff2", "font/woff2"),
            ("woff", "font/woff"),
            ("png", "image/png"),
            ("ico", "image/x-icon"),
            ("json", "application/json"),
            ("map", "application/json"),
            ("bin", "application/octet-stream"),
        ] {
            assert_eq!(content_type(&format!("assets/file.{extension}")), expected);
        }
    }
}
