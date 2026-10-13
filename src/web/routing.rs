//! Applies Host, Origin, token and method rules before dispatching a request.
//! HTTP framing belongs to `parser`; traffic data belongs to the caller's `Api`.
//! Read `respond` first. Origin names the scheme, host and port of a browser page.

use super::{Api, BODY_LIMIT, Config, Method, Request, Response, assets, response, target};

/// Checks access and dispatches to embedded files or an authenticated API provider.
/// Every reply includes safety headers; files accept GET/HEAD and APIs GET/POST.
/// Duplicate access headers fail closed, including on hand-built requests.
pub fn respond(req: &Request, cfg: &Config, api: &dyn Api) -> Response {
    respond_with_files(req, cfg, api, assets::FILES)
}

fn respond_with_files(
    req: &Request,
    cfg: &Config,
    api: &dyn Api,
    files: &[(&str, &[u8])],
) -> Response {
    let mut reply = route(req, cfg, api, files);
    if req.method == Method::Head {
        // HEAD has the GET headers, including length, but never a body (RFC 9110, 9.3.2).
        reply.body.clear();
    }
    reply
}

fn route(req: &Request, cfg: &Config, api: &dyn Api, files: &[(&str, &[u8])]) -> Response {
    let ip_host = format!("127.0.0.1:{}", cfg.port);
    let localhost = format!("localhost:{}", cfg.port);
    let Some(host) = single_header(req, "host") else {
        return response::error(403);
    };
    if host != ip_host && host != localhost {
        return response::error(403);
    }
    if req
        .headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("origin"))
    {
        let Some(origin) = single_header(req, "origin") else {
            return response::error(403);
        };
        if origin != format!("http://{host}") {
            return response::error(403);
        }
    }
    if req.method == Method::Options {
        return response::error(405);
    }
    if req.body.len() > BODY_LIMIT {
        return response::error(413);
    }
    if target::forbidden_path(&req.path) || req.path.starts_with("//") {
        return response::error(400);
    }
    if let Some(path) = req.path.strip_prefix("/api/") {
        let candidate = single_header(req, "x-netmon-token").unwrap_or("");
        if !cfg.token.matches(candidate) {
            return response::error(401);
        }
        if !matches!(req.method, Method::Get | Method::Post) {
            return response::error(405);
        }
        let reply = api.handle(req.method, path, &req.query, &req.body);
        if !(200..=599).contains(&reply.status) {
            return response::error(500);
        }
        response::reply(reply.status, "application/json", reply.json.into_bytes())
    } else if matches!(req.method, Method::Get | Method::Head) {
        assets::serve(&req.path, files)
    } else {
        response::error(405)
    }
}

fn single_header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    let mut values = req
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let (_, value) = values.next()?;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
