//! Checks static routing against a small synthetic embedded table.
//! Filesystem embedding is tested in `tests/web/build.rs`; API rules in `tests/web/rules.rs`.
//! Read `embedded_files_and_head` first. No page build or socket is needed here.

use super::*;
use crate::web::{ApiReply, Token};

struct UnusedApi;
impl Api for UnusedApi {
    fn handle(&self, _: Method, _: &str, _: &[(String, String)], _: &[u8]) -> ApiReply {
        panic!("static files must not call the API")
    }
}

#[test]
fn embedded_files_and_head() {
    let cfg = Config {
        port: 7979,
        token: Token::generate().expect("OS token"),
    };
    let mut req = Request {
        method: Method::Get,
        path: "/".into(),
        query: vec![],
        headers: vec![("Host".into(), "127.0.0.1:7979".into())],
        body: vec![],
    };
    let files: &[(&str, &[u8])] = &[("index.html", b"<p>page</p>"), ("assets/app.js", b"app()")];
    let root = respond_with_files(&req, &cfg, &UnusedApi, files);
    assert_eq!(
        (root.status, root.content_type),
        (200, "text/html; charset=utf-8")
    );
    assert_eq!(root.body, b"<p>page</p>");
    req.path = "/assets/app.js".into();
    let get = respond_with_files(&req, &cfg, &UnusedApi, files);
    assert_eq!(
        (get.status, get.content_type),
        (200, "text/javascript; charset=utf-8")
    );
    assert_eq!(get.body, b"app()");
    req.method = Method::Head;
    let head = respond_with_files(&req, &cfg, &UnusedApi, files);
    assert_eq!(head.status, 200);
    assert_eq!(head.headers, get.headers);
    assert!(head.body.is_empty());
    req.path = "/index.html".into();
    assert_eq!(
        respond_with_files(&req, &cfg, &UnusedApi, files).status,
        404
    );
}
