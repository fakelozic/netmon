//! Serves the embedded page with a fixed ended session for browser checks.
//! HTTP safety belongs to `netmon::web`; real traffic endpoints belong to integration.
//! Read `main` first. The printed URL keeps the token outside the HTTP request path.

use netmon::web::{Api, ApiReply, Method, Server, Token};
use std::io;
use std::sync::{Arc, atomic::AtomicBool};

struct Stub;

impl Api for Stub {
    fn handle(&self, method: Method, path: &str, _: &[(String, String)], _: &[u8]) -> ApiReply {
        if method == Method::Get && path == "session" {
            ApiReply {
                status: 200,
                json: concat!(
                    "{\"version\":\"0.1.0\",\"mode\":\"file\",\"source\":\"stub\",",
                    "\"state\":\"ended\",\"error\":null,\"started\":\"2026-10-13T00:00:00Z\",",
                    "\"packets\":0,\"dropped\":0,\"bytes\":0,\"conversations\":0,\"alerts\":0,",
                    "\"rate\":[],\"log_dir\":null,\"recording\":\"off\",\"problem\":null}"
                )
                .into(),
            }
        } else {
            ApiReply {
                status: 404,
                json: format!("{{\"error\": \"{}\"}}", netmon::explain::web::error(404)),
            }
        }
    }
}

fn main() -> io::Result<()> {
    let token = Token::generate()?;
    let server = Server::bind(7979, 7999)?;
    println!("{}", netmon::explain::web::open_url(&server.url(&token)));
    // The default interrupt action ends this stateless browser stub. The real
    // command supplies its capture supervisor's stop flag and log flushing.
    server.serve(token, Arc::new(Stub), Arc::new(AtomicBool::new(false)));
    Ok(())
}
