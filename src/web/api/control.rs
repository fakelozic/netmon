//! Parses bounded control objects and applies engine-owned actions.
//! Capture never pauses; `state` freezes the browser's published evidence.
//! Read `State::control` first; story escaping belongs to `explain::pipeline`.
//! Raw recording preserves captured payload bytes in the private session folder.

use super::{records::ResultJson, state::State};
use crate::{
    explain::{self, web as words},
    flow::FlowId,
    log::{Json, JsonValue as V, Recording},
};

struct Control {
    action: String,
    flow: Option<u32>,
}
impl State {
    /// Applies one validated control object and returns the published session.
    pub fn control(&mut self, body: &[u8]) -> ResultJson {
        let control = parse(body).ok_or((400, words::error(400)))?;
        let mut path = None;
        match control.action.as_str() {
            "pause" if control.flow.is_none() => self.pause(),
            "resume" if control.flow.is_none() => self.resume(),
            "record_start" | "record_stop" if control.flow.is_none() => {
                let session = self
                    .pipeline
                    .session_mut()
                    .ok_or((400, words::LOGGING_OFF))?;
                if control.action == "record_start" {
                    session.start_recording();
                } else {
                    session.stop_recording();
                }
                if session.recording() == Recording::Failed {
                    return Err((400, words::RECORDING_FAILED));
                }
                if control.action == "record_start" && session.recording() == Recording::Full {
                    return Err((400, words::RECORDING_FULL));
                }
            }
            "export_story" => {
                if self.pipeline.session().is_none() {
                    return Err((400, words::LOGGING_OFF));
                }
                let id = FlowId(
                    control
                        .flow
                        .filter(|n| *n != 0)
                        .ok_or((400, words::error(400)))?,
                );
                let flow = self
                    .paused
                    .as_ref()
                    .map_or_else(
                        || self.pipeline.tracker().flow(id),
                        |p| p.flows.iter().find(|f| f.id == id),
                    )
                    .ok_or((400, words::FLOW_GONE))?;
                let markdown = explain::pipeline::story_markdown(
                    flow,
                    self.pipeline.tracker().names(),
                    self.app(id).map(|a| a.name.as_str()),
                );
                let session = self
                    .pipeline
                    .session_mut()
                    .ok_or((400, words::LOGGING_OFF))?;
                let saved = session
                    .export_markdown(&format!("story-{}", id.0), &markdown)
                    .map_err(|_| (500, words::EXPORT_FAILED))?;
                path = Some(crate::text::sanitise(saved.to_string_lossy().as_bytes()));
            }
            _ => return Err((400, words::UNKNOWN_ACTION)),
        }
        let mut json = Json::object()
            .bool("ok", true)
            .value("session", session_value(self));
        if let Some(path) = path {
            json = json.str("path", &path);
        }
        Ok(json.finish())
    }
}
fn session_value(state: &State) -> V {
    // A session is produced by the shared encoder, never by outside JSON text.
    Json::encoded_object(state.session())
}
fn parse(body: &[u8]) -> Option<Control> {
    let text = std::str::from_utf8(body).ok()?;
    let mut parser = Parser { text, pos: 0 };
    parser.need(b'{')?;
    let mut action = None;
    let mut flow = None;
    loop {
        let key = parser.string()?;
        parser.need(b':')?;
        match key.as_str() {
            "action" if action.is_none() => action = Some(parser.string()?),
            "flow" if flow.is_none() => {
                parser.space();
                let start = parser.pos;
                while parser.peek().is_some_and(|b| b.is_ascii_digit()) {
                    parser.pos += 1;
                }
                let digits = parser.text.get(start..parser.pos)?;
                if digits.len() > 1 && digits.starts_with('0') {
                    return None;
                }
                flow = Some(digits.parse().ok()?);
            }
            _ => return None,
        }
        parser.space();
        if parser.peek() == Some(b'}') {
            parser.pos += 1;
            break;
        }
        parser.need(b',')?;
    }
    parser.space();
    (parser.pos == text.len()).then_some(Control {
        action: action?,
        flow,
    })
}
struct Parser<'a> {
    text: &'a str,
    pos: usize,
}
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }
    fn need(&mut self, byte: u8) -> Option<()> {
        self.space();
        if self.peek()? != byte {
            return None;
        }
        self.pos += 1;
        Some(())
    }
    fn string(&mut self) -> Option<String> {
        self.need(b'"')?;
        let mut out = String::new();
        loop {
            let ch = self.text.get(self.pos..)?.chars().next()?;
            self.pos += ch.len_utf8();
            match ch {
                '"' => return Some(out),
                '\\' => {
                    let escape = self.peek()?;
                    self.pos += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => out.push(char::from(escape)),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let end = self.pos.checked_add(4)?;
                            let code =
                                u32::from_str_radix(self.text.get(self.pos..end)?, 16).ok()?;
                            self.pos = end;
                            out.push(char::from_u32(code)?);
                        }
                        _ => return None,
                    }
                }
                '\u{0000}'..='\u{001f}' => return None,
                _ => out.push(ch),
            }
        }
    }
}
