//! Handles modal text entry.
//! events.rs chooses when to enter these modes; filter.rs checks the grammar.
//! Read App::edit_key first for preserving an invalid filter until it is corrected.
use super::*;
use crate::text;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
impl App {
    /// Handles filter text without applying malformed input.
    pub(super) fn edit_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter_edit = None;
                self.filter_error = None;
            }
            KeyCode::Enter => {
                let input = self.filter_edit.clone().unwrap_or_default();
                // The conversation shortcut uses exact endpoint pairs. Its
                // editable label uses the general substring grammar, so applying
                // unchanged text must preserve the existing exact predicate.
                if input == self.store.filter_text() {
                    self.filter_edit = None;
                    self.filter_error = None;
                    return;
                }
                match filter::parse(&input) {
                    Ok(f) => {
                        self.apply_filter(input, f);
                        self.filter_edit = None;
                        self.filter_error = None;
                    }
                    Err(e) => self.filter_error = Some(e),
                }
            }
            KeyCode::Backspace => {
                if let Some(input) = &mut self.filter_edit {
                    input.pop();
                }
                self.filter_error = None;
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(input) = &mut self.filter_edit {
                    let c = text::sanitise(c.to_string().as_bytes());
                    // The editor shares the parser's byte cap, so any entered
                    // filter can be parsed without a second, larger allocation.
                    if input.len() + c.len() <= 4096 {
                        input.push_str(&c);
                    }
                }
                self.filter_error = None;
            }
            _ => {}
        }
    }
    /// Routes modal navigation, glossary search, and interface choice.
    pub(super) fn overlay_key(&mut self, key: KeyEvent) {
        let Some(overlay) = self.overlay.clone() else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.overlay = None,
            KeyCode::Up | KeyCode::Char('k') if overlay != Overlay::Glossary => {
                self.overlay_scroll = self.overlay_scroll.saturating_sub(1);
                self.interface_index = self.interface_index.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') if overlay != Overlay::Glossary => {
                self.overlay_scroll = self.overlay_scroll.saturating_add(1).min(4096);
                self.interface_index = self
                    .interface_index
                    .saturating_add(1)
                    .min(self.interfaces.len().saturating_sub(1));
            }
            KeyCode::Up => self.overlay_scroll = self.overlay_scroll.saturating_sub(1),
            KeyCode::Down => self.overlay_scroll = self.overlay_scroll.saturating_add(1).min(4096),
            KeyCode::PageUp => self.overlay_scroll = self.overlay_scroll.saturating_sub(10),
            KeyCode::PageDown => {
                self.overlay_scroll = self.overlay_scroll.saturating_add(10).min(4096)
            }
            KeyCode::Enter if overlay == Overlay::Interfaces => {
                if let Some(i) = self.interfaces.get(self.interface_index) {
                    self.request_interface = Some(i.name.clone());
                    self.overlay = None;
                }
            }
            KeyCode::Backspace if overlay == Overlay::Glossary => {
                self.glossary_search.pop();
                self.overlay_scroll = 0;
            }
            KeyCode::Char(c) if overlay == Overlay::Glossary => {
                // A glossary query is only a short substring, never a packet-sized
                // text buffer. Escaped non-ASCII input can grow by at most 16 bytes.
                if self.glossary_search.len() < 256 {
                    self.glossary_search
                        .push_str(&text::sanitise(c.to_string().as_bytes()));
                }
                self.overlay_scroll = 0;
            }
            KeyCode::Char('?') if overlay == Overlay::Help => self.overlay = None,
            KeyCode::Char('q') => self.quit = true,
            _ => {}
        }
    }
}
