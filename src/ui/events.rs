//! Routes input to the focused pane.
//! editing.rs owns text entry; state.rs owns packet selection and pause state.
//! Read App::on_event first; it never reads a keyboard or waits for capture.
use super::*;
use crate::explain::ui as words;
use ratatui::crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
impl App {
    /// Applies a supplied key, mouse, or resize event without terminal IO.
    /// Release events are ignored; Ctrl-C works even inside an overlay or editor.
    pub fn on_event(&mut self, event: Event) {
        match event {
            Event::Key(key) if key.kind != KeyEventKind::Release => self.key(key),
            Event::Mouse(mouse) => self.mouse(mouse),
            _ => {}
        }
    }
    fn mouse(&mut self, mouse: MouseEvent) {
        if self.overlay.is_some() {
            match mouse.kind {
                MouseEventKind::ScrollUp => {
                    self.overlay_scroll = self.overlay_scroll.saturating_sub(3)
                }
                MouseEventKind::ScrollDown => {
                    self.overlay_scroll = self.overlay_scroll.saturating_add(3).min(4096)
                }
                MouseEventKind::Down(MouseButton::Left)
                    if self.overlay == Some(Overlay::Interfaces)
                        && self
                            .areas
                            .overlay
                            .contains((mouse.column, mouse.row).into()) =>
                {
                    let row = usize::from(
                        mouse
                            .row
                            .saturating_sub(self.areas.overlay.y)
                            .saturating_sub(1),
                    );
                    self.interface_index =
                        (self.overlay_scroll + row).min(self.interfaces.len().saturating_sub(1));
                }
                _ => {}
            }
            return;
        }
        let point = (mouse.column, mouse.row).into();
        let pane = if self.areas.packets.contains(point) {
            Some(Pane::Packets)
        } else if self.areas.layers.contains(point) {
            Some(Pane::Layers)
        } else if self.areas.explain.contains(point) {
            Some(Pane::Explain)
        } else if self.areas.bytes.contains(point) {
            Some(Pane::Bytes)
        } else {
            None
        };
        if self.areas.tabs.contains(point) {
            self.focus = Pane::Packets;
        }
        if let Some(pane) = pane {
            self.focus = pane;
            match mouse.kind {
                MouseEventKind::ScrollUp => self.move_cursor(-3),
                MouseEventKind::ScrollDown => self.move_cursor(3),
                MouseEventKind::Down(MouseButton::Left) => self.click(pane, mouse.row),
                _ => {}
            }
        }
    }
    fn click(&mut self, pane: Pane, row: u16) {
        match pane {
            Pane::Packets => {
                let y = row.saturating_sub(self.areas.packets.y).saturating_sub(2);
                self.following = false;
                self.select_index(self.packet_scroll + usize::from(y));
            }
            Pane::Layers => {
                self.tree_selected = (self.tree_scroll
                    + usize::from(row.saturating_sub(self.areas.layers.y).saturating_sub(1)))
                .min(self.tree.len().saturating_sub(1));
                self.reveal_bytes();
            }
            _ => {}
        }
    }
    fn key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        if self.filter_edit.is_some() {
            self.edit_key(key);
            return;
        }
        if self.overlay.is_some() {
            self.overlay_key(key);
            return;
        }
        if self.navigation(key) {
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => {
                self.overlay = Some(Overlay::Help);
                self.overlay_scroll = 0;
            }
            KeyCode::Char('g') => {
                self.overlay = Some(Overlay::Glossary);
                self.overlay_scroll = 0;
                self.glossary_search.clear();
            }
            KeyCode::Char('i') if self.live => {
                self.overlay = Some(Overlay::Interfaces);
                self.overlay_scroll = 0;
                self.request_interfaces = true;
            }
            KeyCode::Char('/') => {
                self.filter_edit = Some(self.store.filter_text().to_owned());
                self.filter_error = None;
            }
            KeyCode::Char('c') | KeyCode::Esc => {
                self.apply_filter(String::new(), filter::Filter::default());
            }
            KeyCode::Char('f') => {
                if let Some(entry) = self.selected.and_then(|id| self.store.get(id))
                    && let Some(f) = filter::Filter::conversation(&entry.summary)
                {
                    let input = words::conversation(&entry.summary);
                    self.apply_filter(input, f);
                }
            }
            KeyCode::Char('t') => self.clock_time = !self.clock_time,
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                self.following = !self.paused;
            }
            _ => {}
        }
    }
    fn navigation(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                let reverse =
                    key.code == KeyCode::BackTab || key.modifiers.contains(KeyModifiers::SHIFT);
                if self.single_detail {
                    // Hidden panes cannot receive useful navigation. Tab rotates
                    // the three visible detail choices; 1 returns to the list.
                    let panes = [Pane::Layers, Pane::Explain, Pane::Bytes];
                    let current = if self.focus == Pane::Packets {
                        self.detail
                    } else {
                        self.focus
                    };
                    let index = panes.iter().position(|p| *p == current).unwrap_or(0);
                    self.detail = panes[(index + if reverse { 2 } else { 1 }) % 3];
                    self.focus = self.detail;
                } else {
                    let panes = [Pane::Packets, Pane::Layers, Pane::Explain, Pane::Bytes];
                    let index = panes.iter().position(|p| *p == self.focus).unwrap_or(0);
                    self.focus = panes[(index + if reverse { 3 } else { 1 }) % 4];
                }
            }
            KeyCode::Char('1') => self.focus = Pane::Packets,
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::PageUp => self.move_cursor(-(self.page() as isize)),
            KeyCode::PageDown => self.move_cursor(self.page() as isize),
            KeyCode::Home => self.move_cursor(-isize::MAX),
            KeyCode::End => {
                self.move_cursor(isize::MAX);
                if self.focus == Pane::Packets {
                    self.following = true;
                    self.paused = false;
                }
            }
            KeyCode::Left if self.focus == Pane::Layers => self.expand(Some(false)),
            KeyCode::Right if self.focus == Pane::Layers => self.expand(Some(true)),
            KeyCode::Enter => {
                if self.focus == Pane::Layers {
                    self.expand(None);
                } else if self.focus == Pane::Packets {
                    self.focus = Pane::Layers;
                }
            }
            _ => return false,
        }
        true
    }
}
