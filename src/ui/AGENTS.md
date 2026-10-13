# Screens — area guide

Applies to everything in `src/ui/`. Read the root `AGENTS.md` first. `PLAN.md` section 6 shows the
intended screens.

## Shape of the code

- **State and logic are separate from the terminal.** An `App` value holds all state. It has
  `on_event(event)`, `on_tick()` and `draw(frame)`. Nothing in `App` reads the keyboard or touches the
  real terminal, so tests can drive it with made-up events and draw it into ratatui's `TestBackend`.
- **One thread owns all state.** Capture, process lookup and file loading run on their own threads and
  send results over channels. The main loop drains them with a time budget, then draws.
- **The loop must never block.** No file or `/proc` reads, no child-process waits, no unbounded work
  in `on_event`, `on_tick` or `draw`. Work that scales with the number of packets is done in bounded
  slices across ticks.
- **Draw only what is visible.** Lists hold their scroll position and render just the rows on screen.
  Drawing must cost the same with 200 packets as with 200,000.

## Rules for this area

- **The terminal is always restored**: on `q`, on Ctrl-C, on an error, and on a panic (install the
  hook before entering the alternate screen; the release build uses `panic = "abort"`, and the hook
  still runs).
- **Wording comes from `src/explain/ui.rs`**: labels, help, hints. Screen code arranges text; it does
  not write sentences.
- **Colour comes from one theme module.** Never rely on colour alone; anything shown by colour is also
  shown by a word or a symbol.
- **Every action has a key.** The mouse is an extra, never the only way.
- **Layouts adapt.** Wide is 120 columns or more, medium is 80 to 119, narrow is under 80. Nothing may
  overlap or be cut mid-word at 80x24. Below 60x15 show a short "terminal too small" message.
- Text on screen is already sanitised by the decoders. Text from other sources must be sanitised first.
- Long text wraps inside its pane. Wide characters and long IPv6 addresses must not break alignment.

## Tests

- Render each screen with `TestBackend` at 140x40, 100x30 and 80x24, loaded from a fixture file, and
  compare the text with golden files in `tests/golden/`.
- Drive `App` with key and mouse events and assert on state: selection, scroll, filter, open overlay.
- Never start the real terminal or `dumpcap` in a test.
