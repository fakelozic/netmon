# Fix 1 for task 11 — layout, URL state, readable code, bundle size

Read `web/AGENTS.md` again first: it has new rules on formatting and line length. Then
`docs/web-api.md` (one addition: `hidden` byte ranges) and your own `tasks/11-web-page.report.md`.

The page was opened in a real browser (headless Firefox, mock data, 1400x900 and 1400x2000). It
renders and works. These are the problems that were seen, and one that was found in the code.

## 1. Layout: an application that fills the window, not a long page

**Seen:** the detail pane sits beside the table and covers its last column, so "What is happening",
the most important column, is invisible. The page scrolls as one long document: with all layers open,
the Bytes view is about 1,600 pixels below the fields, so a field and its bytes are never on screen
together. That link is the main teaching device.

**Required:**

- The page fills the viewport exactly. The document itself never scrolls; panes scroll inside.
- A compact header in **one row**, at most 56 pixels tall: name, one state badge, the source, the
  counts, the rate, and the buttons. Today it shows "Live" twice and takes about 130 pixels.
- **Packets tab**: the packet list on top, across the full width; the detail below it; a draggable
  divider between them (`ResizablePanelGroup`). The list starts at about 45% of the height.
- **Column order**: No, Time, From, To, App, Proto, **What is happening**, Bytes. "What is happening"
  takes all the remaining width. It is never hidden: as the window narrows, drop Bytes, then App, then
  shorten Time to three decimals.
- **Detail**: three panes side by side, each scrolling on its own: Layers, Explain, Bytes. All three
  are visible at once at 1280 pixels wide and above. Below 1024 pixels they become three tabs.
- **Layers** open with only the highest layer expanded.
- **Explain** is never empty: with no field selected it shows the packet's sentence, the highest
  layer's "about" text, and a one-line hint. Selecting a layer heading shows that layer's "about" text.
- **Bytes**: hex and ASCII both fully visible with no clipping (the ASCII column is cut off today).
  Selecting a field scrolls its bytes into view and highlights them in both columns.
- Connections tab: the table on the left, the story on the right, each scrolling on its own.

## 2. State in the URL

**Seen:** the tab and the selection live only in memory. There are no deep links, the back button
does nothing, and the other tabs could not be opened for a screenshot.

**Required:** hash routes, kept in step with the page in both directions:
`#/packets`, `#/packets/<number>`, `#/connections`, `#/connections/<id>`, `#/alerts`, `#/glossary`,
`#/glossary/<term>`. Back and forward work. An unknown route goes to `#/packets`.

- The token still arrives once as `#k=<token>`. Read it, keep it in `sessionStorage` (so a reload
  works; it is gone when the tab closes), and replace the fragment with `#/packets`.
- Mock mode: `?mock` replays packets a few at a time as now; `?mock=all` delivers everything at once,
  for tests and screenshots.
- A filter is part of the URL too: `#/packets?filter=dns`.

## 3. Hidden bytes

`docs/web-api.md` now says `/api/packet/N` may carry `"hidden": [[start, end], …]`: byte ranges that
held a secret (a password or cookie). The server sends zeros there. Show those bytes as `**` in hex and
`*` in ASCII, with a tooltip saying a secret was hidden. Add the field to the types and one mock packet.

## 4. Code a person can read

**Found:** 159 lines are longer than 120 characters and the longest is 447. Whole components are
written as single lines of JSX. The owner reads this code to learn; this is unreadable.

**Required:**

- Prettier is installed. Add `.prettierrc.json` (`printWidth` 100, single quotes, no semicolons to
  match the existing code), a `.prettierignore` for `dist` and `src/components/ui`, and scripts
  `format` (`prettier --write .`) and `format:check` (`prettier --check .`). Format everything.
- After formatting, no line in `src` outside `src/components/ui` is over 120 characters.
- One JSX element per line where Prettier puts it. No nested ternaries in JSX: use a small function
  or component with a name that says what it decides.
- Formatting will make files longer. Split any component file over about 250 lines.
- Remove `API-INTERFACE.md`, `PAGE-INTERFACE.md` and `REPORT.md` from `web/`; put what is useful for
  a developer into `web/README.md` (how to run, how mock mode works, where things live).

## 5. Bundle size

**Seen:** `dist/assets/app.js` is 1,430 kB (239 kB gzipped). The starter template built to 224 kB.
netmon embeds this file, and a small binary is a project goal.

**Required:** find out what the extra megabyte is, and report it. Then:

- The mock data and mock code are not in the main bundle. Load them with a dynamic `import()` only
  when the URL asks for mock mode, as a separate file with a stable name (`assets/mock.js`).
- Import only what is used from large packages.
- Target: `assets/app.js` at most 450 kB. If that cannot be met, say exactly why and what the
  remaining weight is.

## 6. Tests

Update the tests for the new layout, and add:

- every row's sentence is present in the table, under a "What is happening" header
- routes: each hash route shows the right tab and selection; changing tab or selection updates the
  hash; back restores the previous state; the token is moved to `sessionStorage` and removed from the URL
- `?mock=all` delivers all 75 packets at once
- hidden ranges render as `**`
- with no field selected, the Explain pane shows the packet's sentence

## 7. Acceptance commands (run inside `web/`)

Call the tools directly; `nub run` works too, but these are what will be used to check your work.

```sh
node node_modules/prettier/bin/prettier.cjs --check .
node_modules/.bin/oxlint
node node_modules/typescript/bin/tsc -b
node node_modules/vitest/vitest.mjs run --maxWorkers=4
node node_modules/vite/bin/vite.js build
ls -l dist/assets/
find src \( -name '*.ts' -o -name '*.tsx' \) -not -path 'src/components/ui/*' | xargs awk 'length($0) > 120 {print FILENAME": "FNR": "length($0)}'
find src \( -name '*.ts' -o -name '*.tsx' \) -not -path 'src/components/ui/*' | xargs wc -l | awk '$2 != "total" && $1 > 500'
```

The last two commands must print nothing, and `app.js` must meet the size target.
You still cannot open a browser. The page will be opened again after your report, on every route.
