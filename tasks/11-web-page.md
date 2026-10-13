# Task 11 — the web page

Read the root `AGENTS.md`, then `web/AGENTS.md` and `docs/web-api.md` in full. `PLAN.md` sections 5, 6
and 8 describe what netmon is for and what the views should show.

## Goal

The page that `netmon web` serves: a graphical view of the traffic for someone learning networking.
It must make three things easy: seeing what is happening now, opening one packet and understanding
every field, and following one conversation from start to finish.

Another agent builds the Rust server at the same time, against the same contract. The server does not
exist yet, so **the page must also run entirely on mock data**.

## What already exists in `web/`

A Vite + React + TypeScript project with Tailwind 4, React Compiler, 19 shadcn/ui components in
`src/components/ui/`, and all packages installed. `nub run build` works. `src/App.tsx`, `src/App.css`
and `src/assets/` are the starter template's demo: replace them.

**You own:** everything in `web/` except `web/AGENTS.md`, `package.json`'s dependency lists,
`nub.lock` and `src/components/ui/`. You may change `vite.config.ts`, the `tsconfig` files and
`package.json`'s `scripts`. Do not touch anything outside `web/`.

## 1. Project setup

- `vite.config.ts`: keep the three plugins. Add: `server.proxy` sending `/api` to
  `http://127.0.0.1:7979`; `build.modulePreload.polyfill = false` (no inline script);
  stable output names with no hashes (`assets/app.js`, `assets/app.css`, fonts and other assets under
  `assets/` with their own names), because the server embeds the files by name; Vitest configured for
  jsdom with a setup file.
- `package.json` scripts: add `test` (`vitest run`) and `typecheck` (`tsc -b`).
- `index.html`: title `netmon`, no inline script or style, a `<noscript>` line.

## 2. Talking to the server (`src/api/`)

- `types.ts`: TypeScript types for every object in `docs/web-api.md`, field for field.
- `client.ts`: reads the token from the URL fragment (`#k=<token>`), keeps it in memory only, removes
  it from the address bar with `history.replaceState`, and sends it as `X-Netmon-Token` on every
  request. Turns error replies into a typed error with the server's sentence. No token: the page shows
  a clear "open the link netmon printed" message instead of failing silently.
- `mock.ts` and `src/mocks/*.json`: a complete stand-in for the API used when `VITE_MOCK=1` or the URL
  has `?mock`. Base the data on the real fixture: the 75 packets in `tests/golden/loopback-list.txt`
  and `flows-loopback-list.txt`, the full field trees in `tests/golden/packet-*.txt`, the stories in
  `flows-loopback-stories.txt`, the alerts in `alerts-examples.txt`, and the glossary from
  `src/explain/glossary.rs`. In mock mode, packets arrive a few at a time so the live behaviour can be seen.
- Polling as the contract describes: every 500 ms while visible and running; stop when hidden or
  ended; back off after three failures.

## 3. The page

One page with a header and four tabs. Use the shadcn/ui components.

**Header.** Source and mode; a state badge (live, paused, ended, failed, with the error); packets,
conversations and alerts counts; a small bytes-per-second chart from `rate` (live only); buttons for
pause/resume and record; a light/dark switch. A logging problem from the session shows as a warning.

**Packets tab.**
- A filter box. It sends the text to the server and shows `filter_error` under the box, pointing at
  the position, without clearing what was typed. A small help popover lists the filter words.
- A virtualised table: No, Time, From, To, App, Proto, Bytes, What is happening. From and To show the
  label, with the address on hover. Protocol as a small coloured badge. Problem rows carry a mark and a
  colour. One row per packet, never wrapped; the sentence is cut with an ellipsis and shown in full in
  the detail pane.
- "Follow" keeps the newest packet in view while live; scrolling up turns it off, and a button brings
  it back. A saved capture opens at the top.
- A resizable detail pane for the selected packet, in three parts:
  - **Layers**: each layer as a collapsible section with its one-line summary and its "about" text;
    fields as a tree with label and value.
  - **Explain**: for the selected field, its label and the What, Here and Why text. Empty parts are
    not shown.
  - **Bytes**: the packet in hex and ASCII, sixteen per row with offsets. Hovering or selecting a
    field highlights its byte range in both columns. Clicking a byte selects the deepest field that
    contains it. This link between field and bytes is the main teaching device: make it obvious.
- A link from a packet to its conversation.

**Connections tab.**
- A table of conversations: app, remote name, protocol, status, duration, bytes up and down,
  problems. Sortable by recent, bytes and problems.
- Selecting one shows its **story** as a ladder diagram: two vertical lines labelled with the two
  sides, an arrow per step in the right direction, the step's text beside it, the time since the start
  and how long the step took. Steps with problems are marked. Clicking a step opens the Packets tab
  filtered to that conversation at that step's first packet.
- A button exports the story (`export_story`) and shows where the file was written.

**Alerts tab.** One card per alert, newest first: severity, title, time, then Seen, Why and Next, and a
link to the packet that triggered it. An empty state that says what netmon watches for.

**Glossary tab.** A searchable list of terms. Also, wherever explanation text appears (Explain pane,
"about" text, alert text), words that are glossary terms get a dotted underline and a tooltip with
the definition. Match whole words only, build the result as React nodes, never as HTML.

**Throughout.** Empty states that tell a beginner what to do next. Loading skeletons. Light and dark
themes. Works from 1024 pixels wide upward; below that the detail pane stacks under the list.

## 4. Tests (Vitest)

1. `client`: token read from the fragment and removed from the URL; header sent; missing token;
   error replies; malformed JSON.
2. Polling: starts, stops when hidden, stops when ended, backs off after three failures, resumes.
3. Pure helpers: time, byte and duration formatting; hex rows; which bytes a range covers; which field
   is deepest at a byte; the glossary word splitter, including hostile strings.
4. Types: every mock file satisfies the types in `types.ts` (a test that imports them typed).
5. Components with mock data: the table renders rows; selecting a row shows its layers; selecting a
   field shows What/Here/Why and highlights the right bytes; a filter error is shown; the story
   renders every step in order with the right direction; an alert card shows its three texts; the
   glossary filters.
6. Safety: a row, a field value, a server name and an alert title containing
   `<img src=x onerror=1>` and `"><script>alert(1)</script>` render as visible text, and no `img` or
   `script` element appears in the document.

## 5. Acceptance commands (run inside `web/`)

```sh
nub run lint
nub run typecheck
nub run test
nub run build
find dist -type f | sort
grep -c "<script" dist/index.html
find src -name '*.ts' -o -name '*.tsx' | grep -v 'src/components/ui/' | xargs wc -l | awk '$2 != "total" && $1 > 500'
grep -rnE "useMemo|useCallback|React\.memo|dangerouslySetInnerHTML|innerHTML" src --include=*.ts --include=*.tsx | grep -v 'src/components/ui/'
```

Expected: lint, typecheck, tests and build pass; `dist` holds `index.html`, `assets/app.js`,
`assets/app.css` and font files with stable names; the size check and the last `grep` print nothing.

You cannot open a browser in the sandbox. The page will be opened in a real browser after your
report, first in mock mode and then against the server. In the report, list every part of the page you
could not exercise through tests.
