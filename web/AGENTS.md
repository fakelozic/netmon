# Web page — area guide

Applies to everything in `web/`: the page that `netmon web` serves. Read the root `AGENTS.md` first,
then `docs/web-api.md`, which is the contract with the server.

## Stack (chosen by the owner)

Vite 8, React 19 with **React Compiler**, TypeScript, Tailwind CSS 4, shadcn/ui (Radix, "nova" preset),
lucide icons, `@tanstack/react-virtual`. Tests: Vitest with Testing Library and jsdom. Package manager: **nub**.

```sh
nub install            # after a fresh checkout
nub run dev            # dev server with hot reload
nub run build          # type-check, then bundle into web/dist
nub run lint           # oxlint
nub run format         # Prettier
nub exec vitest run    # tests
```

- **No new packages.** The sandbox has no network. Use what is in `package.json`. If something is
  truly missing, say so under "Needed elsewhere" in your report.
- **Never run `nub dlx`, `npx` or `npm`.** `nub dlx create-vite` spawns processes without end on this
  machine. Everything needed is already installed.
- This machine has 16 GB of RAM and is the owner's desktop. Do not start watchers or dev servers.

## Rules

- **React Compiler does the memoising.** Do not write `React.memo`, `useMemo` or `useCallback`. Write
  plain components and plain functions, and follow the Rules of React so the compiler can optimise
  them: no mutation of props or state, no side effects during render, hooks at the top level.
- **Untrusted text.** Every string from the API may contain text chosen by a stranger on the network.
  Render it as React children only. Never `dangerouslySetInnerHTML`, never `innerHTML`, never `eval`.
  Never build a URL, a class name or a style from API text.
- **The page must run under the content policy in `docs/web-api.md`**: scripts and fonts from this
  origin only, nothing remote, no inline `<script>`.
- **shadcn/ui components live in `src/components/ui/` and are vendored.** Use them; do not restyle or
  rewrite them. Change one only when a build error forces it, and say so in your report.
- **Formatted, readable code.** Prettier formats everything (`nub run format`; `printWidth` 100).
  No line over 120 characters. One JSX element per line where Prettier puts it. No nested ternaries
  in JSX: use a small named function or component. Never shorten a file by lengthening its lines;
  the owner reads this code to learn.
- **Small modules.** No file over 500 lines; a component file over about 250 should be split. One
  component per file. API calls in `src/api/`, each view in `src/views/<name>/`, shared hooks in
  `src/hooks/`, pure helpers in `src/lib/`.
- **Logic is kept out of components** where it can be: formatting, hex layout, range-to-byte mapping,
  polling state and reducers are plain functions with unit tests.
- **Types come from the contract.** One file, `src/api/types.ts`, mirrors `docs/web-api.md` exactly.
- **Keyboard first, mouse welcome.** Every action reachable by keyboard; visible focus; lists handle
  arrows, PageUp, PageDown, Home and End.
- **Readable by default.** Light and dark themes. Nothing shown by colour alone. Respect
  `prefers-reduced-motion`.
- **Fast with many packets.** The packet list is virtualised and keeps at most 5,000 rows in memory.
- **A small bundle.** The built script is embedded in the netmon binary. Keep `assets/app.js` under
  450 kB; mock data loads separately and only in mock mode; import only what is used.
- **State in the URL.** The tab, the selection and the filter are hash routes, so links, reload and
  the back button work.
- **An application layout.** The page fills the window and never scrolls as a document; panes scroll.
- **Wording comes from the server.** Explanations, sentences and glossary text arrive in the API. The
  page holds only its own labels, together in `src/lib/labels.ts`.
- Comments follow the root guide: a header on every file, a doc comment on every exported function
  and component, and a "why" comment wherever a choice is not obvious.

## Tests

`nub exec vitest run` must pass with no network. Cover the pure modules and the main components with
mock data. Include hostile strings (`<img src=x onerror=1>`, `"><script>alert(1)</script>`, very long
names) and assert they appear as plain text.
