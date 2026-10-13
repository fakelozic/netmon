# netmon web page

The page follows [the API contract](../docs/web-api.md). Open the link printed by `netmon web`.
Startup transfers `#k=…` to `sessionStorage` under `netmon-token` and replaces it with `#/packets`.
Reloads retain the token and route; closing the browser tab ends its storage lifetime.
Every API request sends the token as `X-Netmon-Token`.

## Finite development commands

Run inside `web/`, using the installed tools. These commands start no watcher or dev server:

```sh
node node_modules/prettier/bin/prettier.cjs --write .
node node_modules/prettier/bin/prettier.cjs --check .
node_modules/.bin/oxlint
node node_modules/typescript/bin/tsc -b
node node_modules/vitest/vitest.mjs run --maxWorkers=4
node node_modules/vite/bin/vite.js build
node node_modules/vite/bin/vite.js build --mode mock
```

The corresponding nub scripts are `format`, `format:check`, `lint`, `typecheck`, `test`, `build` and
`build:mock`. Both build scripts type-check first. The production build writes `dist/`; `build:mock`
writes only `dist-mock/`, which netmon does not embed. Both output folders are ignored by Git and
Prettier. A production build clears stale output, including any mock chunk left by an older build.
Vitest is also capped at four workers in `vite.config.ts`. Dependencies are already installed.
Prettier uses 100 columns, single quotes and no semicolons. It excludes generated output, vendored
UI components and files outside this task's ownership.

## Mock mode and routes

Mock mode is available in Vite development and in the separate `build:mock` output. Append `?mock`
before the fragment to replay five packets per visible, running session poll.
`?mock=all` delivers all 75 packets immediately and marks the capture ended. `VITE_MOCK=1` enables
replay by default in those environments; `?mock=all` still selects the complete capture. The mock
build uses `vite build --mode mock`; it loads `assets/mock.js` only when replay is requested. Without
a mock request, development and mock builds use the real API.

Ordinary `vite build` removes the dynamic mock import and its entire dependency graph. The config
defines `import.meta.env.NETMON_INCLUDE_MOCK` as the constant `'1'` only for Vite's `serve` command or
the explicit `mock` build mode, and `'0'` otherwise. This flag cannot be supplied through an env file;
even an inherited `NODE_ENV=development` cannot include mocks in an ordinary build. Neither mock
code nor fixture JSON is emitted under `dist/`. A production URL with `?mock` or `?mock=all` displays:

```text
Mock mode is not included in this build.
```

That startup sends no API requests. `VITE_MOCK=1` cannot include mock support in a production build;
use `build:mock` for an output that supports replay.

The supported routes are:

```text
#/packets
#/packets/17
#/packets?filter=dns
#/connections
#/connections/7
#/alerts
#/glossary
#/glossary/window%20scale
```

Selections and filter submissions push history entries. Back, Forward and manually changed hashes
update the page. Unknown routes become `#/packets`. Story jumps additionally retain a local
conversation restriction, for example `#/packets/18?flow=7`. This query restricts rows by their
contract `flow` field; it is never sent as an invented server filter word.

Mock files contain 75 packet details, 12 stories, five separate alert examples and 53 definitions.
Networking wording is copied verbatim from reviewed goldens and Rust explanation sources. The alerts
are separate synthetic scenarios, not observations from the loopback recording. Packet 32 includes
one synthetic hidden range, `[128, 132)`, over otherwise harmless fixture bytes to demonstrate the
redaction contract. Those bytes are zeroed. No secret was observed in this fixture. Mock exports
return a labelled example path and write no file.

To regenerate fixtures after engine wording changes, build Rust offline at the repository root,
run `python3 web/scripts/generate-mocks.py`, then format the JSON using the finite command above.
The generator preserves the synthetic range and redacts fields marked `[hidden]` before writing hex.

## Where things live

- `src/main.tsx` consumes the token and renders one API instance.
- `src/api/` contains contract types, real transport, startup selection and dynamically loaded mocks.
- `src/hooks/` handles polling, selected-detail requests, media queries and route subscriptions.
- `src/lib/` holds labels and pure formatting, route, glossary and byte helpers.
- `src/views/packets/` contains the full-width virtual list above resizable packet detail panes.
- `src/views/connections/` keeps the table beside its independently scrolling conversation story.
- `src/views/alerts/` and `src/views/glossary/` show literal server-authored texts.
- `src/components/ui/` is vendored shadcn; it remains unchanged.
- `build/classes.ts` fits the installed cn engine's tables to fixed source class names. Generated
  tables live in ignored `.build/`; Vite uses virtual modules, including in component tests.
- `src/test/` exercises views, routing, teaching interactions and hostile strings in jsdom.

The document stays inside the viewport. The header is one 56-pixel row. Packet list/detail start at
45%/55%; their divider supports the vendored resizer's pointer and keyboard controls. Layers, Explain
and Bytes scroll independently side by side from 1024 pixels, and become tabs below that width.
Only the highest layer starts expanded. The initial Explain pane shows the packet's sentence, the
highest layer's about text and a hint; layer headings select their about text.

The packet sentence occupies the flexible column before Bytes. Narrowing hides Bytes below 1200
pixels, App below 1024, and reduces Time to three decimals below 900. From and To remain present.
Hex and ASCII share the same highlight and byte selection. Selecting a field scrolls to its bytes.
Explicit `hidden` ranges show `**` and `*` with a tooltip; legacy `[hidden]` field ranges are also
masked. Strings from the API remain React children. Scripts and fonts load from this origin.

## Bundle measurements

The finite audit of the previous production mock chunk emitted:

```text
assets/mock.js 962546 bytes
src/lib/mock-filter.ts 2826
src/lib/mock-flow.ts 1597
src/mocks/session.json 599
src/mocks/packets.json 26503
src/mocks/details.json 989674
src/mocks/flows.json 18115
src/mocks/alerts.json 4424
src/mocks/glossary.json 10254
src/api/mock-data.ts 1742
src/api/mock.ts 3520
```

The module values are rendered lengths **before minification**, not separate minified package
sizes. This is direct evidence that the 75 complete packet details dominate the chunk. The source
contains 266 layers and 3,132 fields, including repeated explanatory sentences and captured hex.
The audit contains only the intended fixtures and replay helpers; no accidental package inclusion
was found. The separate mock build retains those complete details and verbatim wording.

Every entry and chunk keeps a stable name: `assets/app.js` and `assets/[name].js`, without hashes.
Production currently emits `app.js`, `button.js` and `FilterHelp.js`; the mock build also emits
`mock.js`, `client.js` and `labels.js`. Removing the mock dependency graph lets the bundler fold
client and label code into the remaining production chunks. The server must serve every generated
file under `assets/`. CSS remains `assets/app.css`, and fonts retain their source names.

The main script target is 450,000 bytes; total production JavaScript must be under 500,000 bytes.
Measure all `.js` files, not just the entry script. The large-chunk warning is confined to the mock
build's deliberately complete dataset. Filter help dynamically loads its popover and focus code.
The cn engine uses project-fitted conflict tables. No dependency or vendored component changed.

## Integration declarations

No Rust public interface was added. Existing transport and `App` entry points remain:

```ts
export declare function readToken(location?: Location, history?: History): string | null
export declare function createClient(token?: string | null, fetcher?: typeof fetch): NetmonApi
export declare function createMock(initialPackets?: number): NetmonApi
export default function App(props: { api: NetmonApi; mock?: boolean }): React.JSX.Element
```

New startup, route and media-query declarations:

```ts
export interface PageRoute {
  tab: 'packets' | 'connections' | 'alerts' | 'glossary'
  packet: number | null
  flow: number | null
  term: string | null
  filter: string
  scope: number | null
}
export declare function packetRoute(): PageRoute
export declare function parseRoute(hash: string): PageRoute
export declare function routeHash(route: PageRoute): string
export declare function useRoute(): {
  route: PageRoute
  navigate: (next: PageRoute) => void
}
export declare function useMediaQuery(query: string): boolean
export declare function createPageApi(
  token: string | null,
  search: string,
  forceMock?: boolean,
): Promise<{ api: NetmonApi | null; mock: boolean }>
export declare function classTables(): import('vite').Plugin
```

`createPageApi` returns a null API when replay was requested in production. The entry point then
shows the unavailable message instead of rendering `App` or polling. A forced mock request cannot
bypass the build boundary. Real startup still constructs transport without immediately fetching.

`PacketDetail` adds `hidden?: ByteRange[]`. Omission means no explicit hidden ranges. `useMonitor`
accepts an optional fifth parameter, `selected: number | null = null`, to fetch a selection outside
its bounded page without changing the list cursor on ordinary row selection.

New view helpers have these exact callable shapes (all type names come from `src/api/types.ts`):

```ts
export declare function ConnectionTable(props: {
  flows: Flow[]
  selected: number | null
  select: (id: number) => void
}): React.JSX.Element
export declare function LayersPane(props: {
  layers: Layer[]
  selected: Field | null
  select: (field: Field) => void
  hover: (field: Field | null) => void
  expanded: Record<number, boolean>
  expand: (index: number, open: boolean) => void
  openFields: ReadonlySet<Field>
  toggleField: (field: Field, open: boolean) => void
  selectLayer: (layer: Layer) => void
}): React.JSX.Element
export default function FilterHelp(): React.JSX.Element
```

`ExplainPane` now takes `field`, `layer`, `packet` and `terms`; `GlossaryView` additionally accepts
optional `selected` and `select`. These are internal page components, not HTTP contract changes.

## Evidence limits

Direct evidence comes from finite builds, type checking, tests and file measurements. jsdom gives
indirect evidence for browser layout and native scrolling. No evidence found from a real browser
for viewport fit, dragging, font rendering, CSP enforcement or sustained traffic performance in this
run. Real Rust-server recording/export and page embedding also require integration review.
Passing mock tests does not prove those untested behaviours; synthetic alerts and redaction remain
explicitly identified, avoiding an inference that they were observed in the fixture.
