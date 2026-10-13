**1. Built** — Production excludes mock code and fixtures. Total JavaScript is **467,668 bytes**; `app.js` is **360,950 bytes**. Mock support remains in development and `build:mock`, which writes to `dist-mock/`. Production `?mock` displays “Mock mode is not included in this build.”

Updated tests, stale fixture wording and [README](web/README.md).

**Direct evidence:** the original chunk audit reported:

```text
assets/mock.js 962546 bytes
src/mocks/details.json 989674
```

The second value is before minification. Complete packet field trees dominate the chunk; no accidental package inclusion was found. The final graph audit reported:

```text
production NODE_ENV=production mock_modules=0
production NODE_ENV=development mock_modules=0
mock NODE_ENV=production mock_modules=10
```

**2. Acceptance results** — All passed. Commands ran directly inside `web/`.

| Command | Result / output excerpt |
|---|---|
| `node node_modules/prettier/bin/prettier.cjs --check .` | Pass: `All matched files use Prettier code style!` |
| `node_modules/.bin/oxlint` | Pass, exit 0; six existing warnings |
| `node node_modules/typescript/bin/tsc -b` | Pass; no TypeScript diagnostics |
| `node node_modules/vitest/vitest.mjs run --maxWorkers=4` | Pass: `Test Files  13 passed (13)`; `Tests  100 passed (100)` |
| `node node_modules/vite/bin/vite.js build` | Pass: `✓ built in 1.13s` |
| `ls -l dist/assets/` | Pass; no mock file, stable names |

JavaScript entries from the listing:

```text
-rw-r--r--. 1 user user  19745 Oct 13 18:08 FilterHelp.js
-rw-r--r--. 1 user user 360950 Oct 13 18:08 app.js
-rw-r--r--. 1 user user  86973 Oct 13 18:08 button.js
```

`vite build --mode mock` also passed: `✓ built in 1.25s`. Its `mock.js` is **962,107 bytes**. `client.js` and `labels.js` retain stable names there; production folds them into the remaining chunks.

Root gates passed:

- `cargo fmt --check`: no formatter output.
- `cargo clippy --offline --all-targets -- -D warnings`: `Finished … target(s) in 4.67s`.
- `cargo test --offline`: 229 tests passed. [Full output](web/.build/cargo-test.log).
- `cargo build --release --offline`: `Finished … target(s) in 11.79s`.
- Required Rust file-size command: no output.

Web line-length and file-size checks also printed nothing. Release binary: **1,964,728 bytes**. Rust files created or changed: **None**, so Rust line counts are not applicable.

**3. Public interface** — Existing [startup function](web/src/api/bootstrap.ts) now permits a null API:

```ts
export declare function createPageApi(
  token: string | null,
  search: string,
  forceMock?: boolean,
): Promise<{ api: NetmonApi | null; mock: boolean }>
```

Null means mock support is unavailable. No new public types or Rust interfaces.

**4. Deviations** — None.

**5. Needed elsewhere** — None.

**6. Not verified** — **Indirect evidence:** jsdom checks message rendering. **No evidence found:** real-browser rendering, CSP enforcement or development-server runtime behavior. Logical fallacy check: passing tests does not establish those behaviors. No dev server, watcher or prohibited package command ran.

**7. Suggested guide updates** — Document `build:mock` and add the four-worker cap to the web guide’s Vitest example.

**8. Questions** — None.