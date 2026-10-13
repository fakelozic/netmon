# Task 14 — keep mock data out of the shipped page

Read `AGENTS.md`, `web/AGENTS.md` and `tasks/11-web-page.fix-1.report.md`. Work only in `web/`.

The production build writes `dist/assets/mock.js` (about 960 kB). netmon embeds everything in
`web/dist`, so the binary carries a megabyte of development data.

1. Find out why the mock chunk is that large and say so in the report. Shrink it if something is
   included by accident.
2. Make the production build (`vite build`) leave mock code and data out entirely. Mock mode stays
   available in `vite dev` and in a separate `build:mock` script that writes to `dist-mock/`.
   In a production build, a URL with `?mock` shows a short message that mock mode is not included.
3. Check the other chunks (`button.js`, `FilterHelp.js`, `client.js`, `labels.js`): the server serves
   any file under `assets/`, so several chunks are fine, but their names must stay stable (no hashes).
4. Update the tests and `web/README.md`.

Acceptance, inside `web/`, calling the tools directly as in the fix brief: Prettier check, oxlint,
`tsc -b`, Vitest, `vite build`, then `ls -l dist/assets/`: no mock file, total JavaScript under 500 kB.
