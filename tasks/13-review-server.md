# Task 13 — review the server side as a second pair of eyes, and fix what you find

Nobody has reviewed the web API, the `netmon web` command, the hidden-bytes change or the README.
Read `AGENTS.md`, `docs/web-api.md`, and the reports `tasks/12a-…`, `tasks/12b-…` and `tasks/12c-…`.
Write your own plan. Do not touch `web/` (another agent is working there).

Review, as a careful colleague who did not write it:

1. **Contract.** Compare every endpoint's actual JSON with `docs/web-api.md`, field by field: names,
   types, `null` versus missing, units, paging, error shapes. Fix mismatches in the code (the contract wins).
2. **Safety.** Trace every path by which a secret (password, cookie, authorization value) could reach
   an API reply, a log file or the terminal. Trace every place text from packets or `/proc` reaches
   JSON, Markdown or the screen and confirm it is sanitised and escaped. Fix what is not.
3. **Robustness.** Unbounded memory, loops driven by untrusted input, panics on bad input, the engine
   thread blocking on a slow client, a `dumpcap` child left running on any exit path.
4. **The command.** `netmon web --help` and its error messages are clear; every option in the contract works.
5. **README.** Every command and fact in it is true for the code as it is.
6. **Rules in `AGENTS.md`.** File size, comments, no `unsafe` outside `src/sys.rs`, dependencies unchanged.

Fix real problems with tests that would have caught them. Do not refactor for taste. Run the quality
gates. In the report, list each finding as: what, where, how serious, fixed or not, and why.
