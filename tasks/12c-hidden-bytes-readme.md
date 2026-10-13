# Task 12c — hidden bytes in the API, a build script, and the README

Read `AGENTS.md`, `docs/web-api.md` and `tasks/12b-web-api.report.md`. Write your own plan.

1. **Hidden bytes.** `docs/web-api.md` says `/api/packet/N` returns `"hidden": [[start, end], …]` for
   byte ranges that held a secret (masked HTTP header values such as `Authorization` and cookies), and
   that `hex` has zeros there. Implement it in the web API, with tests, so a secret never leaves netmon.
2. **Build script.** `tools/build.sh`: builds the web page (`cd web && nub install && nub run build`),
   then `cargo build --release --offline`, and prints the binary's path and size. Plain `sh`, stops on
   the first error. Do not run it in the sandbox (no network); check it with `sh -n`.
3. **README.md** at the repository root, for a newcomer: what netmon is, what it needs (`dumpcap`, the
   `wireshark` group, Rust, `nub` for the page), how to build, how to run each mode (`netmon`,
   `netmon -r`, `netmon web`, `netmon explain`, `netmon glossary`), what the logs are and where they
   go, the safety model of `netmon web` in a few lines, and a map of the source folders. Take facts
   from the code and `--help`, not from memory. Plain English, short.

Do not touch `web/` or `src/ui/`. Run the quality gates in `AGENTS.md` and end with the usual report.
