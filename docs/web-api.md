# netmon web interface: the contract between the server and the page

`netmon web` serves a single page on this computer and a small JSON API that the page calls. Two agents
build the two halves at the same time, so this file is the contract. If something here is wrong or
missing, say so in your report; do not quietly invent a different shape.

## How it runs

```
netmon web [-i IFACE | -r FILE] [-f CAPTURE_FILTER] [--port N] [--no-open] [--log-dir DIR] [--record] [--no-log]
```

- Listens on `127.0.0.1` only. Default port 7979; if it is busy, the next free port up to 7999.
- Prints `netmon web: open http://127.0.0.1:7979/#k=<token>` and opens it with `xdg-open` unless `--no-open`.
- `Ctrl-C` stops capture, flushes logs and exits.

## Safety rules (this page shows the owner's network traffic)

| Rule | Why |
|---|---|
| Bind to `127.0.0.1` only; there is no option to listen elsewhere | Nobody else on the network can reach it |
| A random 128-bit token, made at start from `/dev/urandom`, shown in the URL fragment (`#k=…`) | The fragment is never sent to a server or kept in logs |
| Every `/api/` request must carry `X-Netmon-Token: <token>`; otherwise `401` | Another program or web page on this computer cannot read the data |
| The `Host` header must be `127.0.0.1:<port>` or `localhost:<port>`; otherwise `403` | Stops DNS-rebinding attacks |
| A request with an `Origin` header that is not this server's origin gets `403` | Stops other sites calling the API |
| No CORS headers are ever sent | Same reason |
| Every response carries `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` | Text from packets can never run as script or load anything remote. Inline styles are allowed because the UI components set them; scripts are not |
| Also `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` | Defence in depth |
| The page renders API text as React children only, never as HTML | Hostnames and headers come from strangers |
| Request line and headers at most 8 KB, body at most 4 KB, 5 s read timeout, at most 32 connections | A stuck or hostile client cannot tie up netmon |

Static files need no token: they contain no data. They are the Vite build output in `web/dist`,
embedded in the binary: `/` serves `index.html`, and `/assets/<name>` serves `assets/app.js`,
`assets/app.css` and the font files, each with the right `Content-Type`. Any other path is `404`.

## Responses

- JSON, UTF-8, `Content-Type: application/json`. Errors: `{"error": "plain sentence"}` with status
  400, 401, 403, 404 or 500.
- All text taken from packets or from `/proc` is already sanitised by the server (bytes outside
  printable ASCII appear as `\xNN`). The page still treats every string as untrusted.
- Numbers are plain JSON numbers. Times in seconds are since the first packet unless the name says otherwise.
- A field that does not apply is `null`, never missing.

## Endpoints

### `GET /api/session`

```json
{
  "version": "0.1.0",
  "mode": "live",
  "source": "enp5s0",
  "state": "running",
  "error": null,
  "started": "2026-10-13T11:02:11Z",
  "packets": 1284,
  "dropped": 0,
  "bytes": 912345,
  "conversations": 12,
  "alerts": 2,
  "rate": [0, 1200, 53000],
  "log_dir": "/home/user/.local/state/netmon/20261013-110211Z",
  "recording": "off",
  "problem": null
}
```

`mode`: `live` or `file`. `state`: `running`, `paused`, `ended` (a file was read to its end, or capture
stopped) or `failed` (then `error` says why). `rate`: bytes per second for up to the last 60 seconds,
oldest first. `recording`: `off`, `on`, `full` or `failed`. `log_dir` is `null` when logging is off.

### `GET /api/packets?after=N&limit=M&filter=TEXT`

Rows with a packet number greater than `after` that match the filter, in ascending order, at most
`limit` (default 200, maximum 500). `before=N` instead of `after` returns the `limit` rows just below
`N`, still ascending, for scrolling back. `filter` uses netmon's filter language; empty means all.

```json
{
  "total": 1284,
  "matched": 96,
  "filter_error": null,
  "rows": [
    {
      "no": 9,
      "time": 1.020843,
      "clock": "11:02:12.133",
      "src": "192.168.1.59:55921",
      "dst": "192.168.1.1:53",
      "src_label": "this computer:55921",
      "dst_label": "router:53",
      "app": "firefox",
      "proto": "DNS",
      "bytes": 94,
      "info": "Asks: what is the IPv4 address of example.com?",
      "problem": false,
      "alerts": 0,
      "flow": 5,
      "dir": "out"
    }
  ]
}
```

`filter_error`: `null`, or `{"position": 4, "message": "expected a port number after \"port\""}`; then
`rows` is empty. `src`/`dst` are addresses; `src_label`/`dst_label` use learned names. `app` and `flow`
may be `null`. `dir`: `out` (from this computer), `in`, or `null` when unknown.

### `GET /api/packet/N`

```json
{
  "no": 18,
  "time": 2.014515,
  "clock": "11:02:13.127",
  "info": "Accepts the connection (SYN+ACK) — handshake 2 of 3, 16 µs after the request",
  "wire_len": 74,
  "captured_len": 74,
  "truncated": false,
  "flow": 7,
  "hex": "00000000000000000000000008004500003c...",
  "layers": [
    {
      "proto": "TCP",
      "range": [34, 74],
      "line": "18080 → 51008 [ACK, SYN] seq=626081429 ack=1455604179 win=65483",
      "about": "TCP gives two programs a reliable, ordered stream of bytes on top of IP.",
      "fields": [
        {
          "label": "Flags",
          "value": "0x0012 [ACK, SYN]",
          "range": [46, 48],
          "what": "Tells the other computer whether to open or close a connection, confirm receipt, or handle data specially.",
          "here": "",
          "why": "",
          "children": [
            {"label": "SYN", "value": "1", "range": [47, 48], "what": "…", "here": "Set. …", "why": "", "children": []}
          ]
        }
      ]
    }
  ]
}
```

`hex` is the captured bytes as lowercase hex, at most 65,536 bytes. A `range` is `[start, end)` in
bytes within the packet. `404` if the packet is no longer in memory.

`hidden` (added 2026-10-13) is a list of `[start, end)` byte ranges that held a secret, such as an
HTTP `Authorization` value or a cookie: `"hidden": [[112, 140]]`, or `[]`. The server puts zeros in
`hex` for those bytes, so the secret never leaves netmon. The page shows them as `**`.

### `GET /api/flows?sort=recent|bytes|problems&limit=M`

```json
{
  "total": 12,
  "flows": [
    {
      "id": 7,
      "title": "firefox → github.com:443",
      "app": "firefox",
      "pid": 3688,
      "local": "192.168.1.59:58926",
      "remote": "20.207.73.82:443",
      "remote_name": "github.com",
      "proto": "TCP",
      "app_proto": "TLS 1.3",
      "state": "closed",
      "status": "closed normally",
      "started": 2.633401,
      "duration_ms": 2.6,
      "up_bytes": 1782,
      "down_bytes": 8712,
      "packets": 18,
      "problems": 0,
      "first_packet": 54,
      "last_packet": 71
    }
  ]
}
```

`state`: `opening`, `open`, `closing`, `closed`, `reset`, `refused`, `active`, `idle`. `limit` default
200, maximum 1000. `duration_ms` is `null` while the conversation is still going.

### `GET /api/flow/ID`

The same object as in the list, plus its story:

```json
{
  "id": 7,
  "…": "all fields above",
  "story": [
    {
      "n": 1,
      "dir": "out",
      "kind": "syn",
      "text": "\"Can we talk?\" (SYN)",
      "first_packet": 54,
      "last_packet": 54,
      "at_ms": 0.0,
      "took_ms": null,
      "packets": 1,
      "bytes": 0,
      "problem": false
    }
  ]
}
```

`dir`: `out` is from the side that started the conversation, `in` the other way, `null` for a step with
no direction. `kind` is a lowercase word (`syn`, `syn_ack`, `handshake_ack`, `tls_client_hello`,
`tls_server_hello`, `tls_handshake`, `http_request`, `http_response`, `dns_query`, `dns_response`,
`ping_request`, `ping_reply`, `data`, `retransmission`, `fin`, `reset`, `refused`, `icmp_error`).
`at_ms` is time since the conversation's first packet.

### `GET /api/alerts`

```json
{
  "total": 1,
  "alerts": [
    {
      "id": 1,
      "kind": "port_scan",
      "severity": "warning",
      "time": 3.211,
      "clock": "11:02:14.324",
      "title": "Port scan pattern from 192.168.1.77",
      "seen": "…",
      "why": "…",
      "next": "…",
      "packet": 39,
      "first_packet": 1,
      "subject": "192.168.1.77"
    }
  ]
}
```

`severity`: `notice`, `warning` or `serious`. Newest last; at most 1,000 kept.

### `GET /api/glossary`

```json
{"terms": [{"term": "ACK", "text": "…"}]}
```

### `POST /api/control`

Body: `{"action": "pause"}`. Actions: `pause`, `resume`, `record_start`, `record_stop`, and
`{"action": "export_story", "flow": 7}`. Reply: `{"ok": true, "session": { … }}` with the same object
as `/api/session`; `export_story` adds `"path": "…/story-7.md"`. An action that cannot be done returns
`400` with `{"error": "…"}`.

## How the page keeps up to date

Polling, not a streaming connection. Once every 500 ms while the tab is visible and the session is
`running`, the page asks `/api/session` and, if `packets` grew, `/api/packets?after=<last number it has>`.
It stops polling when the tab is hidden or the session has `ended`, and backs off to every 5 s after
three failed requests in a row.
