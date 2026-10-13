# netmon session summary

- Started: 2026-10-12T12:40:43.112Z
- Ended: 2026-10-12T12:40:46.156Z
- Duration: 3 s
- Packets: 75
- Bytes: 17,764
- Conversations: 12
- DNS lookups: 4
- Alerts: 0

## Alerts

None.

## Conversations

| Number | App | Remote host | Protocol | Duration | Up (payload bytes) | Down (payload bytes) | How it ended |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | unknown app | netmon.test:18443 | TCP + TLS 1.3 | 2.6 ms | 1,782 | 8,712 | closed normally |
| 8 | unknown app | 127.0.0.2:18080 | TCP + HTTP | 550 µs | 91 | 645 | closed normally |
| 7 | unknown app | 127.0.0.2:18080 | TCP + HTTP | 2.7 ms | 79 | 245 | closed normally |
| 9 | unknown app | \[::1\]:18081 | TCP + HTTP | 2.1 ms | 75 | 245 | closed normally |
| 1 | unknown app | 127.0.0.2 | ICMP | 301.2 ms | 112 | 112 | finished |
| 2 | unknown app | ::1 | ICMPv6 | 302.9 ms | 112 | 112 | finished |
| 6 | unknown app | 127.0.0.53:53 | UDP + DNS | 95 µs | 72 | 60 | finished |
| 5 | unknown app | 127.0.0.53:53 | UDP + DNS | 61.6 ms | 55 | 73 | finished |
| 3 | unknown app | 127.0.0.53:53 | UDP + DNS | 56.5 ms | 52 | 72 | finished |
| 4 | unknown app | 127.0.0.53:53 | UDP + DNS | 7.2 ms | 52 | 68 | finished |
| 12 | unknown app | 127.0.0.2:18998 | UDP | 12 µs | 6 | 0 | finished |
| 11 | unknown app | 127.0.0.2:18999 | TCP | 9 µs | 0 | 0 | refused |

## DNS lookups

| Name | Answer | Asked by | Time taken | Result |
| --- | --- | --- | --- | --- |
| example.com | 172.66.147.243 \(and 1 more\) | 127.0.0.2:55921 | 56.5 ms | answered |
| example.com | 2606:4700:8d95:72db:f2de:b99:ef6b:ff98 | 127.0.0.2:48891 | 7.2 ms | answered |
| www&#46;github.com | 20.207.73.82 \(via github.com\) | 127.0.0.2:44337 | 61.6 ms | answered |
| nonexistent-netmon-test.invalid | no answer records | 127.0.0.2:35167 | 95 µs | name does not exist \(NXDOMAIN\) |

## Problems

- Packet 16: Answer: nonexistent-netmon-test.invalid does not exist \(NXDOMAIN\) \(95 µs\)
- Packet 73: Refuses the connection \(RST\) - probably nothing is listening on port 18999
- Packet 75: Cannot deliver: nothing listens on that port - about a UDP packet to port 18998

## Files in this folder

- events.md: Event timeline; open in a Markdown editor or viewer.
- flows.jsonl: Finished conversations; read with a JSON lines tool.
- packets.jsonl: Packet summaries; read with a JSON lines tool.
- summary.md: Session report; open in a Markdown editor or viewer.
