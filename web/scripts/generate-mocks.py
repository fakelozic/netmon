"""Generate fixture JSON without editing the reviewed inputs.

Wording is copied verbatim from golden files or the current Rust renderer.
Run after cargo build --offline; read main first for the source paths.
"""
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'web/src/mocks'


def write(name, value):
    """Write readable UTF-8 JSON for the TypeScript fixture tests."""
    # Prettier formats the generated JSON before it is checked in.
    encode = lambda item: json.dumps(item, ensure_ascii=False)
    if isinstance(value, list):
        text = '[\n' + ',\n'.join('  ' + encode(item) for item in value) + '\n]\n'
    elif any(isinstance(item, list) for item in value.values()):
        lines = []
        for key, item in value.items():
            body = '[\n' + ',\n'.join('    ' + encode(row) for row in item) + '\n  ]' if isinstance(item, list) else encode(item)
            lines.append('  ' + encode(key) + ': ' + body)
        text = '{\n' + ',\n'.join(lines) + '\n}\n'
    else:
        text = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    (OUT / (name + '.json')).write_text(text)


def milliseconds(text):
    """Read the golden renderer's rounded time units as milliseconds."""
    value, unit = text.strip().split()
    return float(value.replace(',', '')) * {'ns': .000001, 'µs': .001, 'ms': 1, 's': 1000}[unit]


def kind(text):
    """Identify fixture step kinds without changing their sentences."""
    for word, result in [('SYN+ACK', 'syn_ack'), ('SYN', 'syn'), ('connection is open', 'handshake_ack'),
                         ('Client Hello', 'tls_client_hello'), ('Server Hello', 'tls_server_hello'),
                         ('Requests', 'http_request'), ('Replies', 'http_response'), ('Asks:', 'dns_query'),
                         ('Answer:', 'dns_response'), ('Ping request', 'ping_request'), ('Ping reply', 'ping_reply'),
                         ('Refuses', 'refused'), ('Cannot deliver', 'icmp_error'), ('FIN', 'fin')]:
        if word in text:
            return result
    return 'data'


def read_flows(rows):
    """Copy observed story order, directions and exact sentences."""
    flows = []
    chunks = (ROOT / 'tests/golden/flows-loopback-stories.txt').read_text().strip().split('\n\n')
    for index, chunk in enumerate(chunks, 1):
        lines = chunk.strip().splitlines()
        title, duration, sizes = lines[0].split(' · ')
        endpoints, proto = title.split('   ')
        local, remote_label = endpoints.split(' ⇄ ')
        up, down = re.findall(r'([\d,]+) bytes', sizes)
        story = []
        for line in lines[3:]:
            m = re.match(r'\s*([\d.]+ (?:ns|µs|ms|s))\s+│ (.*?) │\s+(\d+)\. (.*?)  \[packets (\d+)–(\d+)\]', line)
            if m:
                at, arrow, n, text, first, last = m.groups()
                first, last = int(first), int(last)
                story.append(dict(n=int(n), dir='out' if '▶' in arrow else 'in' if '◀' in arrow else None,
                                  kind=kind(text), text=text, first_packet=first, last_packet=last,
                                  at_ms=milliseconds(at), took_ms=None, packets=last-first+1,
                                  bytes=0, problem=any(w in text for w in ['Refuses', 'Cannot deliver', 'NXDOMAIN', '404'])))
            elif story and 'after the request' in line:
                story[-1]['took_ms'] = milliseconds(line.strip().split(' after')[0])
        first, last = story[0]['first_packet'], story[-1]['last_packet']
        remote = rows[first-1]['dst']
        flow = dict(id=index, title=endpoints, app=None, pid=None, local=local, remote=remote,
                    remote_name='netmon.test' if 'netmon.test' in remote_label else None,
                    proto=proto.split(' + ')[0], app_proto=proto.split(' + ')[1] if ' + ' in proto else None,
                    state='closed' if lines[1] == 'closed normally' else lines[1], status=lines[1],
                    started=rows[first-1]['time'], duration_ms=milliseconds(duration),
                    up_bytes=int(up.replace(',', '')), down_bytes=int(down.replace(',', '')),
                    packets=last-first+1, problems=sum(s['problem'] for s in story), first_packet=first,
                    last_packet=last, story=story)
        flows.append(flow)
        for row in rows[first-1:last]:
            row['flow'] = index
            step = next((step for step in story if step['first_packet'] <= row['no'] <= step['last_packet']), None)
            row['dir'] = step['dir'] if row['src'] == row['dst'] and step else 'out' if row['src'] == local else 'in'
            if flow['remote_name']:
                row['src_label'] = row['src'].replace('127.0.0.2', 'netmon.test')
                row['dst_label'] = row['dst'].replace('127.0.0.2', 'netmon.test')
    return flows


def read_details(rows, about):
    """Copy full field trees and captured hex from goldens or the renderer."""
    details = []
    for row in rows:
        path = ROOT / f"tests/golden/packet-{row['no']}.txt"
        text = path.read_text() if path.exists() else subprocess.check_output([
            str(ROOT / 'target/debug/netmon'), 'explain', str(ROOT / 'tests/fixtures/loopback-mixed.pcapng'),
            '--packet', str(row['no'])], text=True)
        layers, stack, current = [], [], None
        for line in text.splitlines():
            m = re.match(r'(\s+)(.*?)  \[(\d+)\.\.(\d+)\]  (.*)', line)
            if m:
                pad, label, start, end, value = m.groups()
                if len(pad) == 6:
                    layers.append(dict(proto=label, range=[int(start), int(end)], line=value,
                                       about=about.get(label, ''), fields=[]))
                    stack = []
                else:
                    current = dict(label=label, value=value, range=[int(start), int(end)], what='', here='', why='', children=[])
                    while stack and stack[-1][0] >= len(pad):
                        stack.pop()
                    (stack[-1][1]['children'] if stack else layers[-1]['fields']).append(current)
                    stack.append((len(pad), current))
            else:
                m = re.match(r'\s+(What|Here|Why):\s+(.*)', line)
                if m and current:
                    current[m[1].lower()] = m[2]
        hexdata = ''.join(''.join(re.findall(r'\b[0-9a-f]{2}\b', line[6:53]))
                          for line in text.splitlines() if re.match(r'^[0-9a-f]{4}  ', line))
        details.append(dict(no=row['no'], time=row['time'], clock=row['clock'], info=row['info'], wire_len=row['bytes'],
                            captured_len=len(hexdata)//2, truncated=False, flow=row['flow'], hex=hexdata, layers=layers))
    return details


def redact_details(details):
    """Zero secret ranges before mock hex can leave the fixture generator."""
    def fields(tree):
        for field in tree:
            yield field
            yield from fields(field['children'])
    for packet in details:
        packet['hidden'] = [field['range'] for layer in packet['layers']
                            for field in fields(layer['fields']) if '[hidden]' in field['value']]
        # This fixture contains no secret. Packet 32 demonstrates the API's redaction shape.
        if packet['no'] == 32:
            packet['hidden'].append([128, 132])
        hexdata = packet['hex']
        for start, end in packet['hidden']:
            start = max(0, min(start, len(hexdata)//2))
            end = max(start, min(end, len(hexdata)//2))
            hexdata = hexdata[:start*2] + '00'*(end-start) + hexdata[end*2:]
        packet['hex'] = hexdata


def fill_step_bytes(flows, details):
    """Count carried bytes from the renderer's transport or ping data fields."""
    payloads = {}
    for packet in details:
        fields = [field for layer in packet['layers'] for field in layer['fields']]
        payloads[packet['no']] = sum(int(field['value']) for field in fields
                                     if field['label'] in ['Payload size', 'Data size'])
    for flow in flows:
        for step in flow['story']:
            step['bytes'] = sum(payloads[n] for n in range(step['first_packet'], step['last_packet'] + 1))


def main():
    """Copy all 75 rows, 12 stories, full packet trees and explanatory sources."""
    rows = []
    pattern = r'^\s*(\d+)\s+([\d.]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(.*)$'
    for line in (ROOT / 'tests/golden/flows-loopback-list.txt').read_text().splitlines():
        m = re.match(pattern, line)
        if m:
            no, time, src, dst, proto, size, info = m.groups()
            rows.append(dict(no=int(no), time=float(time), clock=f'00:00:{float(time):06.3f}', src=src, dst=dst,
                             src_label=src, dst_label=dst, app=None, proto=proto, bytes=int(size), info=info,
                             problem=any(w in info for w in ['NXDOMAIN', 'Refuses', 'Cannot deliver', '404']),
                             alerts=0, flow=None, dir=None))
    flows = read_flows(rows)
    glossary_src = (ROOT / 'src/explain/glossary.rs').read_text().split('#[cfg(test)]')[0]
    terms = [dict(term=json.loads(a), text=json.loads(b)) for a, b in re.findall(r'\(\s*("(?:[^"\\]|\\.)*"),\s*("(?:[^"\\]|\\.)*"),?\s*\)', glossary_src)]
    about_src = (ROOT / 'src/explain/ui.rs').read_text().split('fn layer(proto: Proto)')[1]
    names = {'Ipv4': 'IPv4', 'Ipv6': 'IPv6', 'Icmp': 'ICMP', 'Icmpv6': 'ICMPv6', 'Tcp': 'TCP', 'Udp': 'UDP', 'Dns': 'DNS', 'Tls': 'TLS', 'Http': 'HTTP'}
    about = {}
    for arms, text in re.findall(r'((?:Proto::\w+(?:\s*\|\s*)?)+)\s*=>\s*\{?\s*"([^"]+)"', about_src):
        for name in re.findall(r'Proto::(\w+)', arms):
            about[names.get(name, name)] = text
    details = read_details(rows, about)
    redact_details(details)
    fill_step_bytes(flows, details)
    alerts = []
    kinds = ['port_scan', 'cleartext_credentials', 'arp_change', 'suspicious_dns', 'unexpected_inbound']
    for index, chunk in enumerate((ROOT / 'tests/golden/alerts-examples.txt').read_text().strip().split('\n\n')):
        lines = chunk.splitlines()
        severity, title = lines[0].split(': ', 1)
        first, packet = map(int, re.findall(r'\d+', lines[1]))
        alerts.append(dict(id=index+1, kind=kinds[index], severity=severity.lower(), time=rows[packet-1]['time'],
                           clock=rows[packet-1]['clock'], title=title, seen=lines[2][6:], why=lines[3][5:],
                           next=lines[4][6:], packet=packet, first_packet=first, subject=re.search(r'\d+\.\d+\.\d+\.\d+', title)[0]))
    write('packets', dict(total=len(rows), matched=len(rows), filter_error=None, rows=rows))
    write('details', details)
    write('flows', flows)
    write('alerts', dict(total=len(alerts), alerts=alerts))
    write('glossary', dict(terms=terms))
    write('session', dict(version='0.1.0', mode='live', source='loopback-mixed.pcapng (replay)', state='running', error=None,
                          started='2026-10-13T00:00:00Z', packets=0, dropped=0, bytes=0, conversations=0, alerts=0,
                          rate=[], log_dir='/mock/session', recording='off', problem=None))


if __name__ == '__main__':
    main()
