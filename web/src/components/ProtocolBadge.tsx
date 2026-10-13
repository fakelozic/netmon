/** Displays protocol names with a fixed palette and a readable text label.
 * Protocol detection belongs to the server; table rendering belongs to views.
 * Read ProtocolBadge for the whitelist that keeps API text out of CSS. */
import { Badge } from './ui/badge'
/** Unknown protocol names use a neutral badge; their text is rendered literally. */
export function ProtocolBadge({ proto }: { proto: string }) {
  const palette: Record<string, string> = {
    TCP: 'proto-tcp',
    UDP: 'proto-udp',
    DNS: 'proto-dns',
    HTTP: 'proto-http',
    TLS: 'proto-tls',
    ICMP: 'proto-icmp',
    ICMPv6: 'proto-icmp',
  }
  return (
    <Badge
      variant="outline"
      className={Object.hasOwn(palette, proto) ? palette[proto] : 'proto-other'}
    >
      {proto}
    </Badge>
  )
}
