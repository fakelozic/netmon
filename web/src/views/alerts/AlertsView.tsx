/** Presents traffic alerts newest first without turning observations into verdicts.
 * Detection and wording belong to the server; glossary linking uses GlossaryText.
 * Read AlertsView for Seen, Why and Next plus the triggering packet link. */
import type { GlossaryTerm, TrafficAlert } from '../../api/types'
import { labels } from '../../lib/labels'
import { moveListFocus } from '../../lib/navigation'
import { GlossaryText } from '../../components/GlossaryText'
import { Button } from '../../components/ui/button'
import { Badge } from '../../components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '../../components/ui/card'
/** Alert titles and all explanatory text remain literal React children. */
export function AlertsView({
  alerts,
  terms,
  jump,
}: {
  alerts: TrafficAlert[]
  terms: GlossaryTerm[]
  jump: (no: number) => void
}) {
  return (
    <div className="alerts-view" onKeyDown={moveListFocus}>
      {!alerts.length && <p className="empty-message">{labels.emptyAlerts}</p>}
      {alerts.toReversed().map((alert) => (
        <Card key={alert.id}>
          <CardHeader>
            <div className="alert-heading">
              <Badge variant={alert.severity === 'serious' ? 'destructive' : 'outline'}>
                {labels[alert.severity]}
              </Badge>
              <span>{alert.clock}</span>
            </div>
            <CardTitle>{alert.title}</CardTitle>
          </CardHeader>
          <CardContent>
            {(['seen', 'why', 'next'] as const).map((part) => (
              <div className="alert-text" key={part}>
                <h3>{labels[part]}</h3>
                <p>
                  <GlossaryText text={alert[part]} terms={terms} />
                </p>
              </div>
            ))}
            <Button variant="link" onClick={() => jump(alert.packet)}>
              {labels.openPacket} {alert.packet}
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
