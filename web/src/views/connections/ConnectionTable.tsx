/** Renders conversation summaries in a keyboard-accessible scrolling table.
 * Loading and sorting belong to ConnectionsView; narratives belong to Story.
 * Read ConnectionTable; selecting a row leaves the list and story independently scrollable. */
import type { Flow } from '../../api/types'
import { labels } from '../../lib/labels'
import { formatBytes, formatDuration } from '../../lib/format'
import { nextIndex } from '../../lib/navigation'
import { Button } from '../../components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../../components/ui/table'
import { ProtocolBadge } from '../../components/ProtocolBadge'

/** Arrow and page keys move selection and focus together without scrolling the document. */
export function ConnectionTable({
  flows,
  selected,
  select,
}: {
  flows: Flow[]
  selected: number | null
  select: (id: number) => void
}) {
  function keyboard(event: React.KeyboardEvent) {
    const index = nextIndex(
      event.key,
      flows.findIndex((flow) => flow.id === selected),
      flows.length,
    )
    if (index === null) return
    event.preventDefault()
    select(flows[index].id)
    event.currentTarget.querySelectorAll<HTMLButtonElement>('tbody button')[index]?.focus()
  }
  return (
    <div className="connections-table" tabIndex={0} onKeyDown={keyboard}>
      <Table>
        <TableHeader>
          <TableRow>
            {[
              labels.app,
              labels.remote,
              labels.proto,
              labels.status,
              labels.duration,
              labels.up,
              labels.down,
              labels.problems,
            ].map((label) => (
              <TableHead key={label}>{label}</TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {flows.map((flow) => (
            <TableRow
              key={flow.id}
              data-state={selected === flow.id ? 'selected' : undefined}
              onClick={() => select(flow.id)}
            >
              <TableCell>{flow.app ?? labels.unknown}</TableCell>
              <TableCell>
                <Button
                  className="remote-button"
                  variant="link"
                  onClick={() => select(flow.id)}
                  title={flow.remote}
                >
                  {flow.remote_name ?? flow.remote}
                </Button>
              </TableCell>
              <TableCell>
                <ProtocolBadge proto={flow.app_proto ?? flow.proto} />
              </TableCell>
              <TableCell>{flow.status}</TableCell>
              <TableCell>{formatDuration(flow.duration_ms)}</TableCell>
              <TableCell>{formatBytes(flow.up_bytes)}</TableCell>
              <TableCell>{formatBytes(flow.down_bytes)}</TableCell>
              <TableCell>
                {flow.problems > 0 ? '⚠ ' : ''}
                {flow.problems}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {!flows.length && <p className="empty-message">{labels.emptyFlows}</p>}
    </div>
  )
}
