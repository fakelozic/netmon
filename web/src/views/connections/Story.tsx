/** Draws a conversation ladder in the order supplied by the server.
 * Conversation selection belongs to ConnectionsView; packet jumps belong to App.
 * Read Story; out means the initiator's side, not necessarily this computer. */
import type { FlowDetail, GlossaryTerm, StoryStep } from '../../api/types'
import { labels } from '../../lib/labels'
import { formatDuration } from '../../lib/format'
import { moveListFocus } from '../../lib/navigation'
import { GlossaryText } from '../../components/GlossaryText'
import { Button } from '../../components/ui/button'
function directionArrow(dir: StoryStep['dir']): string {
  if (dir === 'out') return '────────▶'
  if (dir === 'in') return '◀────────'
  return '────•────'
}
function directionLabel(dir: StoryStep['dir']): string {
  if (dir === 'out') return labels.directionOut
  if (dir === 'in') return labels.directionIn
  return labels.directionNone
}
/** Every step is a keyboard-accessible packet link; absent direction uses a neutral mark. */
export function Story({
  flow,
  terms,
  jump,
  exportStory,
  path,
  mock,
  busy,
}: {
  flow: FlowDetail
  terms: GlossaryTerm[]
  jump: (step: StoryStep) => void
  exportStory: () => void
  path: string | null
  mock: boolean
  busy: boolean
}) {
  return (
    <section className="story-pane" aria-label={labels.story}>
      <div className="story-heading">
        <h2>{flow.title}</h2>
        <Button variant="outline" disabled={busy} onClick={exportStory}>
          {labels.export}
        </Button>
      </div>
      <p>{flow.status}</p>
      {path && (
        <p role="status">
          {mock ? labels.mockExport : labels.exportPath}: <code>{path}</code>
        </p>
      )}
      <div className="ladder-sides">
        <span title={flow.local}>{flow.local}</span>
        <span title={flow.remote}>{flow.remote_name ?? flow.remote}</span>
      </div>
      <ol className="ladder" onKeyDown={moveListFocus}>
        {flow.story.map((step) => {
          const dir = directionLabel(step.dir)
          return (
            <li key={step.n} className={step.problem ? 'story-step story-problem' : 'story-step'}>
              <div className="step-time">
                {formatDuration(step.at_ms)}
                {step.took_ms !== null && (
                  <small>
                    {labels.took} {formatDuration(step.took_ms)}
                  </small>
                )}
              </div>
              <button
                onClick={() => jump(step)}
                className="step-arrow"
                aria-label={dir + ', ' + labels.openPacket + ' ' + step.first_packet}
                data-direction={step.dir ?? 'none'}
              >
                <span aria-hidden="true">{directionArrow(step.dir)}</span>
              </button>
              <div className="step-text">
                <Button variant="link" onClick={() => jump(step)}>
                  {step.problem ? '⚠ ' : ''}
                  {step.n}. <GlossaryText text={step.text} terms={terms} />
                </Button>
                <small>
                  {labels.packets} {step.first_packet}–{step.last_packet}
                </small>
              </div>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
