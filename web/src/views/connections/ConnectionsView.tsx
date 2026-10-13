/** Lists bounded conversations and loads the selected story.
 * Server sorting belongs to the API; story rendering belongs to Story.tsx.
 * Read ConnectionsView; no export path becomes a link. */
import { useState } from 'react'
import type {
  ControlAction,
  ControlReply,
  Flow,
  FlowSort,
  GlossaryTerm,
  NetmonApi,
  StoryStep,
} from '../../api/types'
import { useDetail } from '../../hooks/useDetail'
import { labels } from '../../lib/labels'
import { Skeleton } from '../../components/ui/skeleton'
import { ConnectionTable } from './ConnectionTable'
import { Story } from './Story'
/** The server refresh count updates an open story as packets arrive. */
export function ConnectionsView({
  api,
  flows,
  sort,
  setSort,
  selected,
  select,
  terms,
  jump,
  control,
  revision,
  mock,
  busy,
}: {
  api: NetmonApi
  flows: Flow[]
  sort: FlowSort
  setSort: (sort: FlowSort) => void
  selected: number | null
  select: (id: number) => void
  terms: GlossaryTerm[]
  jump: (flow: Flow, step: StoryStep) => void
  control: (action: ControlAction) => Promise<ControlReply | null>
  revision: number
  mock: boolean
  busy: boolean
}) {
  const detail = useDetail(selected, api.flow, revision)
  const [exported, setExported] = useState<{ id: number; path: string } | null>(null)
  async function exportStory() {
    if (selected === null) return
    const result = await control({ action: 'export_story', flow: selected })
    if (result?.path) setExported({ id: selected, path: result.path })
  }
  function selectedStory() {
    if (detail.error) return <p role="alert">{detail.error}</p>
    const flow = detail.data
    if (flow)
      return (
        <Story
          flow={flow}
          terms={terms}
          jump={(step) => jump(flow, step)}
          exportStory={() => void exportStory()}
          path={exported?.id === selected ? exported.path : null}
          mock={mock}
          busy={busy}
        />
      )
    if (selected === null) return <p className="empty-message">{labels.storyHint}</p>
    return <Skeleton className="detail-skeleton" aria-label={labels.loading} />
  }
  return (
    <div className="connections-view">
      <div className="list-toolbar">
        <h2>{labels.connections}</h2>
        <label>
          {labels.sort}{' '}
          <select value={sort} onChange={(event) => setSort(event.target.value as FlowSort)}>
            <option value="recent">{labels.recent}</option>
            <option value="bytes">{labels.sortBytes}</option>
            <option value="problems">{labels.problems}</option>
          </select>
        </label>
      </div>
      <div className="connections-layout">
        <ConnectionTable flows={flows} selected={selected} select={select} />
        <div className="story-scroll">{selectedStory()}</div>
      </div>
    </div>
  )
}
