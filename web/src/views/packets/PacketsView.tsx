/** Arranges the packet list and selected detail in resizable panes.
 * Packet fetching belongs to useMonitor/useDetail; table virtualisation belongs to PacketTable.
 * Read PacketsView for following and the responsive pane orientation. */
import { useState } from 'react'
import type { FilterError, GlossaryTerm, NetmonApi, PacketRow, Session } from '../../api/types'
import { labels } from '../../lib/labels'
import { useDetail } from '../../hooks/useDetail'
import { Button } from '../../components/ui/button'
import { Skeleton } from '../../components/ui/skeleton'
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from '../../components/ui/resizable'
import { FilterBar } from './FilterBar'
import { PacketTable } from './PacketTable'
import { PacketDetailPane } from './PacketDetailPane'
/** Selection stays independent of Follow; saved captures open at the first packet. */
export function PacketsView({
  api,
  session,
  rows,
  filter,
  filterError,
  apply,
  selected,
  select,
  terms,
  openFlow,
  page,
  scope,
  clearScope,
}: {
  api: NetmonApi
  session: Session
  rows: PacketRow[]
  filter: string
  filterError: FilterError | null
  apply: (text: string) => void
  selected: number | null
  select: (no: number) => void
  terms: GlossaryTerm[]
  openFlow: (id: number) => void
  page: (older: boolean) => Promise<void>
  scope: number | null
  clearScope: () => void
}) {
  const [follow, setFollow] = useState(session.mode === 'live' && scope === null)
  const [pageBusy, setPageBusy] = useState(false)
  const detail = useDetail(selected, api.packet)
  async function loadPage(older: boolean) {
    setFollow(false)
    setPageBusy(true)
    await page(older)
    setPageBusy(false)
  }
  function selectedDetail() {
    if (detail.error) return <p role="alert">{detail.error}</p>
    if (detail.data)
      return (
        <PacketDetailPane
          key={detail.data.no}
          packet={detail.data}
          terms={terms}
          openFlow={openFlow}
        />
      )
    if (selected === null) return <p className="empty-message">{labels.packetHint}</p>
    return <Skeleton className="detail-skeleton" aria-label={labels.loading} />
  }
  return (
    <div className="packets-view">
      <FilterBar
        key={filter}
        filter={filter}
        error={filterError}
        apply={(text) => {
          setFollow(false)
          apply(text)
        }}
      />
      <div className="list-toolbar">
        <span>
          {rows.length.toLocaleString()} {labels.packets}
          {scope !== null && (
            <>
              {' '}
              · {labels.scope} {scope}{' '}
              <Button variant="link" onClick={clearScope}>
                {labels.clearScope}
              </Button>
            </>
          )}
        </span>
        <div>
          <Button
            variant="ghost"
            disabled={pageBusy || (rows[0]?.no ?? 1) <= 1}
            onClick={() => void loadPage(true)}
          >
            {labels.older}
          </Button>
          <Button variant="ghost" disabled={pageBusy} onClick={() => void loadPage(false)}>
            {labels.newer}
          </Button>
          {session.mode === 'live' && (
            <Button
              variant={follow ? 'secondary' : 'outline'}
              aria-pressed={follow}
              onClick={() => {
                setFollow(true)
                void page(false)
              }}
            >
              {follow ? labels.following : labels.follow}
            </Button>
          )}
        </div>
      </div>
      <ResizablePanelGroup orientation="vertical" className="packet-layout">
        <ResizablePanel defaultSize="45%" minSize="20%">
          <PacketTable
            rows={rows}
            selected={selected}
            select={select}
            follow={follow && scope === null}
            following={session.state === 'running'}
            stopFollowing={() => setFollow(false)}
          />
        </ResizablePanel>
        <ResizableHandle withHandle />
        <ResizablePanel defaultSize="55%" minSize="20%">
          <div className="detail-container">{selectedDetail()}</div>
        </ResizablePanel>
      </ResizablePanelGroup>
    </div>
  )
}
