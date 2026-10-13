/** Virtualises the bounded packet list and preserves keyboard selection.
 * Retention and keyboard arithmetic belong to lib/navigation.ts.
 * Read PacketTable; each packet occupies exactly one fixed-height row. */
import { useEffect, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { PacketRow } from '../../api/types'
import { nextIndex } from '../../lib/navigation'
import { formatTime } from '../../lib/format'
import { labels } from '../../lib/labels'
import { ProtocolBadge } from '../../components/ProtocolBadge'
function columnClass(label: string): string | undefined {
  if (label === labels.bytes) return 'packet-bytes'
  if (label === labels.app) return 'packet-app'
  return undefined
}
/** Follow scrolls only while running; user scrolling upward disables it. */
export function PacketTable({
  rows,
  selected,
  select,
  follow,
  following,
  stopFollowing,
}: {
  rows: PacketRow[]
  selected: number | null
  select: (no: number) => void
  follow: boolean
  following: boolean
  stopFollowing: () => void
}) {
  // TanStack exposes a mutable virtualizer; the compiler must leave this component uncached.
  'use no memo'

  const ref = useRef<HTMLDivElement>(null)
  const lastScroll = useRef(0)
  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => ref.current,
    estimateSize: () => 36,
    overscan: 8,
    useFlushSync: false,
    initialRect: { width: 1000, height: 360 },
  })
  useEffect(() => {
    if (follow && following && rows.length) virtual.scrollToIndex(rows.length - 1, { align: 'end' })
  }, [follow, following, rows.length, virtual])
  useEffect(() => {
    const index = rows.findIndex((row) => row.no === selected)
    if (index >= 0 && !follow) virtual.scrollToIndex(index, { align: 'auto' })
  }, [selected, rows, follow, virtual])
  function keyboard(event: React.KeyboardEvent) {
    const index = nextIndex(
      event.key,
      rows.findIndex((row) => row.no === selected),
      rows.length,
      Math.max(1, Math.floor((ref.current?.clientHeight ?? 360) / 36)),
    )
    if (index === null) return
    event.preventDefault()
    stopFollowing()
    select(rows[index].no)
    virtual.scrollToIndex(index, { align: 'auto' })
  }
  return (
    <div
      className="packet-table"
      role="table"
      aria-label={labels.packets}
      aria-rowcount={rows.length + 1}
    >
      <div role="row" className="packet-columns table-heading">
        {[
          labels.no,
          labels.time,
          labels.from,
          labels.to,
          labels.app,
          labels.proto,
          labels.info,
          labels.bytes,
        ].map((label) => (
          <span role="columnheader" key={label} className={columnClass(label)}>
            {label}
          </span>
        ))}
      </div>
      <div
        ref={ref}
        className="packet-scroll"
        tabIndex={0}
        onKeyDown={keyboard}
        aria-label={labels.packets}
        onScroll={(event) => {
          const top = event.currentTarget.scrollTop
          if (top < lastScroll.current - 2) stopFollowing()
          lastScroll.current = top
        }}
      >
        <div style={{ height: virtual.getTotalSize(), position: 'relative' }}>
          {virtual.getVirtualItems().map((item) => {
            const row = rows[item.index]
            return (
              <div
                key={row.no}
                role="row"
                aria-rowindex={item.index + 2}
                aria-selected={selected === row.no}
                className={
                  'packet-columns packet-row' +
                  (row.problem ? ' problem-row' : '') +
                  (selected === row.no ? ' selected-row' : '')
                }
                style={{
                  position: 'absolute',
                  width: '100%',
                  height: item.size,
                  transform: `translateY(${item.start}px)`,
                }}
                onClick={() => select(row.no)}
              >
                <span role="cell">
                  <button
                    className="row-number"
                    onClick={() => select(row.no)}
                    aria-label={labels.openPacket + ' ' + row.no}
                  >
                    {row.problem ? '⚠ ' : ''}
                    {row.no}
                  </button>
                </span>
                <span role="cell">
                  <span className="time-full">{formatTime(row.time)}</span>
                  <span className="time-short">{formatTime(row.time).slice(0, -3)}</span>
                </span>
                <span role="cell" title={row.src}>
                  {row.src_label}
                </span>
                <span role="cell" title={row.dst}>
                  {row.dst_label}
                </span>
                <span role="cell" className="packet-app">
                  {row.app ?? labels.unknown}
                </span>
                <span role="cell">
                  <ProtocolBadge proto={row.proto} />
                </span>
                <span role="cell" title={row.info}>
                  {row.info}
                </span>
                <span role="cell" className="packet-bytes">
                  {row.bytes}
                </span>
              </div>
            )
          })}
        </div>
        {!rows.length && <p className="empty-message">{labels.emptyPackets}</p>}
      </div>
    </div>
  )
}
