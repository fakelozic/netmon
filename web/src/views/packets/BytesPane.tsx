/** Shows captured hex and ASCII with matching field highlights in both columns.
 * Row construction and range arithmetic belong to lib/hex.ts.
 * Read BytesPane; its rows are virtualised even for maximum-size captures. */
import { useEffect, useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { ByteRange } from '../../api/types'
import { hexRows, inRange } from '../../lib/hex'
import { nextIndex } from '../../lib/navigation'
import { labels } from '../../lib/labels'
/** Clicking or pressing Enter on either representation selects the same packet byte. */
export function BytesPane({
  hex,
  range,
  hidden = [],
  choose,
}: {
  hex: string
  range: ByteRange | null
  hidden?: ByteRange[]
  choose: (offset: number) => void
}) {
  // TanStack exposes a mutable virtualizer; the compiler must leave this component uncached.
  'use no memo'

  const rows = hexRows(hex, hidden)
  const ref = useRef<HTMLDivElement>(null)
  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => ref.current,
    estimateSize: () => 28,
    overscan: 6,
    useFlushSync: false,
    initialRect: { width: 750, height: 224 },
  })
  useEffect(() => {
    if (range && rows.length)
      virtual.scrollToIndex(Math.min(rows.length - 1, Math.floor(range[0] / 16)), { align: 'auto' })
  }, [range, rows.length, virtual])
  function keyboard(event: React.KeyboardEvent<HTMLElement>) {
    const target = event.target as HTMLElement
    const offset = Number(target.dataset.offset)
    if (!Number.isInteger(offset)) return
    const index = nextIndex(
      event.key,
      offset,
      rows.reduce((sum, row) => sum + row.bytes.length, 0),
      160,
    )
    if (index === null) return
    event.preventDefault()
    choose(index)
    virtual.scrollToIndex(Math.floor(index / 16), { align: 'auto' })
    // Focus after virtualisation has made the target byte row available.
    requestAnimationFrame(() =>
      ref.current?.querySelector<HTMLButtonElement>(`[data-offset="${index}"]`)?.focus(),
    )
  }
  return (
    <section className="bytes-pane" aria-label={labels.bytes}>
      <h3>
        {labels.bytes}
        {range && (
          <span className="range-label">
            [{range[0]}, {range[1]})
          </span>
        )}
      </h3>
      <p>{labels.bytesHint}</p>
      <div className="hex-scroll" onKeyDown={keyboard} ref={ref} aria-label={labels.bytes}>
        <div style={{ height: virtual.getTotalSize(), position: 'relative', minWidth: 440 }}>
          {virtual.getVirtualItems().map((item) => (
            <div
              className="hex-row"
              key={item.index}
              style={{
                position: 'absolute',
                height: item.size,
                transform: `translateY(${item.start}px)`,
              }}
            >
              <span className="hex-offset">
                {rows[item.index].offset.toString(16).padStart(4, '0')}
              </span>
              <div className="hex-column">
                {rows[item.index].bytes.map((byte) => (
                  <button
                    key={byte.offset}
                    title={byte.hex === '**' ? labels.hiddenSecret : undefined}
                    data-offset={byte.offset}
                    data-highlighted={inRange(byte.offset, range)}
                    className={inRange(byte.offset, range) ? 'byte-highlight' : ''}
                    aria-label={`${labels.hex} ${labels.byte} ${byte.offset}: ${byte.hex}`}
                    onClick={() => choose(byte.offset)}
                  >
                    {byte.hex}
                  </button>
                ))}
              </div>
              <div className="ascii-column">
                {rows[item.index].bytes.map((byte) => (
                  <button
                    key={byte.offset}
                    title={byte.hex === '**' ? labels.hiddenSecret : undefined}
                    data-offset={byte.offset}
                    data-highlighted={inRange(byte.offset, range)}
                    className={inRange(byte.offset, range) ? 'byte-highlight' : ''}
                    aria-label={`${labels.ascii} ${labels.byte} ${byte.offset}: ${byte.ascii}`}
                    onClick={() => choose(byte.offset)}
                  >
                    {byte.ascii}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
