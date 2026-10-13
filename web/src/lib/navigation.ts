/** Gives lists deterministic keyboard movement and bounded packet retention.
 * Focus rendering belongs to the views; server querying belongs to hooks.
 * Read nextIndex for the common keyboard contract. */
import type { PacketRow } from '../api/types'
/** Returns a clamped row index, or null when this is not a navigation key. */
export function nextIndex(key: string, current: number, length: number, page = 10): number | null {
  const moves: Record<string, number> = {
    ArrowDown: current + 1,
    ArrowUp: current - 1,
    PageDown: current + page,
    PageUp: current - page,
    Home: 0,
    End: length - 1,
  }
  return key in moves && length ? Math.max(0, Math.min(length - 1, moves[key])) : null
}
/** Keeps at most 5,000 unique rows, evicting at the end opposite the requested direction. */
export function mergeRows(old: PacketRow[], incoming: PacketRow[], older = false): PacketRow[] {
  const byNo = new Map(old.map((row) => [row.no, row]))
  incoming.forEach((row) => byNo.set(row.no, row))
  const rows = [...byNo.values()].sort((a, b) => a.no - b.no)
  return older ? rows.slice(0, 5000) : rows.slice(-5000)
}
/** Moves focus among visible actions or definitions; closed details keep their children hidden. */
export function moveListFocus(event: import('react').KeyboardEvent<HTMLElement>): void {
  const items = [
    ...event.currentTarget.querySelectorAll<HTMLElement>('button, summary, [data-list-item]'),
  ].filter((item) => {
    let parent = item.parentElement
    while (parent && parent !== event.currentTarget) {
      if (
        parent.tagName === 'DETAILS' &&
        !(parent as HTMLDetailsElement).open &&
        !parent.querySelector('summary')?.contains(item)
      )
        return false
      parent = parent.parentElement
    }
    return true
  })
  const index = nextIndex(
    event.key,
    items.indexOf(document.activeElement as HTMLElement),
    items.length,
  )
  if (index !== null) {
    event.preventDefault()
    items[index]?.focus()
  }
}
